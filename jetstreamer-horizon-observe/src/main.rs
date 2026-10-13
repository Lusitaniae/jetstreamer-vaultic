//! Read-only, invocation-bound resource samples for live Horizon replays.
//!
//! This tool deliberately does not signal, restart, or otherwise mutate a
//! producer. It observes each configured controller and producer before and
//! after two physical scratch scans, then publishes one no-clobber JSON
//! receipt only if every invocation remained stable and healthy.

use {
    anyhow::{Context, Result, anyhow, ensure},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    sha2::{Digest as _, Sha256},
    std::{
        collections::BTreeMap,
        env,
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const CONFIG_SCHEMA: &str = "jetstreamer-horizon-live-resource-sample-config-v1";
const OUTPUT_SCHEMA: &str = "jetstreamer-horizon-live-resource-sample-v1";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PREVIOUS_SAMPLE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    previous_sample: PathBuf,
    minimum_interval_seconds: u64,
    filesystem_path: PathBuf,
    output: PathBuf,
    replays: Vec<ReplayConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayConfig {
    range: String,
    controller_unit: String,
    expected_controller_invocation_id: String,
    producer_unit: String,
    expected_producer_invocation_id: String,
    scratch_path: PathBuf,
    worker_executable_basename: String,
}

#[derive(Clone, Debug, Serialize)]
struct UnitObservation {
    unit: String,
    invocation_id: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    result: String,
    restarts: u64,
    main_pid: u64,
    memory_current_bytes: u64,
    memory_peak_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ScratchScan {
    physical_bytes: u64,
    apparent_bytes: u64,
    entries: u64,
    regular_files: u64,
    directories: u64,
    symlinks: u64,
    vanished_entries: u64,
}

#[derive(Debug, Serialize)]
struct WorkerObservation {
    pid: u64,
    executable: PathBuf,
    executable_beneath_bound_scratch: bool,
    vmas: u64,
    matching_workers: usize,
}

#[derive(Debug, Serialize)]
struct ReplayObservation {
    range: String,
    controller_before: UnitObservation,
    producer_before: UnitObservation,
    worker_before: WorkerObservation,
    scratch_path: PathBuf,
    scratch_measurement_method: &'static str,
    scratch_pass_1: ScratchScan,
    scratch_pass_2: ScratchScan,
    conservative_observed_physical_bytes: u64,
    within_sample_physical_delta_bytes: i128,
    controller_after: UnitObservation,
    producer_after: UnitObservation,
    worker_after: WorkerObservation,
    invocation_binding_stable: bool,
}

fn usage() -> ! {
    eprintln!("usage: jetstreamer-horizon-observe CONFIG.json");
    std::process::exit(2);
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "{label} path must be absolute");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "{label} is not a regular file");
    ensure!(before.nlink() == 1, "{label} has multiple hard links");
    ensure!(before.len() <= maximum, "{label} exceeds size bound");
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "{label} exceeds size bound");
    let after = file.metadata()?;
    ensure!(
        before.dev() == after.dev() && before.ino() == after.ino() && before.len() == after.len(),
        "{label} changed while it was read"
    );
    let current = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-inspect {label} {}", path.display()))?;
    ensure!(
        after.dev() == current.dev() && after.ino() == current.ino(),
        "{label} namespace changed while it was read"
    );
    Ok(bytes)
}

fn parse_args() -> Result<Config> {
    let mut args = env::args_os().skip(1);
    let path = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    ensure!(args.next().is_none(), "unexpected extra argument");
    let bytes = read_bounded(&path, MAX_CONFIG_BYTES, "config")?;
    let config: Config = serde_json::from_slice(&bytes).context("invalid config JSON")?;
    ensure!(config.schema == CONFIG_SCHEMA, "unsupported config schema");
    ensure!(
        config.minimum_interval_seconds >= 1800,
        "minimum interval must be at least 1800 seconds"
    );
    ensure!(
        !config.replays.is_empty(),
        "at least one replay is required"
    );
    ensure!(config.output.is_absolute(), "output path must be absolute");
    ensure!(
        !config.output.exists(),
        "output already exists: {}",
        config.output.display()
    );
    let parent = config
        .output
        .parent()
        .ok_or_else(|| anyhow!("output has no parent"))?;
    ensure!(parent.is_dir(), "output parent is not a directory");
    ensure!(
        config.filesystem_path.is_absolute(),
        "filesystem path must be absolute"
    );
    for replay in &config.replays {
        ensure!(!replay.range.is_empty(), "replay range is empty");
        ensure!(
            replay.controller_unit.ends_with(".service"),
            "controller unit must end in .service"
        );
        ensure!(
            replay.producer_unit.ends_with(".service"),
            "producer unit must end in .service"
        );
        ensure!(
            is_invocation_id(&replay.expected_controller_invocation_id),
            "invalid expected controller invocation ID"
        );
        ensure!(
            is_invocation_id(&replay.expected_producer_invocation_id),
            "invalid expected producer invocation ID"
        );
        ensure!(
            replay.scratch_path.is_absolute(),
            "scratch path must be absolute"
        );
        ensure!(
            !replay.worker_executable_basename.is_empty()
                && !replay.worker_executable_basename.contains('/'),
            "invalid worker executable basename"
        );
    }
    Ok(config)
}

fn is_invocation_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_secs())
}

fn format_utc(unix: u64) -> Result<String> {
    let seconds: libc::time_t = unix
        .try_into()
        .map_err(|_| anyhow!("timestamp is outside time_t"))?;
    let mut broken_down = std::mem::MaybeUninit::<libc::tm>::uninit();
    let result = unsafe { libc::gmtime_r(&seconds, broken_down.as_mut_ptr()) };
    ensure!(!result.is_null(), "gmtime_r failed");
    let broken_down = unsafe { broken_down.assume_init() };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        broken_down.tm_year + 1900,
        broken_down.tm_mon + 1,
        broken_down.tm_mday,
        broken_down.tm_hour,
        broken_down.tm_min,
        broken_down.tm_sec
    ))
}

// Civil-date conversion adapted from Howard Hinnant's public-domain algorithm.
fn parse_utc(value: &str) -> Result<u64> {
    ensure!(value.len() == 20, "timestamp must use YYYY-MM-DDTHH:MM:SSZ");
    let bytes = value.as_bytes();
    ensure!(
        bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'Z',
        "timestamp must use YYYY-MM-DDTHH:MM:SSZ"
    );
    let number = |start: usize, end: usize| -> Result<i64> {
        value[start..end]
            .parse::<i64>()
            .context("timestamp contains a non-number")
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    ensure!((1..=12).contains(&month), "timestamp month is invalid");
    ensure!((1..=31).contains(&day), "timestamp day is invalid");
    ensure!(
        hour <= 23 && minute <= 59 && second <= 59,
        "timestamp time is invalid"
    );
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    ensure!(days >= 0, "timestamp predates Unix epoch");
    let unix = days
        .checked_mul(86400)
        .and_then(|value| value.checked_add(hour * 3600 + minute * 60 + second))
        .ok_or_else(|| anyhow!("timestamp overflow"))?;
    let unix: u64 = unix
        .try_into()
        .map_err(|_| anyhow!("timestamp is negative"))?;
    ensure!(format_utc(unix)? == value, "timestamp date is invalid");
    Ok(unix)
}

fn previous_sample(path: &Path) -> Result<(Vec<u8>, String, u64)> {
    let bytes = read_bounded(path, MAX_PREVIOUS_SAMPLE_BYTES, "previous sample")?;
    let value: Value = serde_json::from_slice(&bytes).context("invalid previous sample JSON")?;
    let timestamp = value
        .get("recorded_at_utc")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("previous sample lacks recorded_at_utc"))?;
    let unix = parse_utc(timestamp)?;
    Ok((bytes, timestamp.to_owned(), unix))
}

fn systemctl_properties(unit: &str) -> Result<BTreeMap<String, String>> {
    let output = Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=LoadState,ActiveState,SubState,Result,MainPID,InvocationID,NRestarts,MemoryCurrent,MemoryPeak",
        ])
        .output()
        .with_context(|| format!("failed to run systemctl for {unit}"))?;
    ensure!(
        output.status.success(),
        "systemctl failed for {unit}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = std::str::from_utf8(&output.stdout).context("systemctl output is not UTF-8")?;
    let mut properties = BTreeMap::new();
    for line in stdout.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("malformed systemctl property for {unit}"))?;
        ensure!(
            properties
                .insert(name.to_owned(), value.to_owned())
                .is_none(),
            "duplicate systemctl property {name} for {unit}"
        );
    }
    Ok(properties)
}

fn required_property<'a>(
    properties: &'a BTreeMap<String, String>,
    name: &str,
    unit: &str,
) -> Result<&'a str> {
    properties
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("systemctl omitted {name} for {unit}"))
}

fn numeric_property(properties: &BTreeMap<String, String>, name: &str, unit: &str) -> Result<u64> {
    let value = required_property(properties, name, unit)?;
    if value == "[not set]" {
        return Ok(0);
    }
    value
        .parse()
        .with_context(|| format!("invalid {name} for {unit}"))
}

fn observe_unit(unit: &str, expected_invocation: &str) -> Result<UnitObservation> {
    let properties = systemctl_properties(unit)?;
    let observation = UnitObservation {
        unit: unit.to_owned(),
        invocation_id: required_property(&properties, "InvocationID", unit)?.to_owned(),
        load_state: required_property(&properties, "LoadState", unit)?.to_owned(),
        active_state: required_property(&properties, "ActiveState", unit)?.to_owned(),
        sub_state: required_property(&properties, "SubState", unit)?.to_owned(),
        result: required_property(&properties, "Result", unit)?.to_owned(),
        restarts: numeric_property(&properties, "NRestarts", unit)?,
        main_pid: numeric_property(&properties, "MainPID", unit)?,
        memory_current_bytes: numeric_property(&properties, "MemoryCurrent", unit)?,
        memory_peak_bytes: numeric_property(&properties, "MemoryPeak", unit)?,
    };
    ensure!(observation.load_state == "loaded", "{unit} is not loaded");
    ensure!(observation.active_state == "active", "{unit} is not active");
    ensure!(observation.sub_state == "running", "{unit} is not running");
    ensure!(observation.restarts == 0, "{unit} has restarted");
    ensure!(
        observation.invocation_id == expected_invocation,
        "{unit} invocation changed"
    );
    Ok(observation)
}

fn path_is_beneath(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn observe_worker(scratch: &Path, executable_basename: &str) -> Result<WorkerObservation> {
    let mut matches = Vec::new();
    for entry in fs::read_dir("/proc").context("failed to read /proc")? {
        let entry = entry?;
        let Some(pid_text) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u64>() else {
            continue;
        };
        let executable = match fs::read_link(entry.path().join("exe")) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => continue,
            Err(error) => return Err(error).context("failed to inspect process executable"),
        };
        let basename_matches =
            executable.file_name().and_then(|name| name.to_str()) == Some(executable_basename);
        if basename_matches && path_is_beneath(&executable, scratch) {
            matches.push((pid, executable));
        }
    }
    ensure!(
        matches.len() == 1,
        "expected exactly one {executable_basename} beneath {}, found {}",
        scratch.display(),
        matches.len()
    );
    let (pid, executable) = matches.pop().expect("length checked");
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("failed to read maps for worker {pid}"))?;
    Ok(WorkerObservation {
        pid,
        executable_beneath_bound_scratch: path_is_beneath(&executable, scratch),
        executable,
        vmas: maps.lines().count() as u64,
        matching_workers: 1,
    })
}

fn add_checked(target: &mut u64, value: u64, label: &str) -> Result<()> {
    *target = target
        .checked_add(value)
        .ok_or_else(|| anyhow!("{label} overflow"))?;
    Ok(())
}

fn scan_scratch(root: &Path) -> Result<ScratchScan> {
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect scratch {}", root.display()))?;
    ensure!(root_metadata.is_dir(), "scratch is not a directory");
    let root_device = root_metadata.dev();
    let mut scan = ScratchScan {
        physical_bytes: root_metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| anyhow!("root block count overflow"))?,
        apparent_bytes: root_metadata.len(),
        entries: 1,
        regular_files: 0,
        directories: 1,
        symlinks: 0,
        vanished_entries: 0,
    };
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                scan.vanished_entries += 1;
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    scan.vanished_entries += 1;
                    continue;
                }
                Err(error) => return Err(error).context("failed to read scratch entry"),
            };
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    scan.vanished_entries += 1;
                    continue;
                }
                Err(error) => return Err(error).context("failed to inspect scratch entry"),
            };
            ensure!(
                metadata.dev() == root_device,
                "scratch entry crosses a filesystem boundary: {}",
                entry.path().display()
            );
            add_checked(&mut scan.entries, 1, "entry count")?;
            add_checked(
                &mut scan.physical_bytes,
                metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| anyhow!("block count overflow"))?,
                "physical byte count",
            )?;
            add_checked(
                &mut scan.apparent_bytes,
                metadata.len(),
                "apparent byte count",
            )?;
            if metadata.file_type().is_symlink() {
                add_checked(&mut scan.symlinks, 1, "symlink count")?;
            } else if metadata.is_dir() {
                add_checked(&mut scan.directories, 1, "directory count")?;
                pending.push(entry.path());
            } else if metadata.is_file() {
                add_checked(&mut scan.regular_files, 1, "regular-file count")?;
            }
        }
    }
    Ok(scan)
}

fn filesystem_available_bytes(path: &Path) -> Result<u64> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .context("filesystem path contains NUL")?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    ensure!(
        result == 0,
        "statvfs failed: {}",
        std::io::Error::last_os_error()
    );
    let stats = unsafe { stats.assume_init() };
    stats
        .f_bavail
        .checked_mul(stats.f_frsize)
        .ok_or_else(|| anyhow!("available-byte count overflow"))
}

fn host_memory() -> Result<(u64, u64)> {
    let text = fs::read_to_string("/proc/meminfo").context("failed to read /proc/meminfo")?;
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("MemTotal:") {
            total = Some(parse_meminfo_kib(value, "MemTotal")?);
        } else if let Some(value) = line.strip_prefix("MemAvailable:") {
            available = Some(parse_meminfo_kib(value, "MemAvailable")?);
        }
    }
    Ok((
        total.ok_or_else(|| anyhow!("MemTotal is missing"))?,
        available.ok_or_else(|| anyhow!("MemAvailable is missing"))?,
    ))
}

fn parse_meminfo_kib(value: &str, label: &str) -> Result<u64> {
    let mut fields = value.split_whitespace();
    let number: u64 = fields
        .next()
        .ok_or_else(|| anyhow!("{label} has no value"))?
        .parse()
        .with_context(|| format!("invalid {label}"))?;
    ensure!(fields.next() == Some("kB"), "{label} has unexpected unit");
    ensure!(fields.next().is_none(), "{label} has extra fields");
    Ok(number)
}

fn vm_max_map_count() -> Result<u64> {
    fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse()
        .context("invalid vm.max_map_count")
}

fn stable_unit(before: &UnitObservation, after: &UnitObservation) -> bool {
    before.invocation_id == after.invocation_id
        && before.restarts == 0
        && after.restarts == 0
        && after.load_state == "loaded"
        && after.active_state == "active"
        && after.sub_state == "running"
}

fn stable_worker(before: &WorkerObservation, after: &WorkerObservation) -> bool {
    before.pid == after.pid
        && before.executable == after.executable
        && before.matching_workers == 1
        && after.matching_workers == 1
        && before.executable_beneath_bound_scratch
        && after.executable_beneath_bound_scratch
}

fn write_no_clobber(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    File::open(path.parent().expect("validated output parent"))?.sync_all()?;
    Ok(())
}

fn run(config: Config) -> Result<()> {
    let (previous_bytes, previous_timestamp, previous_unix) =
        previous_sample(&config.previous_sample)?;
    let started_unix = now_unix()?;
    ensure!(
        started_unix >= previous_unix,
        "current clock predates previous sample"
    );
    let interval = started_unix - previous_unix;
    ensure!(
        interval >= config.minimum_interval_seconds,
        "routine observation interval is only {interval} seconds; require {}",
        config.minimum_interval_seconds
    );

    let available_before = filesystem_available_bytes(&config.filesystem_path)?;
    let (memory_total_kib, memory_available_before_kib) = host_memory()?;
    let mut observations = Vec::with_capacity(config.replays.len());
    for replay in &config.replays {
        let controller_before = observe_unit(
            &replay.controller_unit,
            &replay.expected_controller_invocation_id,
        )?;
        let producer_before = observe_unit(
            &replay.producer_unit,
            &replay.expected_producer_invocation_id,
        )?;
        let worker_before =
            observe_worker(&replay.scratch_path, &replay.worker_executable_basename)?;
        let scratch_pass_1 = scan_scratch(&replay.scratch_path)?;
        let scratch_pass_2 = scan_scratch(&replay.scratch_path)?;
        let controller_after = observe_unit(
            &replay.controller_unit,
            &replay.expected_controller_invocation_id,
        )?;
        let producer_after = observe_unit(
            &replay.producer_unit,
            &replay.expected_producer_invocation_id,
        )?;
        let worker_after =
            observe_worker(&replay.scratch_path, &replay.worker_executable_basename)?;
        let invocation_binding_stable = stable_unit(&controller_before, &controller_after)
            && stable_unit(&producer_before, &producer_after)
            && stable_worker(&worker_before, &worker_after);
        ensure!(
            invocation_binding_stable,
            "{} invocation or worker changed during observation",
            replay.range
        );
        let conservative_observed_physical_bytes = scratch_pass_1
            .physical_bytes
            .max(scratch_pass_2.physical_bytes);
        let within_sample_physical_delta_bytes =
            i128::from(scratch_pass_2.physical_bytes) - i128::from(scratch_pass_1.physical_bytes);
        observations.push(ReplayObservation {
            range: replay.range.clone(),
            controller_before,
            producer_before,
            worker_before,
            scratch_path: replay.scratch_path.clone(),
            scratch_measurement_method:
                "two race-tolerant non-symlink-following physical-block scans",
            scratch_pass_1,
            scratch_pass_2,
            conservative_observed_physical_bytes,
            within_sample_physical_delta_bytes,
            controller_after,
            producer_after,
            worker_after,
            invocation_binding_stable,
        });
    }
    let available_after = filesystem_available_bytes(&config.filesystem_path)?;
    let (_, memory_available_after_kib) = host_memory()?;
    let completed_unix = now_unix()?;
    let next_observation = started_unix
        .checked_add(config.minimum_interval_seconds)
        .ok_or_else(|| anyhow!("next-observation timestamp overflow"))?;
    let value = serde_json::json!({
        "schema": OUTPUT_SCHEMA,
        "recorded_at_utc": format_utc(started_unix)?,
        "completed_at_utc": format_utc(completed_unix)?,
        "cadence": {
            "previous_sample": config.previous_sample,
            "previous_sample_recorded_at_utc": previous_timestamp,
            "previous_sample_sha256": sha256(&previous_bytes),
            "minimum_interval_seconds": config.minimum_interval_seconds,
            "observed_interval_seconds": interval,
            "next_routine_observation_not_before_utc": format_utc(next_observation)?,
        },
        "filesystem": {
            "path": config.filesystem_path,
            "available_bytes_before": available_before,
            "available_bytes_after": available_after,
            "conservative_available_bytes": available_before.min(available_after),
        },
        "host_memory": {
            "total_kib": memory_total_kib,
            "available_kib_before": memory_available_before_kib,
            "available_kib_after": memory_available_after_kib,
            "conservative_available_kib": memory_available_before_kib.min(memory_available_after_kib),
        },
        "vm_max_map_count": vm_max_map_count()?,
        "replays": observations,
        "mutation": {
            "producer_or_controller_signals_sent": false,
            "service_state_changed": false,
            "remote_mutations": false,
            "r2_mutations": false,
        }
    });
    write_no_clobber(&config.output, &value)
}

fn main() -> Result<()> {
    run(parse_args()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_round_trip_known_values() {
        for (text, unix) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2000-02-29T12:34:56Z", 951_827_696),
            ("2026-10-13T16:13:20Z", 1_791_908_000),
        ] {
            assert_eq!(parse_utc(text).unwrap(), unix);
            assert_eq!(format_utc(unix).unwrap(), text);
        }
    }

    #[test]
    fn scratch_scan_does_not_follow_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("large"), vec![7_u8; 64 * 1024]).unwrap();
        fs::create_dir(directory.path().join("inside")).unwrap();
        fs::write(directory.path().join("inside/file"), b"sample").unwrap();
        std::os::unix::fs::symlink(outside.path(), directory.path().join("link")).unwrap();
        let scan = scan_scratch(directory.path()).unwrap();
        assert_eq!(scan.regular_files, 1);
        assert_eq!(scan.directories, 2);
        assert_eq!(scan.symlinks, 1);
        assert_eq!(scan.entries, 4);
    }

    #[test]
    fn no_clobber_writer_refuses_existing_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("receipt.json");
        fs::write(&output, b"preserve me").unwrap();
        assert!(write_no_clobber(&output, &serde_json::json!({"new": true})).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preserve me");
    }
}
