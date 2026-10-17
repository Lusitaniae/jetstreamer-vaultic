//! Derive deterministic Horizon sidecar ETAs from one identity-stable observer receipt.

use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    },
};

const MODEL_SCHEMA: &str = "jetstreamer-horizon-r2-status-eta-model-v1";
const OBSERVER_SCHEMA: &str = "jetstreamer-horizon-live-resource-sample-v2";
const OUTPUT_SCHEMA: &str = "jetstreamer-horizon-r2-status-estimates-v1";
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug)]
struct Arguments {
    model: PathBuf,
    model_sha256: String,
    observer: PathBuf,
    observer_sha256: String,
    self_sha256: String,
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Model {
    schema: String,
    sample_target_utc: String,
    phase: String,
    status_receipt_directory: PathBuf,
    evidence: Vec<Evidence>,
    rounding: String,
    ranges: Vec<RangeModel>,
    validation: Validation,
    authority: Authority,
}

#[derive(Debug, Deserialize)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct RangeModel {
    range: String,
    expected_controller_invocation_id: String,
    expected_producer_invocation_id: String,
    archive_directory: PathBuf,
    epochs: Vec<u64>,
    elapsed_execution_millis: u64,
    terminal_slot: u64,
    current_completion_overhead_seconds: u64,
    second_epoch_commit_offset_seconds: u64,
    next_pair_replay_seconds: u64,
    formula: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Authority {
    publication_authorized_only_after_bound_v2_observer_receipt: bool,
    replay_launch_authorized: bool,
    archive_publication_authorized: bool,
    r2_archive_mutations_authorized: bool,
}

#[derive(Debug, Deserialize)]
struct Validation {
    #[serde(rename = "matches_2026_10_17T04_17_00Z_statuses_within_one_second")]
    matches_2026_10_17_t04_17_00_z_statuses_within_one_second: bool,
    #[serde(rename = "reproduces_2026_10_17T04_47_00Z_statuses_exactly")]
    reproduces_2026_10_17_t04_47_00_z_statuses_exactly: bool,
}

#[derive(Debug, Deserialize)]
struct Observer {
    schema: String,
    recorded_at_utc: String,
    replays: Vec<Replay>,
}

#[derive(Debug, Deserialize)]
struct Replay {
    range: String,
    controller_after: Unit,
    producer_after: Unit,
    useful_work: UsefulWork,
    invocation_binding_stable: bool,
}

#[derive(Debug, Deserialize)]
struct Unit {
    invocation_id: String,
    restarts: u64,
    active_state: String,
    sub_state: String,
}

#[derive(Debug, Deserialize)]
struct UsefulWork {
    last: Option<ProgressPoint>,
    slots_per_second: Option<f64>,
    sufficient_for_rates: bool,
}

#[derive(Debug, Deserialize)]
struct ProgressPoint {
    slot: u64,
    terminal_slot: u64,
}

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    sampled_at_utc: String,
    observer_path: String,
    observer_sha256: String,
    model_path: String,
    model_sha256: String,
    estimator_sha256: String,
    phase: String,
    status_receipt_directory: String,
    ranges: Vec<RangeOutput>,
    estimates: Vec<EpochEstimate>,
    mutations: Mutations,
}

#[derive(Debug, Serialize)]
struct RangeOutput {
    range: String,
    observed_last_slot: u64,
    terminal_slot: u64,
    slots_per_second: f64,
    current_completion_seconds: u64,
}

#[derive(Debug, Serialize)]
struct EpochEstimate {
    epoch: u64,
    archive_directory: String,
    expected_controller_invocation_id: String,
    expected_producer_invocation_id: String,
    elapsed_execution_millis: u64,
    estimated_remaining_millis: u64,
}

#[derive(Debug, Serialize)]
struct Mutations {
    replay_state_changed: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} --model PATH --model-sha256 HEX --observer PATH --observer-sha256 HEX --self-sha256 HEX --output PATH"
    )
}

fn parse_args() -> Result<Arguments> {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| "jetstreamer-horizon-status-estimate".into());
    let mut values = BTreeMap::<String, PathBuf>::new();
    while let Some(flag) = args.next() {
        let flag = flag
            .to_str()
            .context("arguments must be UTF-8")?
            .to_string();
        ensure!(
            matches!(
                flag.as_str(),
                "--model"
                    | "--model-sha256"
                    | "--observer"
                    | "--observer-sha256"
                    | "--self-sha256"
                    | "--output"
            ),
            "{}\nunknown option {flag}",
            usage(&program.to_string_lossy())
        );
        let value = args
            .next()
            .with_context(|| format!("missing value for {flag}"))?;
        ensure!(
            values.insert(flag, value.into()).is_none(),
            "duplicate option"
        );
    }
    let take = |name: &str| -> Result<PathBuf> {
        values
            .get(name)
            .cloned()
            .with_context(|| format!("missing {name}"))
    };
    Ok(Arguments {
        model: take("--model")?,
        model_sha256: take("--model-sha256")?.to_string_lossy().into_owned(),
        observer: take("--observer")?,
        observer_sha256: take("--observer-sha256")?.to_string_lossy().into_owned(),
        self_sha256: take("--self-sha256")?.to_string_lossy().into_owned(),
        output: take("--output")?,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_exact(path: &Path, expected_sha256: &str, immutable_root_owned: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    ensure!(
        path.canonicalize()? == path,
        "path is not exact: {}",
        path.display()
    );
    ensure!(valid_sha256(expected_sha256), "invalid expected SHA-256");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "input is not a regular file");
    ensure!(before.nlink() == 1, "input is not singly linked");
    ensure!(before.len() <= MAX_INPUT_BYTES, "input exceeds size bound");
    if immutable_root_owned {
        ensure!(before.uid() == 0, "input is not root-owned");
        ensure!(before.mode() & 0o222 == 0, "input is writable");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == before.len(), "input length changed");
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    ensure!(
        current.is_file()
            && !current.file_type().is_symlink()
            && identity(&before) == identity(&after)
            && identity(&before) == identity(&current),
        "input changed while reading"
    );
    let actual = format!("{:x}", Sha256::digest(&bytes));
    ensure!(actual == expected_sha256, "input SHA-256 mismatch");
    Ok(bytes)
}

fn validate_model(model: &Model) -> Result<()> {
    ensure!(model.schema == MODEL_SCHEMA, "model schema mismatch");
    ensure!(model.phase == "replay", "model phase mismatch");
    ensure!(
        model.status_receipt_directory.is_absolute(),
        "status receipt directory is not absolute"
    );
    ensure!(
        model.rounding
            == "round each estimated total to the nearest whole second, then multiply by 1000",
        "model rounding policy mismatch"
    );
    ensure!(!model.evidence.is_empty(), "model lacks evidence");
    for evidence in &model.evidence {
        ensure!(
            evidence.path.is_absolute(),
            "model evidence path is not absolute"
        );
        ensure!(
            valid_sha256(&evidence.sha256),
            "model evidence SHA-256 is invalid"
        );
    }
    ensure!(
        model
            .validation
            .matches_2026_10_17_t04_17_00_z_statuses_within_one_second
            && model
                .validation
                .reproduces_2026_10_17_t04_47_00_z_statuses_exactly,
        "model validation evidence is incomplete"
    );
    ensure!(
        model
            .authority
            .publication_authorized_only_after_bound_v2_observer_receipt
            && !model.authority.replay_launch_authorized
            && !model.authority.archive_publication_authorized
            && !model.authority.r2_archive_mutations_authorized,
        "model authority is unsafe"
    );
    ensure!(
        model.ranges.len() == 2,
        "expected exactly two public ranges"
    );
    let mut ranges = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    for range in &model.ranges {
        ensure!(
            ranges.insert(range.range.as_str()),
            "duplicate modeled range"
        );
        ensure!(
            range.epochs.len() == 4,
            "modeled range must contain four epochs"
        );
        ensure!(
            range.archive_directory.is_absolute(),
            "modeled archive directory is not absolute"
        );
        ensure!(range.formula.len() == 4, "modeled range lacks formulas");
        ensure!(
            range.expected_controller_invocation_id.len() == 32
                && range
                    .expected_controller_invocation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                && range.expected_producer_invocation_id.len() == 32
                && range
                    .expected_producer_invocation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "invalid modeled invocation ID"
        );
        for epoch in &range.epochs {
            ensure!(epochs.insert(*epoch), "duplicate modeled epoch");
            ensure!(
                range.formula.contains_key(&epoch.to_string()),
                "missing epoch formula"
            );
        }
    }
    ensure!(
        epochs == (216..=223).collect(),
        "model does not cover exactly epochs 216-223"
    );
    Ok(())
}

fn estimate_range(
    model: &RangeModel,
    replay: &Replay,
) -> Result<(RangeOutput, Vec<EpochEstimate>)> {
    ensure!(replay.range == model.range, "range mismatch");
    ensure!(
        replay.invocation_binding_stable,
        "observer binding is not stable"
    );
    for unit in [&replay.controller_after, &replay.producer_after] {
        ensure!(unit.restarts == 0, "observed unit restarted");
        ensure!(
            unit.active_state == "active" && unit.sub_state == "running",
            "observed unit is not running"
        );
    }
    ensure!(
        replay.controller_after.invocation_id == model.expected_controller_invocation_id,
        "controller invocation mismatch"
    );
    ensure!(
        replay.producer_after.invocation_id == model.expected_producer_invocation_id,
        "producer invocation mismatch"
    );
    ensure!(
        replay.useful_work.sufficient_for_rates,
        "observer rate is insufficient"
    );
    let last = replay
        .useful_work
        .last
        .as_ref()
        .context("observer lacks last progress point")?;
    let rate = replay
        .useful_work
        .slots_per_second
        .context("observer lacks slot rate")?;
    ensure!(
        rate.is_finite() && rate > 0.0,
        "observer slot rate is invalid"
    );
    ensure!(
        last.terminal_slot == model.terminal_slot,
        "terminal slot mismatch"
    );
    ensure!(
        last.slot <= model.terminal_slot,
        "observed slot exceeds terminal"
    );
    let replay_seconds = (model.terminal_slot - last.slot) as f64 / rate;
    let first_seconds = (replay_seconds + model.current_completion_overhead_seconds as f64).round();
    ensure!(
        first_seconds.is_finite() && first_seconds >= 0.0,
        "ETA is invalid"
    );
    let first = first_seconds as u64;
    let values = [
        first,
        first
            .checked_add(model.second_epoch_commit_offset_seconds)
            .context("ETA overflow")?,
        first
            .checked_add(model.next_pair_replay_seconds)
            .context("ETA overflow")?,
        first
            .checked_add(model.next_pair_replay_seconds)
            .and_then(|value| value.checked_add(model.second_epoch_commit_offset_seconds))
            .context("ETA overflow")?,
    ];
    let estimates = model
        .epochs
        .iter()
        .zip(values)
        .map(|(epoch, seconds)| {
            Ok(EpochEstimate {
                epoch: *epoch,
                archive_directory: model.archive_directory.display().to_string(),
                expected_controller_invocation_id: model.expected_controller_invocation_id.clone(),
                expected_producer_invocation_id: model.expected_producer_invocation_id.clone(),
                elapsed_execution_millis: model.elapsed_execution_millis,
                estimated_remaining_millis: seconds
                    .checked_mul(1000)
                    .context("millisecond overflow")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        RangeOutput {
            range: model.range.clone(),
            observed_last_slot: last.slot,
            terminal_slot: model.terminal_slot,
            slots_per_second: rate,
            current_completion_seconds: first,
        },
        estimates,
    ))
}

fn validate_output_path(path: &Path) -> Result<()> {
    ensure!(
        path.parent()
            == Some(Path::new(
                "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness",
            )),
        "unexpected output parent"
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid output filename")?;
    ensure!(
        name.starts_with("horizon-r2-status-estimates-") && name.ends_with(".json"),
        "unexpected output filename"
    );
    Ok(())
}

fn fsync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fsync_directory(path.parent().context("output has no parent")?)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn run() -> Result<()> {
    let arguments = parse_args()?;
    validate_output_path(&arguments.output)?;
    let executable = fs::read_link("/proc/self/exe")?;
    read_exact(&executable, &arguments.self_sha256, true)?;
    let model_bytes = read_exact(&arguments.model, &arguments.model_sha256, true)?;
    let observer_bytes = read_exact(&arguments.observer, &arguments.observer_sha256, false)?;
    let model: Model = serde_json::from_slice(&model_bytes).context("invalid model JSON")?;
    let observer: Observer =
        serde_json::from_slice(&observer_bytes).context("invalid observer JSON")?;
    validate_model(&model)?;
    ensure!(
        model.status_receipt_directory.canonicalize()? == model.status_receipt_directory,
        "status receipt directory path is not exact"
    );
    let receipt_directory_metadata = fs::symlink_metadata(&model.status_receipt_directory)?;
    ensure!(
        receipt_directory_metadata.is_dir()
            && receipt_directory_metadata.uid() == 0
            && receipt_directory_metadata.mode() & 0o7777 == 0o700,
        "status receipt directory identity or mode mismatch"
    );
    for evidence in &model.evidence {
        read_exact(&evidence.path, &evidence.sha256, false)
            .with_context(|| format!("model evidence failed: {}", evidence.path.display()))?;
    }
    ensure!(
        observer.schema == OBSERVER_SCHEMA,
        "observer schema mismatch"
    );
    ensure!(
        observer.recorded_at_utc == model.sample_target_utc,
        "observer timestamp mismatch"
    );
    ensure!(
        observer.replays.len() == 3,
        "observer replay census mismatch"
    );

    let mut ranges = Vec::new();
    let mut estimates = Vec::new();
    for range_model in &model.ranges {
        ensure!(
            range_model.archive_directory.canonicalize()? == range_model.archive_directory,
            "archive directory path is not exact"
        );
        ensure!(
            fs::symlink_metadata(&range_model.archive_directory)?.is_dir(),
            "archive directory is not a directory"
        );
        let matches: Vec<_> = observer
            .replays
            .iter()
            .filter(|replay| replay.range == range_model.range)
            .collect();
        ensure!(
            matches.len() == 1,
            "observer range is missing or duplicated"
        );
        let (range, mut range_estimates) = estimate_range(range_model, matches[0])?;
        ranges.push(range);
        estimates.append(&mut range_estimates);
    }
    estimates.sort_by_key(|item| item.epoch);
    let output = Output {
        schema: OUTPUT_SCHEMA,
        sampled_at_utc: observer.recorded_at_utc,
        observer_path: arguments.observer.display().to_string(),
        observer_sha256: arguments.observer_sha256,
        model_path: arguments.model.display().to_string(),
        model_sha256: arguments.model_sha256,
        estimator_sha256: arguments.self_sha256,
        phase: model.phase,
        status_receipt_directory: model.status_receipt_directory.display().to_string(),
        ranges,
        estimates,
        mutations: Mutations {
            replay_state_changed: false,
            remote_mutations: false,
            r2_mutations: false,
        },
    };
    let mut bytes = serde_json::to_vec_pretty(&output)?;
    bytes.push(b'\n');
    let digest = write_new(&arguments.output, &bytes)?;
    println!(
        "{}",
        serde_json::json!({"path": arguments.output, "sha256": digest})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(invocation_id: &str) -> Unit {
        Unit {
            invocation_id: invocation_id.to_string(),
            restarts: 0,
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
        }
    }

    #[test]
    fn reproduces_latest_lane_216_estimates() {
        let controller = "2b6ded8d8baf4f72a5c8a91385f7c278";
        let producer = "95fb05d1b78349bcb907c1e930e7682e";
        let model = RangeModel {
            range: "216-219".to_string(),
            expected_controller_invocation_id: controller.to_string(),
            expected_producer_invocation_id: producer.to_string(),
            archive_directory: "/tmp/lane-216-output".into(),
            epochs: vec![216, 217, 218, 219],
            elapsed_execution_millis: 336_638_000,
            terminal_slot: 94_175_999,
            current_completion_overhead_seconds: 10_230,
            second_epoch_commit_offset_seconds: 2_442,
            next_pair_replay_seconds: 347_843,
            formula: (216..=219)
                .map(|epoch| (epoch.to_string(), "bound".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(controller),
            producer_after: unit(producer),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 94_145_814,
                    terminal_slot: 94_175_999,
                }),
                slots_per_second: Some(2.8857456247679627),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        let (_, estimates) = estimate_range(&model, &replay).unwrap();
        assert!(
            estimates
                .iter()
                .all(|item| item.elapsed_execution_millis == 336_638_000)
        );
        assert!(estimates.iter().all(|item| {
            item.archive_directory == "/tmp/lane-216-output"
                && item.expected_controller_invocation_id == controller
                && item.expected_producer_invocation_id == producer
        }));
        assert_eq!(
            estimates
                .iter()
                .map(|item| item.estimated_remaining_millis)
                .collect::<Vec<_>>(),
            vec![20_690_000, 23_132_000, 368_533_000, 370_975_000]
        );
    }

    #[test]
    fn rejects_identity_change() {
        let model = RangeModel {
            range: "220-223".to_string(),
            expected_controller_invocation_id: "0".repeat(32),
            expected_producer_invocation_id: "1".repeat(32),
            archive_directory: "/tmp/lane-220-output".into(),
            epochs: vec![220, 221, 222, 223],
            elapsed_execution_millis: 214_176_000,
            terminal_slot: 95_903_999,
            current_completion_overhead_seconds: 8_779,
            second_epoch_commit_offset_seconds: 2_442,
            next_pair_replay_seconds: 334_084,
            formula: (220..=223)
                .map(|epoch| (epoch.to_string(), "bound".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(&"f".repeat(32)),
            producer_after: unit(&"1".repeat(32)),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 95_592_968,
                    terminal_slot: 95_903_999,
                }),
                slots_per_second: Some(2.5149505547550577),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        assert!(estimate_range(&model, &replay).is_err());
    }

    #[test]
    fn reproduces_latest_lane_220_estimates() {
        let controller = "0b69b5009dc74bbda94b94d059a3daa7";
        let producer = "c2adebaad0cb42b385156631156813fe";
        let model = RangeModel {
            range: "220-223".to_string(),
            expected_controller_invocation_id: controller.to_string(),
            expected_producer_invocation_id: producer.to_string(),
            archive_directory: "/tmp/lane-220-output".into(),
            epochs: vec![220, 221, 222, 223],
            elapsed_execution_millis: 214_176_000,
            terminal_slot: 95_903_999,
            current_completion_overhead_seconds: 8_779,
            second_epoch_commit_offset_seconds: 2_442,
            next_pair_replay_seconds: 334_084,
            formula: (220..=223)
                .map(|epoch| (epoch.to_string(), "bound".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(controller),
            producer_after: unit(producer),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 95_592_968,
                    terminal_slot: 95_903_999,
                }),
                slots_per_second: Some(2.5149505547550577),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        let (_, estimates) = estimate_range(&model, &replay).unwrap();
        assert_eq!(
            estimates
                .iter()
                .map(|item| item.estimated_remaining_millis)
                .collect::<Vec<_>>(),
            vec![132_452_000, 134_894_000, 466_536_000, 468_978_000]
        );
    }

    #[test]
    fn reproduces_previous_sample_for_both_lanes() {
        let cases = [
            (
                RangeModel {
                    range: "216-219".to_string(),
                    expected_controller_invocation_id: "2b6ded8d8baf4f72a5c8a91385f7c278"
                        .to_string(),
                    expected_producer_invocation_id: "95fb05d1b78349bcb907c1e930e7682e".to_string(),
                    archive_directory: "/tmp/lane-216-output".into(),
                    epochs: vec![216, 217, 218, 219],
                    elapsed_execution_millis: 334_838_000,
                    terminal_slot: 94_175_999,
                    current_completion_overhead_seconds: 10_230,
                    second_epoch_commit_offset_seconds: 2_442,
                    next_pair_replay_seconds: 347_843,
                    formula: (216..=219)
                        .map(|epoch| (epoch.to_string(), "bound".to_string()))
                        .collect(),
                },
                94_140_628,
                2.759349388074035,
                vec![23_048_000, 25_490_000, 370_891_000, 373_333_000],
            ),
            (
                RangeModel {
                    range: "220-223".to_string(),
                    expected_controller_invocation_id: "0b69b5009dc74bbda94b94d059a3daa7"
                        .to_string(),
                    expected_producer_invocation_id: "c2adebaad0cb42b385156631156813fe".to_string(),
                    archive_directory: "/tmp/lane-220-output".into(),
                    epochs: vec![220, 221, 222, 223],
                    elapsed_execution_millis: 212_376_000,
                    terminal_slot: 95_903_999,
                    current_completion_overhead_seconds: 8_779,
                    second_epoch_commit_offset_seconds: 2_442,
                    next_pair_replay_seconds: 334_084,
                    formula: (220..=223)
                        .map(|epoch| (epoch.to_string(), "bound".to_string()))
                        .collect(),
                },
                95_588_448,
                2.5660109198403633,
                vec![131_752_000, 134_194_000, 465_836_000, 468_278_000],
            ),
        ];
        for (model, slot, rate, expected) in cases {
            let replay = Replay {
                range: model.range.clone(),
                controller_after: unit(&model.expected_controller_invocation_id),
                producer_after: unit(&model.expected_producer_invocation_id),
                useful_work: UsefulWork {
                    last: Some(ProgressPoint {
                        slot,
                        terminal_slot: model.terminal_slot,
                    }),
                    slots_per_second: Some(rate),
                    sufficient_for_rates: true,
                },
                invocation_binding_stable: true,
            };
            let (_, estimates) = estimate_range(&model, &replay).unwrap();
            for (actual, expected) in estimates
                .iter()
                .map(|item| item.estimated_remaining_millis)
                .zip(expected)
            {
                assert!(actual.abs_diff(expected) <= 1_000);
            }
        }
    }

    #[test]
    fn output_writer_is_private_durable_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("estimate.json");
        let bytes = b"{\"ok\":true}\n";
        let digest = write_new(&path, bytes).unwrap();
        assert_eq!(digest, format!("{:x}", Sha256::digest(bytes)));
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert!(write_new(&path, b"replacement\n").is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
