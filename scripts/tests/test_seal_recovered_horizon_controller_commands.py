import unittest

from scripts import seal_recovered_horizon_controller_commands as seal


class RecoveredControllerCommandTests(unittest.TestCase):
    def test_extracts_controller_argv_with_separator(self) -> None:
        path = "/sealed/controller.py"
        command = (
            "sudo -n systemd-run --unit=test.service --property=PrivateTmp=yes -- "
            f"/usr/bin/python3 {path} --first-epoch=134 --execute"
        )
        self.assertEqual(
            seal.controller_argv(command, seal.Path(path)),
            ["--first-epoch=134", "--execute"],
        )

    def test_extracts_controller_argv_without_separator(self) -> None:
        path = "/sealed/controller.py"
        command = (
            "sudo -n systemd-run --unit=test.service --setenv=VALUE=1 "
            f"/usr/bin/python3 {path} --first-epoch=134 --execute"
        )
        self.assertEqual(
            seal.controller_argv(command, seal.Path(path)),
            ["--first-epoch=134", "--execute"],
        )

    def test_rejects_ambiguous_controller_path(self) -> None:
        path = "/sealed/controller.py"
        command = f"/usr/bin/python3 {path} {path}"
        with self.assertRaisesRegex(seal.SealError, "one exact controller path"):
            seal.controller_argv(command, seal.Path(path))


if __name__ == "__main__":
    unittest.main()
