import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("uat_linux", Path(__file__).with_name("uat-linux.py"))
uat_linux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uat_linux)


class BuildSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.monorepo = Path(self.temporary.name) / "monorepo"
        self.snapshot = Path(self.temporary.name) / "snapshot"
        for selected in uat_linux.BUILD_SOURCE_DIRECTORIES:
            (self.monorepo / selected).mkdir(parents=True)
        (self.monorepo / uat_linux.BUILD_SOURCE_DIRECTORIES[1] / "main.go").write_text("package main\n")
        for name in uat_linux.BUILD_SOURCE_FILES:
            (self.monorepo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.monorepo / name).write_text(name + "\n")

    def tearDown(self):
        self.temporary.cleanup()

    def test_the_standalone_files_reach_the_snapshot_with_their_digests(self):
        copied = uat_linux.copy_build_sources(self.monorepo, self.snapshot)
        for name in uat_linux.BUILD_SOURCE_FILES:
            with self.subTest(name=name):
                self.assertEqual((self.snapshot / name).read_text(), name + "\n")
                self.assertEqual(copied[name], hashlib.sha256((name + "\n").encode()).hexdigest())
        self.assertIn(uat_linux.BUILD_SOURCE_DIRECTORIES[1] + "/main.go", copied)

    def test_a_symlinked_standalone_file_is_refused(self):
        name = uat_linux.BUILD_SOURCE_FILES[0]
        outside = Path(self.temporary.name) / "outside.json"
        outside.write_text("{}")
        (self.monorepo / name).unlink()
        os.symlink(outside, self.monorepo / name)
        with self.assertRaises(RuntimeError):
            uat_linux.copy_build_sources(self.monorepo, self.snapshot)

    def test_a_symlink_inside_a_selected_directory_is_refused(self):
        os.symlink("/etc/hosts", self.monorepo / uat_linux.BUILD_SOURCE_DIRECTORIES[1] / "hosts")
        with self.assertRaises(RuntimeError):
            uat_linux.copy_build_sources(self.monorepo, self.snapshot)


    def test_a_symlink_to_a_directory_inside_a_selected_directory_is_refused(self):
        os.symlink(self.temporary.name, self.monorepo / uat_linux.BUILD_SOURCE_DIRECTORIES[1] / "elsewhere")
        with self.assertRaises(RuntimeError):
            uat_linux.copy_build_sources(self.monorepo, self.snapshot)

    def test_a_dangling_symlink_inside_a_selected_directory_is_refused(self):
        os.symlink(Path(self.temporary.name) / "missing", self.monorepo / uat_linux.BUILD_SOURCE_DIRECTORIES[1] / "gone")
        with self.assertRaises(RuntimeError):
            uat_linux.copy_build_sources(self.monorepo, self.snapshot)

    def test_a_dangling_symlink_as_a_standalone_file_is_refused(self):
        name = uat_linux.BUILD_SOURCE_FILES[1]
        (self.monorepo / name).unlink()
        os.symlink(Path(self.temporary.name) / "missing", self.monorepo / name)
        with self.assertRaises(RuntimeError):
            uat_linux.copy_build_sources(self.monorepo, self.snapshot)


def audit_batch(*events):
    """One OTLP export batch holding (request id, phase, outcome) log records, shaped like the gateway's."""
    records = [{"body": {"stringValue": outcome},
                "attributes": [{"key": "request.id", "value": {"stringValue": request_id}},
                               {"key": "event.id", "value": {"stringValue": request_id + "/" + phase}}]}
               for request_id, phase, outcome in events]
    return {"resourceLogs": [{"scopeLogs": [{"logRecords": records}]}]}


class GraceWaitTest(unittest.TestCase):
    def test_unrelated_audit_events_do_not_complete_a_bound_call(self):
        # One bound call, still missing its terminal event, plus a busy refusal's full pair: as many events as
        # the bound calls need in total, but not the right ones.
        observations = {"requestIds": ["bound"], "auditBatches": [
            audit_batch(("bound", "start", "started")),
            audit_batch(("refused", "start", "started"), ("refused", "terminal", "request-denied"))]}
        self.assertFalse(uat_linux.bound_audit_complete(observations))
        observations["auditBatches"].append(audit_batch(("bound", "terminal", "provider-stream-ended")))
        self.assertTrue(uat_linux.bound_audit_complete(observations))

    def test_every_bound_call_needs_both_phases(self):
        observations = {"requestIds": ["one", "two"], "auditBatches": [
            audit_batch(("one", "start", "started"), ("one", "terminal", "provider-stream-ended"), ("two", "start", "started"))]}
        self.assertFalse(uat_linux.bound_audit_complete(observations))

if __name__ == "__main__":
    unittest.main()
