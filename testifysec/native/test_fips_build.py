import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("fips_build", Path(__file__).with_name("fips-build.py"))
fips_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fips_build)


def fake_run(listed):
    calls = []

    def run(command, **_):
        calls.append(command)
        stdout = listed.encode() if command[:2] == ["go", "list"] else b""
        return subprocess.CompletedProcess(command, 0, stdout, b"")

    return run, calls


class RookerySourcesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.module = Path(self.temporary.name) / "attestation@v0.1.0"
        for package in fips_build.ROOKERY_PACKAGES:
            (self.module / package).mkdir(parents=True)
            (self.module / package / (package + ".go")).write_text("package " + package + "\n")

    def tearDown(self):
        self.temporary.cleanup()

    def test_extracts_offline_then_returns_every_package_source(self):
        run, calls = fake_run(str(self.module))
        directory, paths = fips_build.rookery_sources(run)
        self.assertEqual(calls[0], ["go", "mod", "download", fips_build.ROOKERY_MODULE])
        self.assertEqual(directory, self.module)
        self.assertEqual({p.parent.name for p in paths}, set(fips_build.ROOKERY_PACKAGES))

    def test_an_empty_module_directory_refuses(self):
        # go list -m prints an empty Dir for a cached but unextracted module. Run from a directory
        # that does hold the packages, so only the empty-Dir check can refuse.
        previous = os.getcwd()
        os.chdir(self.module)
        try:
            with self.assertRaises(RuntimeError):
                fips_build.rookery_sources(fake_run("")[0])
        finally:
            os.chdir(previous)

    def test_a_missing_directory_refuses(self):
        with self.assertRaises(RuntimeError):
            fips_build.rookery_sources(fake_run(str(self.module / "absent"))[0])

    def test_a_package_without_go_sources_refuses(self):
        (self.module / "dsse" / "dsse.go").unlink()
        with self.assertRaises(RuntimeError):
            fips_build.rookery_sources(fake_run(str(self.module))[0])


if __name__ == "__main__":
    unittest.main()
