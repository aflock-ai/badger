# jade:ring local
"""Native customer labels remain available without starting a runtime."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class NativeBrandingTest(unittest.TestCase):
    def test_owned_launcher_labels_preserve_upstream_attribution(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="badger-native-branding-") as directory:
            runtime = Path(directory) / "fixture-runtime"
            runtime.write_bytes(b"not an executable; help must never start this")
            launcher = Path(directory) / "badger"
            build = subprocess.run([
                "python3", str(root / "testifysec/native/wrap.py"),
                "--go", shutil.which("go"), "--runtime", str(runtime),
                "--output", str(launcher), "--brand-product",
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr)
            runtime.unlink()
            for flag in ("--help", "--version"):
                result = subprocess.run([str(launcher), flag], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Badger", result.stdout)
                self.assertIn("Built on OpenCode. Upstream licenses and attribution are preserved.", result.stdout)
                self.assertNotIn("Aflock", result.stdout)
                self.assertIn("Usage: badger < request.json" if flag == "--help" else "OpenCode ", result.stdout)
                if flag == "--version":
                    self.assertIn("Badger " + (root / "VERSION").read_text().strip(), result.stdout)
            result = subprocess.run([str(launcher), "--help", "--version"], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
