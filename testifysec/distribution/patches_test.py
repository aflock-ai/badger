# jade:ring local
"""Source reconstruction must never turn source links into Git configuration writes."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from patches import replace_from_archive


class SourceArchiveBoundary(unittest.TestCase):
    def test_git_metadata_cannot_be_reached_through_source_symlinks(self):
        for target in (".git", "./.git", "dir/../.git", ".GiT", "../outside"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / ".git").mkdir()
                (root / ".git/config").write_text("protected")
                archive = io.BytesIO()
                with tarfile.open(fileobj=archive, mode="w") as tar:
                    link = tarfile.TarInfo("alias")
                    link.type = tarfile.SYMTYPE
                    link.linkname = target
                    tar.addfile(link)
                    file = tarfile.TarInfo("alias/config")
                    file.size = 6
                    tar.addfile(file, io.BytesIO(b"poison"))
                with self.assertRaises(ValueError):
                    replace_from_archive(root, archive.getvalue())
                self.assertEqual((root / ".git/config").read_text(), "protected")

    def test_safe_source_links_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as tar:
                file = tarfile.TarInfo("source")
                file.size = 2
                tar.addfile(file, io.BytesIO(b"ok"))
                link = tarfile.TarInfo("alias")
                link.type = tarfile.SYMTYPE
                link.linkname = "source"
                tar.addfile(link)
            replace_from_archive(root, archive.getvalue())
            self.assertTrue((root / "alias").is_symlink())
            self.assertEqual((root / "alias").read_bytes(), b"ok")


if __name__ == "__main__":
    unittest.main()
