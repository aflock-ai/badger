import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location("extract_worker", Path(__file__).with_name("extract-worker.py"))
extract_worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract_worker)

REQUIRED = ["--image", "sha256:" + "0" * 64, "--worker", "w", "--output", "o"]


class SocketTest(unittest.TestCase):
    def test_defaults_to_the_callers_local_docker_desktop_socket(self):
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote-host:2375"}):
            args = extract_worker.parse_args(REQUIRED)
        self.assertEqual(args.socket, f"unix://{Path.home()}/.docker/run/docker.sock")

    def test_refuses_a_socket_that_is_not_local(self):
        for socket in ("tcp://remote-host:2375", "ssh://user@host", "https://host", "npipe:////./pipe/x"):
            with self.subTest(socket=socket), self.assertRaises(SystemExit):
                extract_worker.parse_args(REQUIRED + ["--socket", socket])

    def test_accepts_an_explicit_local_socket(self):
        args = extract_worker.parse_args(REQUIRED + ["--socket", "unix:///var/run/docker.sock"])
        self.assertEqual(args.socket, "unix:///var/run/docker.sock")


class AbsenceTest(unittest.TestCase):
    name = "hc-vm-input-0123abcd"

    def test_either_cli_casing_of_the_prefix_confirms_absence(self):
        for prefix in ("Error: No such object: ", "error: no such object: "):
            with self.subTest(prefix=prefix):
                self.assertTrue(extract_worker.absent(1, (prefix + self.name + "\n").encode(), self.name))

    def test_the_name_must_match_verbatim(self):
        for other in (self.name.upper(), self.name + "x", "other"):
            with self.subTest(other=other):
                self.assertFalse(extract_worker.absent(1, ("error: no such object: " + other).encode(), self.name))

    def test_any_other_failure_does_not_confirm_absence(self):
        self.assertFalse(extract_worker.absent(2, ("error: no such object: " + self.name).encode(), self.name))
        self.assertFalse(extract_worker.absent(1, b"Cannot connect to the Docker daemon", self.name))


if __name__ == "__main__":
    unittest.main()
