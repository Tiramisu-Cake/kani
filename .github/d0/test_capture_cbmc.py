# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = pathlib.Path(__file__).with_name("capture_cbmc.py")
spec = importlib.util.spec_from_file_location("capture_cbmc", SCRIPT)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.fake = self.root / "fake_cbmc"
        self.fake.write_text("""#!/usr/bin/env python3
import os, signal, sys
mode = sys.argv[1]
if mode == 'signal':
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == 'signal_kill':
    os.kill(os.getpid(), signal.SIGKILL)
elif mode == 'exit10':
    sys.stdout.buffer.write(b'{\\\"result\\\":[]}\\n')
    sys.exit(10)
elif mode == 'large':
    sys.stdout.buffer.write(b'0123456789abcdef')
elif mode == 'linger':
    open(os.environ['CHILD_PID_FILE'], 'w').write(str(os.getpid()))
    while True:
        time.sleep(0.05)
elif mode == 'trapterm':
    def stopped(_sig, _frame):
        open(os.environ['CHILD_MARKER_FILE'], 'w').write('term-forwarded')
        sys.exit(23)
    signal.signal(signal.SIGTERM, stopped)
    open(os.environ['CHILD_READY_FILE'], 'w').write('ready')
    while True:
        time.sleep(0.05)
else:
    sys.stdout.buffer.write(b'{\\\"ok\\\":true}\\n')
""", encoding="utf-8")
        self.fake.chmod(0o755)
        self.archive = self.root / "archive"

    def tearDown(self):
        self.temp.cleanup()

    def run_fake(self, arg, limit=capture.MAX_CAPTURE_BYTES):
        sink = io.BytesIO()
        code, metadata_path = capture.run_capture([arg], str(self.fake), str(self.archive), sink,
                                                   capture_limit=limit, invoked_as="cbmc")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        return code, sink.getvalue(), metadata, self.archive / metadata["retained_stdout_file"]

    def test_success_forwards_stdout_and_archives_hash_and_argv(self):
        code, forwarded, metadata, archive = self.run_fake("success")
        self.assertEqual(code, 0)
        self.assertEqual(forwarded, b'{"ok":true}\n')
        self.assertEqual(archive.read_bytes(), forwarded)
        self.assertEqual(metadata["argv"], ["cbmc", "success"])
        self.assertEqual(metadata["original_stdout_sha256"], hashlib.sha256(forwarded).hexdigest())
        self.assertTrue(metadata["captured_complete"])

    def test_exit_10_is_preserved(self):
        code, forwarded, metadata, _ = self.run_fake("exit10")
        self.assertEqual(code, 10)
        self.assertEqual(metadata["child_exit"], 10)
        self.assertEqual(metadata["child_signal"], None)
        self.assertEqual(metadata["original_stdout_sha256"], hashlib.sha256(forwarded).hexdigest())

    def test_capture_cap_does_not_truncate_forwarded_stdout(self):
        code, forwarded, metadata, archive = self.run_fake("large", limit=5)
        self.assertEqual(code, 0)
        self.assertEqual(forwarded, b"0123456789abcdef")
        self.assertEqual(archive.read_bytes(), b"01234")
        self.assertEqual(metadata["dropped_bytes"], 11)
        self.assertFalse(metadata["captured_complete"])
        self.assertEqual(metadata["original_stdout_sha256"], hashlib.sha256(forwarded).hexdigest())

    def test_child_signal_is_preserved_by_wrapper_process(self):
        env = os.environ.copy()
        env["D0_REAL_CBMC"] = str(self.fake)
        env["D0_CAPTURE_DIR"] = str(self.archive)
        result = subprocess.run([sys.executable, str(SCRIPT), "signal"], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, -signal.SIGTERM)
        metadata_path = next(self.archive.glob("*.meta.json"))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["child_signal"], signal.SIGTERM)
        self.assertEqual(metadata["child_exit"], None)

    def test_sigkill_child_is_preserved_without_invalid_signal_handler(self):
        env = os.environ.copy()
        env["D0_REAL_CBMC"] = str(self.fake)
        env["D0_CAPTURE_DIR"] = str(self.archive)
        result = subprocess.run([sys.executable, str(SCRIPT), "signal_kill"], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, -signal.SIGKILL)
        metadata_path = next(self.archive.glob("*.meta.json"))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["child_signal"], signal.SIGKILL)

    def test_killing_wrapper_also_kills_solver_child(self):
        pid_file = self.root / "child.pid"
        env = os.environ.copy()
        env.update({"D0_REAL_CBMC": str(self.fake), "D0_CAPTURE_DIR": str(self.archive),
                    "CHILD_PID_FILE": str(pid_file)})
        wrapper = subprocess.Popen([sys.executable, str(SCRIPT), "linger"], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(pid_file.exists(), "fake solver did not start")
        child_pid = int(pid_file.read_text())
        os.kill(wrapper.pid, signal.SIGKILL)
        wrapper.wait(timeout=5)
        if wrapper.stderr:
            wrapper.stderr.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                stat = pathlib.Path(f"/proc/{child_pid}/stat").read_text()
                if stat.split()[2] == "Z":
                    break
            except (FileNotFoundError, ProcessLookupError):
                break
            time.sleep(0.02)
        try:
            state = pathlib.Path(f"/proc/{child_pid}/stat").read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            state = None
        self.assertIn(state, (None, "Z"), "solver child survived wrapper SIGKILL")
        metadata_path = next(self.archive.glob("*.meta.json"))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["capture_state"], "RUNNING")
        self.assertFalse(metadata["captured_complete"])

    def test_wrapper_forwards_catchable_signal_and_records_it(self):
        marker = self.root / "term.marker"
        env = os.environ.copy()
        env.update({"D0_REAL_CBMC": str(self.fake), "D0_CAPTURE_DIR": str(self.archive),
                    "CHILD_MARKER_FILE": str(marker), "CHILD_READY_FILE": str(self.root / "term.ready")})
        wrapper = subprocess.Popen([sys.executable, str(SCRIPT), "trapterm"], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        ready = pathlib.Path(env["CHILD_READY_FILE"])
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists(), "fake solver did not install TERM handler")
        os.kill(wrapper.pid, signal.SIGTERM)
        self.assertEqual(wrapper.wait(timeout=5), -signal.SIGTERM)
        if wrapper.stderr:
            wrapper.stderr.close()
        self.assertEqual(marker.read_text(), "term-forwarded")
        metadata_path = next(self.archive.glob("*.meta.json"))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["wrapper_signal"], signal.SIGTERM)
        self.assertEqual(metadata["child_exit"], 23)
        self.assertEqual(metadata["capture_state"], "COMPLETE")

    def test_missing_or_invalid_real_executable_is_setup_error(self):
        for real_binary in (None, str(self.root / "missing-cbmc")):
            env = os.environ.copy()
            env.pop("D0_REAL_CBMC", None)
            if real_binary is not None:
                env["D0_REAL_CBMC"] = real_binary
            env["D0_CAPTURE_DIR"] = str(self.archive)
            result = subprocess.run([sys.executable, str(SCRIPT), "success"], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 127)
            self.assertIn(b"D0_REAL_CBMC", result.stderr)


if __name__ == "__main__":
    unittest.main()
