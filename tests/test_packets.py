"""Compare the native executable's localhost UDP packets with the Python source."""

import ast
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get("JIYU_TEST_EXE", ROOT / "x64" / "Release" / "JiYuUdpTool.exe"))
SOURCE = ROOT / "py" / "Jiyu_udp_attack.py"


def templates():
    module = ast.parse(SOURCE.read_text(encoding="utf-8"))
    assignment = next(
        node for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "store"
                for target in node.targets)
    )
    return [bytearray(packet) for packet in ast.literal_eval(assignment.value)]


def expected(index, value=""):
    packet = templates()[index]
    if value:
        offset = 56 if index == 0 else 578
        encoded = value.encode("utf-16-le")
        packet[offset:offset + len(encoded)] = encoded
    return bytes(packet)


def expected_run(program, arguments=""):
    packet = templates()[1]
    packet[60:892] = b"\0" * (892 - 60)
    for offset, value in ((60, program), (572, arguments)):
        encoded = value.encode("utf-16-le")
        packet[offset:offset + len(encoded)] = encoded
    return bytes(packet)


class PacketTests(unittest.TestCase):
    def run_tool(self, *arguments, packets=1):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(3)
            port = listener.getsockname()[1]
            result = subprocess.run(
                [str(EXE), "-ip", "127.0.0.1", "-p", str(port), *arguments],
                capture_output=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            return [listener.recvfrom(2048)[0] for _ in range(packets)]

    def test_message_ascii_and_chinese(self):
        for value in ("hello", "你好", "🙂"):
            with self.subTest(value=value):
                self.assertEqual(self.run_tool("-msg", value), [expected(0, value)])

    def test_command(self):
        for command in ("calc.exe", "taskkill /F /IM notepad.exe",
                        "rundll32.exe user32.dll,LockWorkStation"):
            with self.subTest(command=command):
                packet = self.run_tool("-c", command)[0]
                self.assertEqual(packet, expected(1, command))
                self.assertEqual(packet[60:114].decode("utf-16-le"),
                                 r"C:\Windows\system32\cmd.exe")
                self.assertEqual(packet[572:578].decode("utf-16-le"), "/c ")
                self.assertEqual(packet[578:578 + len(command) * 2].decode("utf-16-le"),
                                 command)

    def test_run_without_cmd_prefix(self):
        for value, program, args in (
            (r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\notepad.exe", ""),
            ('"C:\\Program Files\\Example App\\app.exe" --quiet',
            r"C:\Program Files\Example App\app.exe", "--quiet"),
        ):
            with self.subTest(value=value):
                self.assertEqual(self.run_tool("-run", value), [expected_run(program, args)])

    def test_reboot_and_shutdown(self):
        self.assertEqual(self.run_tool("-e", "r"), [expected(2)])
        self.assertEqual(self.run_tool("-e", "s"), [expected(3)])

    def test_python_reference_command(self):
        command = "taskkill /F /IM notepad.exe"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(3)
            result = subprocess.run(
                [sys.executable, str(SOURCE), "-ip", "127.0.0.1", "-p",
                 str(listener.getsockname()[1]), "-c", command],
                capture_output=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual(listener.recvfrom(2048)[0], expected(1, command))

    def test_combined_packets_and_repeat(self):
        received = self.run_tool("-msg", "hi", "-c", "whoami", "-l", "2", "-t", "0", packets=4)
        self.assertEqual(received, [expected(0, "hi"), expected(1, "whoami")] * 2)

    def test_parallel_range_preserves_per_target_packet_order(self):
        listeners = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3)]
        try:
            listeners[0].bind(("127.0.0.1", 0))
            port = listeners[0].getsockname()[1]
            for index, listener in enumerate(listeners[1:], start=2):
                listener.bind((f"127.0.0.{index}", port))
            for listener in listeners:
                listener.settimeout(3)
            result = subprocess.run(
                [str(EXE), "-ip", "127.0.0.1-3", "-p", str(port),
                 "-j", "3", "-msg", "hello", "-c", "whoami"],
                capture_output=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            for listener in listeners:
                self.assertEqual([listener.recvfrom(2048)[0] for _ in range(2)],
                                 [expected(0, "hello"), expected(1, "whoami")])
        finally:
            for listener in listeners:
                listener.close()

    def test_invalid_input(self):
        for args in (("-msg", "x" * 449), ("-c", "x" * 157),
                     ("-msg", "ok", "-ip", "bad"), ("-p", "65536", "-msg", "ok"),
                     ("-j", "0", "-msg", "ok"), ("-j", "65", "-msg", "ok"),
                     ("-run", '"unterminated'), ("-run", "x" * 256),
                     ("-run", "app.exe " + "x" * 160)):
            with self.subTest(args=args):
                result = subprocess.run([str(EXE), "-ip", "127.0.0.1", *args],
                                        capture_output=True, check=False, timeout=10)
                self.assertNotEqual(result.returncode, 0)

    def test_removed_modes(self):
        for mode in ("nc", "g", "break", "continue"):
            with self.subTest(mode=mode):
                for program in ((str(EXE),), (sys.executable, str(SOURCE))):
                    result = subprocess.run([*program, "-ip", "127.0.0.1", "-e", mode],
                                            capture_output=True, check=False, timeout=10)
                    self.assertNotEqual(result.returncode, 0)

    def test_interactive_state_and_aliases(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(3)
            port = listener.getsockname()[1]
            commands = (f"ip 127.0.0.1\nport {port}\nmsg 你好\nwait\n"
                        "command taskkill /F /IM notepad.exe\nwait\n"
                        "c rundll32.exe user32.dll,LockWorkStation\nwait\n"
                        "r\nwait\nshutdown\nwait\nexit\n")
            result = subprocess.run([str(EXE)], input=commands.encode("utf-8"),
                                    capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual([listener.recvfrom(2048)[0] for _ in range(5)], [
                expected(0, "你好"), expected(1, "taskkill /F /IM notepad.exe"),
                expected(1, "rundll32.exe user32.dll,LockWorkStation"),
                expected(2), expected(3),
            ])
            self.assertIn("Target: 127.0.0.1", result.stdout.decode("utf-8"))

    def test_interactive_validation_and_range(self):
        commands = "msg before target\nip 127.0.0.1-2  \nstatus\nip bad\nstatus\nexit\n"
        result = subprocess.run([str(EXE)], input=commands.encode("utf-8"),
                                capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0)
        output = result.stdout.decode("utf-8")
        self.assertIn("Target: 127.0.0.1-2 (2 address(es))", output)
        self.assertEqual(output.count("Target: 127.0.0.1-2"), 3)
        self.assertIn("Select a target first", result.stderr.decode("utf-8"))
        self.assertIn("Invalid IPv4 address", result.stderr.decode("utf-8"))

    def test_interactive_prompts_for_missing_text(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(3)
            commands = (f"ip 127.0.0.1\nport {listener.getsockname()[1]}\n"
                        "msg\nhello from prompt\nwait\nc\nwhoami\nwait\nexit\n")
            result = subprocess.run([str(EXE)], input=commands.encode("utf-8"),
                                    capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual([listener.recvfrom(2048)[0] for _ in range(2)],
                             [expected(0, "hello from prompt"), expected(1, "whoami")])
            output = result.stdout.decode("utf-8")
            self.assertIn("Message: ", output)
            self.assertIn("Command: ", output)

    def test_interactive_run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(3)
            commands = (f"ip 127.0.0.1\nport {listener.getsockname()[1]}\n"
                        'run "C:\\Program Files\\Example App\\app.exe" --quiet\nwait\nexit\n')
            result = subprocess.run([str(EXE)], input=commands.encode("utf-8"),
                                    capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual(listener.recvfrom(2048)[0],
                             expected_run(r"C:\Program Files\Example App\app.exe", "--quiet"))

    def test_interactive_old_prefix_still_works(self):
        result = subprocess.run([str(EXE)], input=b"/ip 127.0.0.1-2\n/status\n/exit\n",
                                capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertIn("Target: 127.0.0.1-2", result.stdout.decode("utf-8"))

    def test_interactive_scan_explicit_and_selected(self):
        commands = b"scan 127.0.0.1\nip 127.0.0.1\nscan\nstatus\nexit\n"
        result = subprocess.run([str(EXE)], input=commands,
                                capture_output=True, check=False, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        output = result.stdout.decode("utf-8")
        self.assertEqual(output.count("Scanning 1 address(es) with ICMP echo using 1 worker(s)"), 2)
        self.assertEqual(output.count("Scan complete: 1 checked"), 2)
        self.assertIn("Target: 127.0.0.1, port: 4705", output)

    def test_interactive_scan_requires_range(self):
        result = subprocess.run([str(EXE)], input=b"scan\nscan invalid\nexit\n",
                                capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0)
        errors = result.stderr.decode("utf-8")
        self.assertIn("Enter a range or select one with ip", errors)
        self.assertIn("Invalid IPv4 address", errors)

    def test_interactive_worker_setting(self):
        commands = b"threads 4\nstatus\nthreads 0\nstatus\nthreads 65\nstatus\nexit\n"
        result = subprocess.run([str(EXE)], input=commands,
                                capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0)
        output = result.stdout.decode("utf-8")
        self.assertIn("Workers: 4", output)
        self.assertEqual(output.count("workers: 4"), 3)
        self.assertEqual(result.stderr.decode("utf-8").count("Number outside valid range"), 2)

    def test_three_octet_prefix_shorthand(self):
        commands = b"ip 10.88.128./24\nstatus\nip 10.88./24\nstatus\nexit\n"
        result = subprocess.run([str(EXE)], input=commands,
                                capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0)
        output = result.stdout.decode("utf-8")
        self.assertIn("Target: 10.88.128./24 (254 address(es))", output)
        self.assertIn("Target: 10.88.128./24, port: 4705", output)
        self.assertIn("Invalid IPv4 address", result.stderr.decode("utf-8"))

    def test_ip_scan_selects_responding_target(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(3)
            commands = ("ip scan 127.0.0.1\nwait\nstatus\n"
                        f"port {listener.getsockname()[1]}\nmsg hello\nwait\nexit\n")
            result = subprocess.run([str(EXE)], input=commands.encode("utf-8"),
                                    capture_output=True, check=False, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual(listener.recvfrom(2048)[0], expected(0, "hello"))
            output = result.stdout.decode("utf-8")
            self.assertIn("Selected 1 responding address(es)", output)
            self.assertIn("Target: scan 127.0.0.1, port: 4705, workers: 64, targets: 1", output)

    def test_manual_ip_supersedes_background_selection(self):
        commands = b"ip scan 127.0.0.1-3\nip 127.0.0.1\nwait\nstatus\nexit\n"
        result = subprocess.run([str(EXE)], input=commands,
                                capture_output=True, check=False, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertIn("Target: 127.0.0.1, port: 4705", result.stdout.decode("utf-8"))

    def test_interactive_background_jobs(self):
        commands = b"scan 127.0.0.1-2\nstatus\njobs\nwait 1\njobs\nexit\n"
        result = subprocess.run([str(EXE)], input=commands,
                                capture_output=True, check=False, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        output = result.stdout.decode("utf-8")
        self.assertIn("[job 1] started: scan 127.0.0.1-2", output)
        self.assertIn("[job 1] done: scan 127.0.0.1-2", output)
        self.assertIn("Scan complete: 2 checked", output)
        self.assertIn("Target: (not selected), port: 4705, workers: 64", output)


if __name__ == "__main__":
    if not EXE.exists():
        sys.exit(f"Build Release|x64 first: {EXE}")
    unittest.main()
