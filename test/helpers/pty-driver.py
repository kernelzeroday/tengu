#!/usr/bin/env python3
"""
Minimal real-PTY driver for Tengu TUI smoke tests.
Reads a JSON spec from stdin:
{
  "argv": ["node", "..."],
  "env": { ... },
  "cols": 120,
  "rows": 35,
  "timeout": 12,
  "steps": [
    {"op": "wait_for", "text": "Tengu", "timeout": 5},
    {"op": "send", "data": "/help\r"},
    {"op": "resize", "cols": 70, "rows": 20},
    {"op": "sleep", "ms": 150}
  ]
}
Prints JSON result to stdout: { "exitCode": int|None, "output": str, "timedOut": bool, "stepErrors": [...] }
"""
import fcntl
import json
import os
import pty
import select
import signal
import struct
import sys
import termios
import time


def set_winsize(fd: int, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def drain_fd(fd: int, buf: bytearray, wait_sec: float = 0.05) -> None:
    end = time.monotonic() + wait_sec
    while True:
        rem = end - time.monotonic()
        if rem <= 0:
            break
        r, _, _ = select.select([fd], [], [], min(rem, 0.05))
        if not r:
            break
        try:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            buf.extend(chunk)
        except OSError:
            break


def main() -> None:
    spec = json.loads(sys.stdin.read())
    argv = spec["argv"]
    cols = int(spec.get("cols", 120))
    rows = int(spec.get("rows", 35))
    total_timeout = float(spec.get("timeout", 15))
    env = os.environ.copy()
    env.update(spec.get("env", {}))
    env.setdefault("TERM", "xterm-256color")

    pid, master_fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env)

    set_winsize(master_fd, rows, cols)
    output = bytearray()
    step_errors = []
    start_time = time.monotonic()

    try:
        for idx, step in enumerate(spec.get("steps", [])):
            op = step["op"]
            if op == "sleep":
                drain_fd(master_fd, output, float(step.get("ms", 100)) / 1000.0)
            elif op == "send":
                data = step["data"].encode("utf-8")
                os.write(master_fd, data)
                drain_fd(master_fd, output, float(step.get("afterMs", 80)) / 1000.0)
            elif op == "resize":
                new_cols = int(step["cols"])
                new_rows = int(step["rows"])
                set_winsize(master_fd, new_rows, new_cols)
                try:
                    os.kill(pid, signal.SIGWINCH)
                except ProcessLookupError:
                    pass
                drain_fd(master_fd, output, float(step.get("afterMs", 120)) / 1000.0)
            elif op == "wait_for":
                needle = step["text"].encode("utf-8")
                step_timeout = float(step.get("timeout", 5))
                deadline = time.monotonic() + step_timeout
                found = False
                while time.monotonic() < deadline:
                    if needle in output:
                        found = True
                        break
                    drain_fd(master_fd, output, 0.05)
                if not found:
                    step_errors.append(f"step {idx}: wait_for {step['text']!r} timed out")

        # Wait for process to exit cleanly up to remaining timeout
        exit_code = None
        timed_out = False
        while time.monotonic() - start_time < total_timeout:
            drain_fd(master_fd, output, 0.05)
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    exit_code = -os.WTERMSIG(status)
                break
        else:
            timed_out = True
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    print(
        json.dumps(
            {
                "exitCode": exit_code,
                "output": output.decode("utf-8", errors="replace"),
                "timedOut": timed_out,
                "stepErrors": step_errors,
            }
        )
    )


if __name__ == "__main__":
    main()
