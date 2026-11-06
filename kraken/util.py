"""Small, dependency-free helpers used across KRAKEN."""

from __future__ import annotations

import errno
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable, Sequence


class CommandError(RuntimeError):
    """A required system command was missing, timed out, or failed."""


def run(
    cmd: Sequence[str],
    *,
    timeout: float = 20,
    check: bool = False,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command without a shell and return the completed process."""
    argv = [str(part) for part in cmd]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            input=input_text,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"missing executable: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"timed out after {timeout}s: {' '.join(argv)}") from exc
    except OSError as exc:
        raise CommandError(f"cannot run {' '.join(argv)}: {exc}") from exc

    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise CommandError(f"{' '.join(argv)} failed ({proc.returncode}): {detail}")
    return proc


def run_ok(cmd: Sequence[str], **kwargs: object) -> bool:
    try:
        return run(cmd, **kwargs).returncode == 0  # type: ignore[arg-type]
    except CommandError:
        return False


def output_of(cmd: Sequence[str], *, default: str = "", timeout: float = 20) -> str:
    try:
        proc = run(cmd, timeout=timeout)
    except CommandError:
        return default
    return proc.stdout.strip() if proc.returncode == 0 else default


_SYS_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def which(name: str) -> str | None:
    path = os.environ.get("PATH", "")
    search_path = f"{path}:{_SYS_PATH}" if path else _SYS_PATH
    return shutil.which(name, path=search_path)


def rfkill_unblock_wifi() -> None:
    rfkill_bin = which("rfkill")
    if rfkill_bin:
        run_ok([rfkill_bin, "unblock", "wifi"], timeout=5)
    try:
        for state_file in Path("/var/lib/systemd/rfkill").glob("*:wlan"):
            state_file.write_text("0\n", encoding="utf-8")
    except OSError:
        pass
    try:
        for idx_dir in Path("/sys/class/rfkill").glob("rfkill*"):
            typ = (idx_dir / "type").read_text(encoding="utf-8").strip()
            if typ in ("wlan", "wifi"):
                (idx_dir / "state").write_text("1\n", encoding="utf-8")
    except OSError:
        pass


def write_atomic(path: str | Path, text: str, mode: int = 0o644) -> None:
    """Write ``text`` to ``path`` atomically, creating parents as needed."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kraken-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_text(path: str | Path, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def ensure_dir(path: str | Path, mode: int = 0o755) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target, mode)
    except OSError:
        pass
    return target


def now() -> float:
    return time.time()


def human_uptime(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}h"
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def human_bytes(value: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def mac_is_group(mac: str | None) -> bool:
    """True for multicast/broadcast MAC addresses."""
    if not mac:
        return True
    try:
        return bool(int(mac.split(":")[0], 16) & 0x01)
    except (ValueError, IndexError):
        return True


_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")


def is_mac(value: str | None) -> bool:
    return bool(value and _MAC_RE.match(value.lower()))


def is_iface(value: str | None) -> bool:
    return bool(value and _IFACE_RE.match(value))


def normalize_mac(value: str) -> str:
    return value.lower()


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def tail_lines(path: str | Path, lines: int = 200) -> list[str]:
    path = Path(path)
    if lines <= 0:
        return []
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            block = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= lines:
                step = min(block, size)
                size -= step
                handle.seek(size)
                data = handle.read(step) + data
        return data.decode("utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return []


def setup_logging(log_path: str | Path | None = None, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("kraken")
    logger.setLevel(level)
    logger.propagate = False
    if logger.handlers:
        return logger
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)
    if log_path:
        try:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            from logging.handlers import RotatingFileHandler

            file_handler = RotatingFileHandler(
                log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError:
            pass
    return logger


class ManagedProcess:
    """A long-running child process with a log file and graceful stop."""

    def __init__(self, name: str, cmd: Iterable[str], log_path: str | Path, env: dict | None = None):
        self.name = name
        self.cmd = [str(part) for part in cmd]
        self.log_path = Path(log_path)
        self.env = env
        self.proc: subprocess.Popen[bytes] | None = None
        self._log_handle = None
        self.started_at: float | None = None

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self) -> None:
        if self.alive():
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log_path.open("ab", buffering=0)
        self._log_handle.write(
            f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} starting: {' '.join(self.cmd)}\n".encode()
        )
        self.proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.DEVNULL,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=self.env,
        )
        self.started_at = time.time()

    def stop(self, timeout: float = 6) -> None:
        proc = self.proc
        self.proc = None
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                pass
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            except OSError:
                pass
            self._log_handle = None
        self.started_at = None

    def returncode(self) -> int | None:
        return self.proc.poll() if self.proc is not None else None


def kill_stale(pid_file: str | Path) -> None:
    """Terminate a PID recorded in ``pid_file`` if it is still alive."""
    try:
        pid = int(Path(pid_file).read_text().strip())
    except (OSError, ValueError):
        return
    if pid <= 1:
        return
    try:
        os.kill(pid, 15)
        for _ in range(20):
            time.sleep(0.1)
            os.kill(pid, 0)
    except OSError as exc:
        if exc.errno not in (errno.ESRCH, errno.EPERM):
            raise
