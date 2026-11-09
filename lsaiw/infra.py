"""Logging, keep-alive, graceful shutdown, error classification and retry helpers."""
import atexit
import logging
import os
import shutil
import signal
import stat
import threading
from collections import deque
from datetime import datetime
from pathlib import Path


class ShutdownRequested(Exception):
    """Raised inside a retry wait when a shutdown was requested."""


class SkipRepo(Exception):
    """Permanent, expected reason to drop a repo (no commits before snapshot, no code, ...)."""


class PipelineLogger:
    """Dual-output logger: a file (tail -f friendly) and the console, plus a ring buffer for the dashboard."""

    def __init__(self, log_path: Path, tail: int = 30):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger('pipeline')
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()

        # File handler: always append so the log survives restarts
        fh = logging.FileHandler(str(log_path), encoding='utf-8')
        fh.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s | %(message)s',
                                          datefmt='%Y-%m-%d %H:%M:%S'))
        self._logger.addHandler(fh)
        self.tail = deque(maxlen=tail)
        self._lock = threading.Lock()

    def _emit(self, level_fn, level: str, msg: str):
        level_fn(msg)
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {level} {msg}"
        with self._lock:
            self.tail.append(line)
            try:
                print(line, flush=True)
            except Exception:
                pass

    def info(self, msg):
        self._emit(self._logger.info, 'INFO', msg)

    def warn(self, msg):
        self._emit(self._logger.warning, 'WARN', msg)

    def error(self, msg):
        self._emit(self._logger.error, 'ERROR', msg)

    def repo_event(self, repo: str, stage: str, msg: str, duration: float = None):
        self.info(f"[{repo}] {stage} {msg}" + (f" ({duration:.1f}s)" if duration is not None else ''))


class GracefulShutdown:
    """Catches SIGINT/SIGTERM and sets a flag for workers; a second Ctrl+C exits immediately.

    Exiting immediately is safe: every repo is committed to SQLite in one transaction,
    so unfinished repos simply stay 'pending' and are resumed on the next run.
    """

    def __init__(self, logger: PipelineLogger = None):
        self._event = threading.Event()
        self._logger = logger
        self._save_callback = None
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._handle)
            except (OSError, ValueError):
                pass  # not in main thread
        atexit.register(self._on_exit)

    def _handle(self, signum, frame):
        if self._event.is_set():
            if self._logger:
                self._logger.warn("Second interrupt: exiting now (unfinished repos stay pending).")
            os._exit(130)
        self.request(f"signal {signum}")

    def request(self, why: str = 'requested'):
        self._event.set()
        if self._logger:
            self._logger.warn(f"Shutdown {why}: finishing in-flight work, flushing, saving state. "
                              f"Press Ctrl+C again to exit immediately.")
        self._on_exit()

    def _on_exit(self):
        if self._save_callback and self._event.is_set():
            try:
                self._save_callback()
            except Exception:
                pass

    @property
    def shutdown_requested(self) -> bool:
        return self._event.is_set()

    def wait(self, seconds: float) -> bool:
        """Interruptible sleep; returns True if shutdown was requested."""
        return self._event.wait(seconds)

    def set_save_callback(self, fn):
        self._save_callback = fn


class KeepAlive:
    """Background daemon thread that pings an API periodically and records the result."""

    def __init__(self, ping, interval: int, logger: PipelineLogger):
        self._ping = ping
        self._interval = interval
        self._logger = logger
        self._stop_event = threading.Event()
        self._thread = None
        self.last = None

    def _run(self):
        while not self._stop_event.wait(self._interval):
            try:
                self.last = self._ping()
                self._logger.info(f"keepalive: {self.last}")
            except Exception as e:
                self._logger.warn(f"keepalive ping failed: {e}")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name='keepalive')
        self._thread.start()
        atexit.register(self.stop)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)


# ── Transient vs permanent error classification ────────────────────
_TRANSIENT_PATTERNS = [
    'timeout', 'timed out', 'connection reset', 'connection refused',
    'connection abort', 'broken pipe', 'network is unreachable',
    'temporary failure', 'name resolution', 'ssl', 'eof occurred',
    '500', '502', '503', '429', 'rate limit', 'server error', 'early eof',
]
_PERMANENT_PATTERNS = [
    '404', 'not found', '451', 'dmca', 'repository not found',
    'authentication', 'permission denied', 'access denied', '403',
    'bad credentials', 'invalid', 'could not read username', 'terminal prompts disabled',
]


def _is_transient(error_str: str) -> bool:
    """Return True if the error looks transient and worth retrying."""
    lower = error_str.lower()
    for pat in _PERMANENT_PATTERNS:
        if pat in lower:
            return False
    for pat in _TRANSIENT_PATTERNS:
        if pat in lower:
            return True
    # Default: treat unknown errors as transient (retry is safer for a long run)
    return True


def retry(fn, *, what: str, log: PipelineLogger, cfg: dict, shutdown: GracefulShutdown = None):
    """Call fn() with exponential backoff on transient errors (15s, 30s, 60s by default)."""
    max_retries, base = cfg['max_retries'], cfg['retry_base_delay']
    for attempt in range(1, max_retries + 1):
        try:
            return fn()
        except (SkipRepo, ShutdownRequested):
            raise
        except Exception as e:
            msg = str(e) or type(e).__name__
            if not _is_transient(msg) or attempt == max_retries:
                raise
            delay = base * 2 ** (attempt - 1)
            log.warn(f"{what} RETRY {attempt}/{max_retries}: {msg[:200]} (waiting {delay}s)")
            if shutdown and shutdown.wait(delay):
                raise ShutdownRequested()


def rmtree_force(path: Path):
    """rmtree that also removes read-only files (git objects on Windows)."""
    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    if Path(path).exists():
        shutil.rmtree(path, onerror=_onerror)


def load_tokens(root: Path) -> list:
    """GitHub tokens from env or keys.env: GITHUB_TOKENS=a,b or GITHUB_TOKEN=a."""
    try:
        from dotenv import load_dotenv
        load_dotenv(root / 'keys.env')
    except ImportError:
        pass
    raw = os.getenv('GITHUB_TOKENS') or os.getenv('GITHUB_TOKEN') or ''
    tokens = [t.strip() for t in raw.split(',') if t.strip()]
    if not tokens:
        raise ValueError("GitHub token not found!\n"
                         "  create keys.env with GITHUB_TOKEN=ghp_...  (or GITHUB_TOKENS=tok1,tok2 to rotate)")
    return tokens
