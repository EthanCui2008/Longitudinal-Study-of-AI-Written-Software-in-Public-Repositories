"""Pipeline configuration, LLM release events, and AI-marker patterns."""
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Adjustable parameters ──────────────────────────────────────────
CONFIG = {
    # Sampling: repos are bucketed by *creation* month and analysed at
    # created + snapshot_days, so every bucket has the same exposure time.
    # Two strata per (month, language) cell:
    #   random - unscreened equal-probability draw; the time series and prevalence use only these
    #   ai     - candidates from the same search windows, enrolled only if a GraphQL screen finds
    #            AI-tool markers at HEAD (oversamples the rare AI-marked repos for repo-level contrasts)
    'random_per_cell': 15,               # before ai_start
    'random_per_cell_ai_era': 50,        # from ai_start on
    'ai_per_cell': 130,                  # ai stratum target per cell, from ai_start on
    'ai_start': '2023-01',
    'max_total_repos': 20_000,           # hard budget across all cells and strata
    # Human controls must be free of undisclosed AI code: snapshots before this date predate
    # every public AI coding tool (GitHub Copilot technical preview, 2021-06-29).
    'human_cutoff': '2021-06-29',
    'owner_repos_checked': 10,           # owner's most recently pushed repos screened for AI-tool files
    'max_stars': 50,                     # personal / low-star repos
    'max_size_kb': 50_000,               # skip repos > 50 MB before cloning
    'start': (2017, 1),
    'end': (2026, 7),                    # last month whose snapshot date is in the past
    'snapshot_days': 90,
    'languages': ['Python', 'JavaScript'],
    'window_hours': 2,                   # random creation-time window per search query
    'picks_per_window': 4,               # max random-stratum repos taken from one window (spreads the sample)
    'ai_picks_per_window': 10,           # max ai-stratum repos taken from one window
    'screen_page_size': 50,              # search results per window when screening (heavier query)
    'max_windows_per_cell': 240,         # give up on a cell after this many windows (a month has ~360)
    'seed': 42,

    # Workers (None = auto-size from CPU count and free RAM)
    'clone_workers': None,
    'semgrep_procs': None,               # concurrent semgrep processes
    'semgrep_jobs': None,                # -j per semgrep process
    'deps_workers': 4,
    'osv_fetch_threads': 16,             # parallel OSV advisory-detail requests
    'semgrep_batch_size': 16,            # repos per semgrep invocation
    'semgrep_batch_wait': 10,            # seconds to wait while filling a batch
    'semgrep_max_memory_mb': 6000,       # per semgrep process

    # Fixed measurement sets, frozen into rules/ by `run.py rules`
    'rules_per_lang': 50,                # Semgrep rules per language -> rules/core.yml
    'cves_per_ecosystem': 50,            # dependency CVEs per ecosystem -> rules/cves.json

    # Timeouts (seconds)
    'clone_timeout': 300,
    'semgrep_timeout': 1800,             # per batch
    'semgrep_rule_timeout': 30,          # per rule per file
    'http_timeout': 60,

    # Resilience
    'max_retries': 3,                    # retry attempts for transient failures
    'retry_base_delay': 15,              # exponential backoff: 15s, 30s, 60s
    'max_repo_attempts': 3,              # re-queue failed repos on resume up to this many times
    'keepalive_interval': 300,           # GitHub API ping every 5 min
    'snapshot_every': 250,               # DB backup every N finished repos
    'snapshots_keep': 3,

    # Paths
    'results_dir': ROOT / 'results',
    'work_dir': None,                    # None -> /dev/shm/lsaiw on Linux, ./repos otherwise
    'rules_dir': ROOT / 'rules',

    # Dashboard
    'dashboard_host': '127.0.0.1',
    'dashboard_port': 8765,
}

TEST_OVERRIDES = {
    'random_per_cell': 2,
    'random_per_cell_ai_era': 2,
    'ai_per_cell': 2,
    'max_windows_per_cell': 20,
    'start': (2025, 5),
    'end': (2025, 7),
    'results_dir': ROOT / 'results_test',
    'snapshot_every': 10,
    'semgrep_batch_wait': 5,
}


def cell_targets(month: str, cfg: dict) -> dict:
    """Repos wanted per stratum in one (month, language) cell."""
    ai_era = month >= cfg['ai_start']
    return {'random': cfg['random_per_cell_ai_era' if ai_era else 'random_per_cell'],
            'ai': cfg['ai_per_cell'] if ai_era else 0}


def build_config(test: bool = False, **overrides) -> dict:
    cfg = dict(CONFIG)
    if test:
        cfg.update(TEST_OVERRIDES)
    cfg.update({k: v for k, v in overrides.items() if v is not None})
    cfg['results_dir'] = Path(cfg['results_dir'])
    cfg['db_path'] = cfg['results_dir'] / 'pipeline.db'
    cfg['log_file'] = cfg['results_dir'] / 'pipeline.log'
    cfg['snapshot_dir'] = cfg['results_dir'] / 'snapshots'
    if cfg['work_dir'] is None:
        shm = Path('/dev/shm')
        cfg['work_dir'] = shm / 'lsaiw' if sys.platform.startswith('linux') and shm.is_dir() else ROOT / 'repos'
    cfg['work_dir'] = Path(cfg['work_dir'])
    _resolve_workers(cfg)
    return cfg


def _resolve_workers(cfg: dict):
    cores = os.cpu_count() or 4
    try:
        import psutil
        avail_gb = psutil.virtual_memory().available / 2**30
    except Exception:
        avail_gb = 8.0
    if cfg['semgrep_procs'] is None:
        # Two overlapping processes hide semgrep's rule-loading startup cost.
        cfg['semgrep_procs'] = 2 if cores >= 4 and avail_gb >= 8 else 1
    if cfg['semgrep_jobs'] is None:
        # Use every core: clone threads mostly wait on network/git I/O.
        cfg['semgrep_jobs'] = max(1, cores // cfg['semgrep_procs'])
    if cfg['clone_workers'] is None:
        cfg['clone_workers'] = min(12, max(2, cores + cores // 2))


# ── Languages / files ──────────────────────────────────────────────
LANG_EXT = {
    'Python': ('.py',),
    'JavaScript': ('.js', '.jsx', '.mjs', '.cjs'),
}
CODE_EXT = {ext: lang for lang, exts in LANG_EXT.items() for ext in exts}
EXCLUDE_DIRS = {
    'node_modules', 'vendor', 'dist', 'build', '.git', 'bower_components',
    'site-packages', '.venv', 'venv', 'env', '__pycache__', 'third_party', '.next', 'coverage',
}
EXCLUDE_GLOBS = ['*.min.js', '*.bundle.js', '*.map']
MAX_FILE_BYTES = 1_000_000

# Popular packages whose advisories make up the fixed dependency-CVE set (in popularity order).
CVE_SEED_PACKAGES = {
    'PyPI': ['urllib3', 'requests', 'setuptools', 'certifi', 'idna', 'cryptography', 'pyyaml', 'jinja2',
             'werkzeug', 'flask', 'django', 'pillow', 'numpy', 'lxml', 'sqlalchemy', 'aiohttp', 'paramiko',
             'pyjwt', 'tornado', 'twisted', 'gunicorn', 'celery', 'tensorflow', 'scrapy', 'httplib2',
             'pycrypto', 'bleach', 'markdown', 'mistune', 'babel'],
    'npm': ['lodash', 'minimist', 'axios', 'express', 'node-fetch', 'jsonwebtoken', 'ws', 'moment',
            'handlebars', 'marked', 'jquery', 'underscore', 'qs', 'semver', 'tar', 'json5', 'ajv',
            'yargs-parser', 'glob-parent', 'path-parse', 'ua-parser-js', 'shell-quote', 'socket.io',
            'mongoose', 'ejs', 'pug', 'serialize-javascript', 'dot-prop', 'set-value', 'minimatch'],
}

# ── LLM release events (month the tool became broadly available) ──
LLM_EVENTS = [
    ('2022-06', 'GitHub Copilot GA'),
    ('2022-11', 'ChatGPT'),
    ('2023-03', 'GPT-4'),
    ('2025-02', 'Claude Code preview'),
    ('2025-05', 'Codex / Copilot coding agent'),
]


def event_index(month: str) -> int:
    """Number of LLM release events at or before `month` ('YYYY-MM')."""
    return sum(1 for m, _ in LLM_EVENTS if m <= month)


# ── AI-marker patterns ─────────────────────────────────────────────
MARKER_BASENAMES = {
    'claude.md': 'claude',
    'agents.md': 'agents-md',
    'gemini.md': 'gemini',
    '.cursorrules': 'cursor',
    '.windsurfrules': 'windsurf',
    '.clinerules': 'cline',
    'copilot-instructions.md': 'copilot',
    '.aider.conf.yml': 'aider',
}
MARKER_PREFIXES = {
    '.cursor/rules/': 'cursor',
    '.claude/': 'claude',
    '.continue/': 'continue',
    '.github/instructions/': 'copilot',
    '.aider': 'aider',
}
COMMIT_PATTERNS = [
    (re.compile(r'co-authored-by:\s*claude', re.I), 'claude'),
    (re.compile(r'generated with \[?claude code', re.I), 'claude'),
    (re.compile(r'co-authored-by:\s*(github\s*)?copilot', re.I), 'copilot'),
    (re.compile(r'co-authored-by:[^\n]*cursor', re.I), 'cursor'),
    (re.compile(r'co-authored-by:[^\n]*(openai|codex|chatgpt)', re.I), 'openai'),
    (re.compile(r'co-authored-by:[^\n]*devin', re.I), 'devin'),
    (re.compile(r'^aider: ', re.I | re.M), 'aider'),
    (re.compile(r'(generated|written) (by|with|using) (chatgpt|gpt-?4|copilot|claude|gemini|cursor)', re.I), 'llm-text'),
]
# Directories at a repo root that, when present, show an AI coding tool is in use (GraphQL screen)
SCREEN_DIRS = {'.cursor': 'cursor', '.claude': 'claude', '.continue': 'continue', '.windsurf': 'windsurf'}
BOT_AUTHOR = re.compile(
    r'copilot-swe-agent|devin-ai-integration|claude\[bot\]|chatgpt-codex|openai-codex|'
    r'cursoragent|cursor-agent|google-labs-jules', re.I)
