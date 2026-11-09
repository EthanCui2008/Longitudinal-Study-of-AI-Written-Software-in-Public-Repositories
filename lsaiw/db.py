"""SQLite store (WAL): one transaction per repo, resumable status, backups, CSV export."""
import calendar
import csv
import json
import shutil
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS repos(
    full_name TEXT PRIMARY KEY, language TEXT, month TEXT, stratum TEXT, stars INT, forks INT, size_kb INT,
    created_at TEXT, pushed_at TEXT, clone_url TEXT, description TEXT,
    screen_ai_types TEXT, owner_ai INT, owner_ai_types TEXT,
    status TEXT DEFAULT 'pending', attempts INT DEFAULT 0, reason TEXT,
    snapshot_date TEXT, sha TEXT, commit_count INT, loc INT, code_files INT,
    ai_marker INT, ai_marker_types TEXT, ai_commit_count INT, ai_commit_share REAL,
    later_ai INT, later_ai_types TEXT,
    n_findings INT, n_high INT, n_packages INT, n_deps INT, deps_ok INT,
    scanned_at TEXT, scan_seconds REAL);
CREATE INDEX IF NOT EXISTS repos_status ON repos(status);
CREATE INDEX IF NOT EXISTS repos_month ON repos(month);
CREATE TABLE IF NOT EXISTS cells(
    month TEXT, language TEXT, stratum TEXT, target INT, collected INT, status TEXT,
    PRIMARY KEY(month, language, stratum));
CREATE TABLE IF NOT EXISTS screens(
    month TEXT, language TEXT, window TEXT, candidates INT, with_ai INT,
    PRIMARY KEY(month, language, window));
CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY, repo_name TEXT, rule_id TEXT, severity TEXT, message TEXT, file TEXT,
    line_start INT, line_end INT, cwe TEXT, owasp TEXT, cve TEXT, confidence TEXT, category TEXT);
CREATE INDEX IF NOT EXISTS findings_repo ON findings(repo_name);
CREATE TABLE IF NOT EXISTS deps(
    id INTEGER PRIMARY KEY, repo_name TEXT, package TEXT, version TEXT, vulnerability_id TEXT,
    severity TEXT, description TEXT, ecosystem TEXT, fix_versions TEXT, published TEXT, cves TEXT);
CREATE INDEX IF NOT EXISTS deps_repo ON deps(repo_name);
CREATE TABLE IF NOT EXISTS errors(
    id INTEGER PRIMARY KEY, repo_name TEXT, stage TEXT, error TEXT, at TEXT);
CREATE INDEX IF NOT EXISTS errors_stage ON errors(stage);
CREATE TABLE IF NOT EXISTS osv_pkg(
    ecosystem TEXT, name TEXT, version TEXT, vuln_ids TEXT, PRIMARY KEY(ecosystem, name, version));
CREATE TABLE IF NOT EXISTS osv_vuln(
    id TEXT PRIMARY KEY, published TEXT, aliases TEXT, severity TEXT, summary TEXT, fixed TEXT);
CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT);
"""

REPO_COLS = ['full_name', 'language', 'month', 'stratum', 'stars', 'forks', 'size_kb',
             'created_at', 'pushed_at', 'clone_url', 'description',
             'screen_ai_types', 'owner_ai', 'owner_ai_types']

# Column layouts kept identical to the original pipeline's CSVs
FINDING_FIELDS = [
    'repo_name', 'language', 'stars', 'interval_start', 'interval_end',
    'rule_id', 'severity', 'message', 'file', 'line_start', 'line_end',
    'cwe', 'owasp', 'cve', 'confidence', 'category',
]
DEP_FIELDS = [
    'repo_name', 'language', 'stars', 'interval_start', 'interval_end',
    'package', 'version', 'vulnerability_id', 'severity',
    'description', 'ecosystem', 'fix_versions',
]


def _clean(v):
    """Strip newlines/carriage returns that break CSV parsing."""
    return v.replace('\n', ' ').replace('\r', '') if isinstance(v, str) else v


def connect(path: Path, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True,
                               check_same_thread=False, timeout=30)
    else:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30, isolation_level=None)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA busy_timeout=30000')
    conn.row_factory = sqlite3.Row
    return conn


class DB:
    """Thread-safe wrapper: a single write connection guarded by a lock."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = connect(path)
        self.lock = threading.RLock()
        cols = {r[1] for r in self.conn.execute('PRAGMA table_info(repos)')}
        if cols and 'stratum' not in cols:
            raise RuntimeError(f"{path} was created by an older pipeline version (no strata); "
                               "move it aside and start a new run")
        self.conn.executescript(SCHEMA)

    def _tx(self, fn):
        with self.lock:
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                out = fn(self.conn)
                self.conn.execute('COMMIT')
                return out
            except BaseException:
                self.conn.execute('ROLLBACK')
                raise

    def query(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    # -- state ------------------------------------------------------------
    def set_state(self, key, value):
        with self.lock:
            self.conn.execute('INSERT OR REPLACE INTO state VALUES(?,?)', (key, json.dumps(value)))

    def get_state(self, key, default=None):
        rows = self.query('SELECT value FROM state WHERE key=?', (key,))
        return json.loads(rows[0][0]) if rows else default

    # -- collection -------------------------------------------------------
    def insert_repos(self, repos: list) -> list:
        """Insert new repos as pending; returns those that were actually new."""
        def fn(c):
            new = []
            for r in repos:
                cur = c.execute(f"INSERT OR IGNORE INTO repos({','.join(REPO_COLS)}) "
                                f"VALUES({','.join('?' * len(REPO_COLS))})",
                                [r.get(k) for k in REPO_COLS])
                if cur.rowcount:
                    new.append(r)
            return new
        return self._tx(fn)

    def cell(self, month, language, stratum):
        rows = self.query('SELECT * FROM cells WHERE month=? AND language=? AND stratum=?',
                          (month, language, stratum))
        return dict(rows[0]) if rows else None

    def cell_count(self, month, language, stratum) -> int:
        return self.query('SELECT COUNT(*) FROM repos WHERE month=? AND language=? AND stratum=?',
                          (month, language, stratum))[0][0]

    def total_repos(self) -> int:
        return self.query('SELECT COUNT(*) FROM repos')[0][0]

    def mark_cell(self, month, language, stratum, target, collected, status):
        with self.lock:
            self.conn.execute('INSERT OR REPLACE INTO cells VALUES(?,?,?,?,?,?)',
                              (month, language, stratum, target, collected, status))

    def record_screen(self, month, language, window, candidates, with_ai):
        """Screening tally per search window (idempotent, so a resumed cell is not double-counted)."""
        with self.lock:
            self.conn.execute('INSERT OR REPLACE INTO screens VALUES(?,?,?,?,?)',
                              (month, language, window, candidates, with_ai))

    def resumable_repos(self, max_attempts: int) -> list:
        rows = self.query("SELECT * FROM repos WHERE status='pending' "
                          "OR (status='failed' AND attempts<?) ORDER BY month, language", (max_attempts,))
        return [dict(r) for r in rows]

    # -- results ----------------------------------------------------------
    def mark_repo(self, full_name, status, reason=None, bump_attempt=False):
        with self.lock:
            self.conn.execute(
                'UPDATE repos SET status=?, reason=?, attempts=attempts+? WHERE full_name=?',
                (status, (reason or '')[:300] or None, 1 if bump_attempt else 0, full_name))

    def log_error(self, repo_name, stage, error):
        with self.lock:
            self.conn.execute('INSERT INTO errors(repo_name, stage, error, at) VALUES(?,?,?,?)',
                              (repo_name, stage, _clean(str(error))[:300], datetime.now().isoformat()))

    def save_repo_result(self, rec: dict):
        """Write one fully scanned repo atomically (replacing any partial earlier rows)."""
        name = rec['full_name']

        def fn(c):
            for t in ('findings', 'deps'):
                c.execute(f'DELETE FROM {t} WHERE repo_name=?', (name,))
            c.executemany(
                'INSERT INTO findings(repo_name, rule_id, severity, message, file, line_start, line_end, '
                'cwe, owasp, cve, confidence, category) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                [(name, f['rule_id'], f['severity'], f['message'], f['file'], f['line_start'],
                  f['line_end'], f['cwe'], f['owasp'], f['cve'], f['confidence'], f['category'])
                 for f in rec['findings']])
            c.executemany(
                'INSERT INTO deps(repo_name, package, version, vulnerability_id, severity, description, '
                'ecosystem, fix_versions, published, cves) VALUES(?,?,?,?,?,?,?,?,?,?)',
                [(name, d['package'], d['version'], d['vulnerability_id'], d['severity'],
                  d['description'], d['ecosystem'], d['fix_versions'], d['published'], d['cves'])
                 for d in rec['deps']])
            c.executemany('INSERT INTO errors(repo_name, stage, error, at) VALUES(?,?,?,?)',
                          [(name, s, _clean(str(e))[:300], datetime.now().isoformat())
                           for s, e in rec['errors']])
            n_high = sum(1 for f in rec['findings'] if str(f['severity']).upper() in ('ERROR', 'HIGH', 'CRITICAL'))
            c.execute(
                "UPDATE repos SET status='done', reason=NULL, snapshot_date=?, sha=?, commit_count=?, loc=?, "
                "code_files=?, ai_marker=?, ai_marker_types=?, ai_commit_count=?, ai_commit_share=?, "
                "later_ai=?, later_ai_types=?, n_findings=?, n_high=?, n_packages=?, n_deps=?, deps_ok=?, scanned_at=?, scan_seconds=? "
                "WHERE full_name=?",
                (rec['snapshot_date'], rec['sha'], rec['commit_count'], rec['loc'], rec['code_files'],
                 int(rec['ai_marker']), ','.join(rec['ai_marker_types']), rec['ai_commit_count'],
                 rec['ai_commit_share'], int(bool(rec['later_ai_types'])), ','.join(rec['later_ai_types']),
                 len(rec['findings']), n_high, len(rec['packages']),
                 len(rec['deps']), int(rec['deps_ok']), datetime.now().isoformat(),
                 rec.get('scan_seconds'), name))
        self._tx(fn)

    # -- OSV cache --------------------------------------------------------
    def osv_pkg_get(self, keys: list) -> dict:
        out = {}
        with self.lock:
            for k in keys:
                row = self.conn.execute('SELECT vuln_ids FROM osv_pkg WHERE ecosystem=? AND name=? AND version=?',
                                        k).fetchone()
                if row:
                    out[k] = json.loads(row[0])
        return out

    def osv_pkg_put(self, items: dict):
        self._tx(lambda c: c.executemany('INSERT OR REPLACE INTO osv_pkg VALUES(?,?,?,?)',
                                         [(*k, json.dumps(v)) for k, v in items.items()]))

    def osv_vuln_get(self, ids: list) -> dict:
        out = {}
        with self.lock:
            for i in ids:
                row = self.conn.execute('SELECT * FROM osv_vuln WHERE id=?', (i,)).fetchone()
                if row:
                    out[i] = dict(row)
        return out

    def osv_vuln_put(self, rows: list):
        self._tx(lambda c: c.executemany(
            'INSERT OR REPLACE INTO osv_vuln VALUES(:id,:published,:aliases,:severity,:summary,:fixed)', rows))

    # -- backups / integrity ---------------------------------------------
    def backup(self, snapshot_dir: Path, keep: int = 3) -> Path:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        dest = snapshot_dir / f"pipeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        out = sqlite3.connect(str(dest))
        with self.lock:
            self.conn.backup(out)
        out.close()
        for old in sorted(snapshot_dir.glob('pipeline_*.db'), reverse=True)[keep:]:
            old.unlink(missing_ok=True)
        return dest

    def close(self):
        with self.lock:
            self.conn.close()


def ensure_healthy(db_path: Path, snapshot_dir: Path, log) -> None:
    """PRAGMA integrity_check on startup; on failure move the DB aside and restore the newest snapshot."""
    if not db_path.exists():
        return
    try:
        conn = sqlite3.connect(str(db_path))
        ok = conn.execute('PRAGMA integrity_check').fetchone()[0]
        conn.close()
    except sqlite3.DatabaseError as e:
        ok = str(e)
    if ok == 'ok':
        log.info(f"DB integrity OK: {db_path.name}")
        return
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    log.warn(f"DB integrity check failed ({ok}); moving aside as .corrupted.{ts}")
    for suffix in ('', '-wal', '-shm'):
        p = Path(str(db_path) + suffix)
        if p.exists():
            shutil.move(str(p), str(p) + f'.corrupted.{ts}')
    snaps = sorted(snapshot_dir.glob('pipeline_*.db'), reverse=True)
    if snaps:
        shutil.copy2(snaps[0], db_path)
        log.warn(f"Restored {snaps[0].name}; repos after that snapshot will be re-scanned.")


def _month_bounds(month: str):
    y, m = map(int, month.split('-'))
    return f"{month}-01", f"{month}-{calendar.monthrange(y, m)[1]:02d}"


def export_csvs(db_path: Path, out_dir: Path) -> dict:
    """Write the original CSV layouts (+ repositories.csv) from the DB; only status='done' repos."""
    out_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path, readonly=True)
    repos = {r['full_name']: dict(r) for r in conn.execute("SELECT * FROM repos")}
    counts = {}

    def meta(name):
        r = repos[name]
        s, e = _month_bounds(r['month'])
        return {'repo_name': name, 'language': r['language'], 'stars': r['stars'],
                'interval_start': s, 'interval_end': e}

    done = "SELECT {} FROM {} t JOIN repos r ON r.full_name=t.repo_name WHERE r.status='done'"
    for fname, table, fields in (('semgrep_findings.csv', 'findings', FINDING_FIELDS),
                                 ('deprecated_dependencies.csv', 'deps', DEP_FIELDS)):
        own = [f for f in fields if f not in ('repo_name', 'language', 'stars', 'interval_start', 'interval_end')]
        with open(out_dir / fname, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            n = 0
            for row in conn.execute(done.format(', '.join(['t.repo_name'] + [f't.{c}' for c in own]), table)):
                w.writerow({**meta(row['repo_name']), **{c: _clean(row[c]) for c in own}})
                n += 1
        counts[fname] = n

    with open(out_dir / 'scan_errors.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['repo_name', 'stage', 'error'])
        rows = conn.execute('SELECT repo_name, stage, error FROM errors').fetchall()
        w.writerows([[_clean(c) for c in r] for r in rows])
        counts['scan_errors.csv'] = len(rows)

    with open(out_dir / 'repositories.csv', 'w', newline='', encoding='utf-8') as f:
        cols = list(next(iter(repos.values())).keys()) if repos else ['full_name']
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in repos.values():
            w.writerow({k: _clean(v) for k, v in r.items()})
        counts['repositories.csv'] = len(repos)
    conn.close()
    return counts
