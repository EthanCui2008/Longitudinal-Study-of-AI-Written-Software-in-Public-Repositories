"""Batched Semgrep: one invocation scans many repo snapshots, results are split back per repo.

Semgrep spends several seconds loading and compiling rules on every call, which dominates
the cost for small personal repos. A batch pays that once. If a batch fails, each repo is
re-run on its own (with retries), so one bad repo cannot sink the batch.
"""
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from .config import CODE_EXT, EXCLUDE_DIRS, EXCLUDE_GLOBS
from .infra import retry

RULE_PACKS = ['p/security-audit', 'p/owasp-top-ten', 'p/cwe-top-25']
# Prefer the semgrep next to this interpreter (works without activating the venv)
_local = Path(sys.executable).parent / ('semgrep.exe' if os.name == 'nt' else 'semgrep')
SEMGREP = str(_local) if _local.exists() else (shutil.which('semgrep') or 'semgrep')
SEMGREP_ENV = {**os.environ, 'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8', 'SEMGREP_SEND_METRICS': 'off'}


def fetch_rules(rules_dir: Path, log) -> list:
    """Freeze the full rule packs to rules/packs/; select_rules() picks the scanned subset from them."""
    packs_dir = rules_dir / 'packs'
    packs_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for pack in RULE_PACKS:
        dest = packs_dir / (pack.split('/')[-1] + '.yml')
        req = urllib.request.Request(f'https://semgrep.dev/c/{pack}', headers={'User-Agent': 'lsaiw-research'})
        with urllib.request.urlopen(req, timeout=120) as r:
            dest.write_bytes(r.read())
        log.info(f"Saved {pack} -> {dest}")
        out.append(dest)
    return out


_RANK = {'ERROR': 3, 'WARNING': 2, 'INFO': 1, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}


def _cwes(rule: dict) -> list:
    cwe = (rule.get('metadata') or {}).get('cwe') or []
    return [c.split(':')[0].strip() for c in (cwe if isinstance(cwe, list) else [cwe])]


def select_rules(rules_dir: Path, per_lang: int, log) -> Path:
    """Fixed subset of the frozen packs -> rules/core.yml, the only file SemgrepRunner loads.

    Per language: rank rules by generality (language-level before framework-specific), then
    severity, likelihood, confidence and id, and take them
    round-robin across CWEs so near-duplicate rules for one CWE cannot fill the quota.
    """
    from ruamel.yaml import YAML  # ships with semgrep
    yaml = YAML(typ='safe')
    rules = {}
    for f in sorted((rules_dir / 'packs').glob('*.yml')):
        for r in yaml.load(f.read_text('utf-8'))['rules']:
            rules.setdefault(r['id'], r)
    pools = {'python': {'python'}, 'javascript': {'javascript', 'js'}}
    meta = lambda r, k: (r.get('metadata') or {}).get(k)
    picked, taken = [], set()
    for lang, names in pools.items():
        pool = [r for r in rules.values() if names & set(r.get('languages', [])) and _cwes(r) and r['id'] not in taken]
        # Language-level rules (python.lang.*, javascript.lang.*) apply to any repo; framework
        # rules (flask, express, ...) only to repos using that framework, so they rank second.
        pool.sort(key=lambda r: ('.lang.' not in r['id'], -_RANK.get(r.get('severity'), 0),
                                 -_RANK.get(meta(r, 'likelihood'), 0),
                                 -_RANK.get(meta(r, 'confidence'), 0), r['id']))
        by_cwe = {}
        for r in pool:
            by_cwe.setdefault(_cwes(r)[0], []).append(r)
        # CWEs with the best top rule go first in each round
        order = sorted(by_cwe, key=lambda c: pool.index(by_cwe[c][0]))
        chosen = []
        while len(chosen) < per_lang and any(by_cwe.values()):
            for c in order:
                if by_cwe[c] and len(chosen) < per_lang:
                    chosen.append(by_cwe[c].pop(0))
        taken.update(r['id'] for r in chosen)
        picked += chosen
        log.info(f"{lang}: {len(chosen)} of {len(pool)} rules across {len({_cwes(r)[0] for r in chosen})} CWEs")
    dest = rules_dir / 'core.yml'
    with dest.open('w', encoding='utf-8') as fh:
        YAML().dump({'rules': picked}, fh)
    log.info(f"Saved {len(picked)} rules -> {dest}")
    return dest


def semgrep_version() -> str:
    r = subprocess.run([SEMGREP, '--version'], capture_output=True, timeout=120, env=SEMGREP_ENV)
    return r.stdout.decode('utf-8', 'replace').strip()


class SemgrepRunner:
    FINDING_KEYS = ['rule_id', 'severity', 'message', 'file', 'line_start', 'line_end',
                    'cwe', 'owasp', 'cve', 'confidence', 'category']

    def __init__(self, cfg, log, shutdown):
        self.cfg, self.log, self.shutdown = cfg, log, shutdown
        self.rule_files = sorted(Path(cfg['rules_dir']).glob('*.yml'))
        if not self.rule_files:
            raise FileNotFoundError(f"No rules/core.yml in {cfg['rules_dir']}: run `python run.py rules` first")

    def _cmd(self, targets: list) -> list:
        cmd = [SEMGREP, 'scan', '--json', '--metrics=off', '--disable-version-check', '--quiet',
               '-j', str(self.cfg['semgrep_jobs']), '--timeout', str(self.cfg['semgrep_rule_timeout']),
               '--max-target-bytes', '1000000', '--max-memory', str(self.cfg['semgrep_max_memory_mb'])]
        for f in self.rule_files:
            cmd += ['--config', f.as_posix()]
        # No --include: it matches nothing on Windows. Target-language filtering happens in _counted().
        for pat in sorted(EXCLUDE_DIRS) + EXCLUDE_GLOBS:
            cmd += ['--exclude', pat]
        return cmd + [Path(t).resolve().as_posix() for t in targets]

    def _invoke(self, targets: list) -> dict:
        r = subprocess.run(self._cmd(targets), capture_output=True, env=SEMGREP_ENV,
                           timeout=self.cfg['semgrep_timeout'])
        stdout = r.stdout.decode('utf-8', 'replace')
        try:
            data = json.loads(stdout) if stdout else None
        except json.JSONDecodeError as e:
            data = None
            stdout = f"bad JSON: {e}"
        if not isinstance(data, dict) or 'results' not in data:
            stderr = r.stderr.decode('utf-8', 'replace')[-300:]
            raise RuntimeError(f"semgrep rc={r.returncode}: {stdout[:200] or stderr}")
        return data

    @staticmethod
    def _owner(path: str, roots: dict):
        p = Path(path).resolve().as_posix()
        key = p.lower() if os.name == 'nt' else p
        for root, name in roots.items():
            if key == root or key.startswith(root + '/'):
                return name, p[len(root) + 1:]
        return None, p

    @staticmethod
    def _counted(rel: str) -> bool:
        """Same file rules as count_loc(), so the findings numerator matches the LOC denominator."""
        parts = rel.split('/')
        name = parts[-1]
        return (os.path.splitext(name)[1].lower() in CODE_EXT and '.min.' not in name
                and not any(p in EXCLUDE_DIRS for p in parts[:-1]))

    @staticmethod
    def _finding(hit: dict, rel: str) -> dict:
        extra = hit.get('extra', {})
        meta = extra.get('metadata', {}) or {}
        join = lambda v: ','.join(map(str, v)) if isinstance(v, list) else str(v or '')
        return {
            'rule_id': hit.get('check_id', ''),
            'severity': extra.get('severity', ''),
            'message': (extra.get('message') or '').replace('\n', ' ').replace('\r', '')[:300],
            'file': rel,
            'line_start': hit.get('start', {}).get('line', 0),
            'line_end': hit.get('end', {}).get('line', 0),
            'cwe': join(meta.get('cwe', [])),
            'owasp': join(meta.get('owasp', [])),
            'cve': join(meta.get('cve', '')),
            'confidence': str(meta.get('confidence', '')),
            'category': str(meta.get('category', '')),
        }

    def _split(self, data: dict, snaps: list) -> None:
        roots = {}
        for s in snaps:
            root = Path(s['path']).resolve().as_posix()
            roots[root.lower() if os.name == 'nt' else root] = s['full_name']
        by_name = {s['full_name']: s for s in snaps}
        seen = set()  # the packs overlap: same rule id on the same line counts once
        for hit in data.get('results', []):
            name, rel = self._owner(hit.get('path', ''), roots)
            if name is None or not self._counted(rel):
                continue
            f = self._finding(hit, rel)
            key = (name, f['rule_id'].rsplit('.', 1)[-1], rel, f['line_start'], hit.get('start', {}).get('col'))
            if key in seen:
                continue
            seen.add(key)
            by_name[name]['findings'].append(f)
        for err in data.get('errors', []):
            name, _ = self._owner(err.get('path', '') or '', roots)
            if name:
                msg = err.get('message') or err.get('long_msg') or err.get('type') or str(err)
                by_name[name]['errors'].append(('semgrep-error', str(msg)[:300]))

    def scan(self, snaps: list) -> list:
        """Fills snap['findings'] / ['errors'] in place; returns the snaps whose scan failed."""
        try:
            data = self._invoke([s['path'] for s in snaps])
            self._split(data, snaps)
            return []
        except Exception as e:
            if len(snaps) == 1:
                raise
            self.log.warn(f"semgrep batch of {len(snaps)} failed ({str(e)[:150]}); falling back to per-repo scans")
        failed = []
        for s in snaps:
            if self.shutdown.shutdown_requested:
                failed.append(s)
                continue
            try:
                data = retry(lambda: self._invoke([s['path']]), what=f"[{s['full_name']}] semgrep",
                             log=self.log, cfg=self.cfg, shutdown=self.shutdown)
                self._split(data, [s])
            except Exception as e:
                s['errors'].append(('semgrep', str(e)[:300]))
                failed.append(s)
        return failed
