"""Dependency manifests -> OSV batch lookups, counting only advisories published by the snapshot date
and only CVEs in the fixed set frozen to rules/cves.json (see select_cves).

Replaces pip-audit / npm audit: one OSV querybatch call covers up to 1000 packages, needs
no Node install, and gives each advisory's `published` date. Without that date filter, old
repos would pick up every CVE disclosed since they were written.
"""
import json
import os
import re
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from .config import CVE_SEED_PACKAGES, EXCLUDE_DIRS
from .infra import retry

OSV_BATCH = 'https://api.osv.dev/v1/querybatch'
OSV_VULN = 'https://api.osv.dev/v1/vulns/{}'
OSV_QUERY = 'https://api.osv.dev/v1/query'
MAX_PACKAGES = 2000

_REQ = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)(\[[^\]]*\])?\s*===?\s*([A-Za-z0-9_.!+\-]+)')
_SEMVER = re.compile(r'^[\s^~>=v]*(\d+)(\.\d+)?(\.\d+)?([\w.+\-]*)$')


def _pypi(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def _npm_version(spec: str):
    m = _SEMVER.match(spec or '')
    if not m:
        return None  # urls, tags, '*', 'latest', ranges with '||' ...
    return f"{m.group(1)}{m.group(2) or '.0'}{m.group(3) or '.0'}{m.group(4)}"


def _parse_requirements(p: Path):
    for line in p.read_text('utf-8', 'replace').splitlines():
        m = _REQ.match(line.split('#', 1)[0])
        if m:
            yield 'PyPI', _pypi(m.group(1)), m.group(3)


def _parse_pyproject(p: Path):
    data = tomllib.loads(p.read_text('utf-8', 'replace'))
    for spec in data.get('project', {}).get('dependencies', []) or []:
        m = _REQ.match(spec)
        if m:
            yield 'PyPI', _pypi(m.group(1)), m.group(3)
    for name, spec in (data.get('tool', {}).get('poetry', {}).get('dependencies', {}) or {}).items():
        if isinstance(spec, str) and re.fullmatch(r'=?=?\d[\w.]*', spec):
            yield 'PyPI', _pypi(name), spec.lstrip('=')


def _parse_poetry_lock(p: Path):
    for pkg in tomllib.loads(p.read_text('utf-8', 'replace')).get('package', []):
        yield 'PyPI', _pypi(pkg['name']), pkg['version']


def _parse_pipfile_lock(p: Path):
    data = json.loads(p.read_text('utf-8', 'replace'))
    for section in ('default', 'develop'):
        for name, info in (data.get(section) or {}).items():
            v = (info or {}).get('version', '')
            if v.startswith('=='):
                yield 'PyPI', _pypi(name), v[2:]


def _parse_package_lock(p: Path):
    data = json.loads(p.read_text('utf-8', 'replace'))
    for key, info in (data.get('packages') or {}).items():  # lockfile v2/v3
        if key and 'version' in (info or {}):
            yield 'npm', key.split('node_modules/')[-1], info['version']
    def walk(deps):  # lockfile v1
        for name, info in (deps or {}).items():
            if 'version' in (info or {}):
                yield 'npm', name, info['version']
            yield from walk(info.get('dependencies'))
    if not data.get('packages'):
        yield from walk(data.get('dependencies'))


def _parse_package_json(p: Path):
    data = json.loads(p.read_text('utf-8', 'replace'))
    for section in ('dependencies', 'devDependencies'):
        for name, spec in (data.get(section) or {}).items():
            v = _npm_version(spec) if isinstance(spec, str) else None
            if v:
                yield 'npm', name, v


PARSERS = {
    'pyproject.toml': _parse_pyproject,
    'poetry.lock': _parse_poetry_lock,
    'Pipfile.lock': _parse_pipfile_lock,
    'package-lock.json': _parse_package_lock,
}


def parse_manifests(root: Path) -> list:
    """[(ecosystem, name, version, relative_manifest_path)], deduplicated."""
    seen, out = set(), []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS and not d.startswith('.')]
        fset = set(filenames)
        for fn in filenames:
            p = Path(dirpath) / fn
            if fn in PARSERS:
                parser = PARSERS[fn]
            elif fn.startswith('requirements') and fn.endswith('.txt'):
                parser = _parse_requirements
            elif fn == 'package.json' and 'package-lock.json' not in fset:
                parser = _parse_package_json  # lower bound of the declared range
            else:
                continue
            try:
                for eco, name, ver in parser(p):
                    key = (eco, name, ver)
                    if ver and key not in seen:
                        seen.add(key)
                        out.append((eco, name, ver, p.relative_to(root).as_posix()))
            except Exception:
                continue  # malformed manifest: ignore
            if len(out) >= MAX_PACKAGES:
                return out
    return out


def _vuln_row(vid: str, v: dict) -> dict:
    fixed = {}
    for aff in v.get('affected', []):
        pkg = aff.get('package', {}).get('name', '')
        for rng in aff.get('ranges', []):
            for ev in rng.get('events', []):
                if 'fixed' in ev:
                    fixed.setdefault(pkg, []).append(ev['fixed'])
    sev = (v.get('database_specific') or {}).get('severity') or \
          next((s.get('score') for s in v.get('severity', [])), '')
    return {'id': vid, 'published': (v.get('published') or '')[:10],
            'aliases': ','.join(a for a in v.get('aliases', []) if a.startswith('CVE-')),
            'severity': str(sev or ''), 'summary': (v.get('summary') or v.get('details') or '')[:300],
            'fixed': json.dumps(fixed)}


_SEV = {'CRITICAL': 2, 'HIGH': 1}


def select_cves(rules_dir: Path, cfg: dict, log) -> Path:
    """Fixed dependency-CVE set -> rules/cves.json.

    For each ecosystem: every OSV advisory of the seed packages (config.CVE_SEED_PACKAGES) that
    has a CVE alias, CRITICAL/HIGH severity and a publication date inside the study period.
    Packages take turns in popularity order, each contributing its most severe CVEs first.
    """
    session = requests.Session()
    first, last = f"{cfg['start'][0]}-{cfg['start'][1]:02d}", f"{cfg['end'][0]}-{cfg['end'][1]:02d}"
    out = []
    for eco, packages in CVE_SEED_PACKAGES.items():
        by_cve = {}
        for rank, pkg in enumerate(packages):
            token = None
            while True:
                q = {'package': {'ecosystem': eco, 'name': pkg}, **({'page_token': token} if token else {})}
                r = session.post(OSV_QUERY, json=q, timeout=cfg['http_timeout'])
                r.raise_for_status()
                data = r.json()
                for v in data.get('vulns', []):
                    row = _vuln_row(v['id'], v)
                    if not (first <= row['published'][:7] <= last):
                        continue
                    for cve in filter(None, row['aliases'].split(',')):
                        e = by_cve.setdefault(cve, {'cve': cve, 'ecosystem': eco, 'package': pkg, 'rank': rank,
                                                    'severity': '', 'published': row['published'], 'osv_ids': []})
                        e['osv_ids'] = sorted(set(e['osv_ids']) | {v['id']})
                        e['published'] = min(e['published'], row['published'])
                        if _SEV.get(row['severity'].upper(), 0) > _SEV.get(e['severity'], 0):
                            e['severity'] = row['severity'].upper()  # PYSEC records often lack it; GHSA has it
                token = data.get('next_page_token')
                if not token:
                    break
        ranked = sorted((e for e in by_cve.values() if e['severity'] in _SEV),
                        key=lambda e: (e['rank'], -_SEV[e['severity']], e['cve']))
        by_pkg = {}
        for e in ranked:
            by_pkg.setdefault(e['rank'], []).append(e)
        chosen = []  # round-robin over packages so a few heavily-reported ones cannot fill the set
        while len(chosen) < cfg['cves_per_ecosystem'] and any(by_pkg.values()):
            for k in sorted(by_pkg):
                if by_pkg[k] and len(chosen) < cfg['cves_per_ecosystem']:
                    chosen.append(by_pkg[k].pop(0))
        log.info(f"{eco}: {len(chosen)} of {len(ranked)} CRITICAL/HIGH CVEs, "
                 f"{len({e['package'] for e in chosen})} packages")
        out += [{k: v for k, v in e.items() if k != 'rank'} for e in chosen]
    dest = rules_dir / 'cves.json'
    dest.write_text(json.dumps(out, indent=1), 'utf-8')
    log.info(f"Saved {len(out)} CVEs -> {dest}")
    return dest


def load_cves(rules_dir: Path) -> tuple:
    """(CVE ids, OSV ids) of the fixed set."""
    p = Path(rules_dir) / 'cves.json'
    if not p.exists():
        raise FileNotFoundError(f"No {p}: run `python run.py rules` first")
    cves = json.loads(p.read_text('utf-8'))
    return {c['cve'] for c in cves}, {i for c in cves for i in c['osv_ids']}


class OSVClient:
    """Cached OSV lookups (package -> vuln ids, vuln id -> published date / aliases / fixes)."""

    def __init__(self, db, cfg, log, shutdown):
        self.db, self.cfg, self.log, self.shutdown = db, cfg, log, shutdown
        self.session = requests.Session()
        self.cves, self.osv_ids = load_cves(cfg['rules_dir'])

    def _post(self, payload):
        r = self.session.post(OSV_BATCH, json=payload, timeout=self.cfg['http_timeout'])
        if r.status_code >= 500 or r.status_code == 429:
            raise RuntimeError(f"OSV server error {r.status_code}")
        r.raise_for_status()
        return r.json()

    def _get_vuln(self, vid):
        r = self.session.get(OSV_VULN.format(vid), timeout=self.cfg['http_timeout'])
        if r.status_code == 404:
            return None
        if r.status_code >= 500 or r.status_code == 429:
            raise RuntimeError(f"OSV server error {r.status_code}")
        r.raise_for_status()
        return r.json()

    def _pkg_vulns(self, keys: list) -> dict:
        cached = self.db.osv_pkg_get(keys)
        missing = [k for k in keys if k not in cached]
        for i in range(0, len(missing), 1000):
            chunk = missing[i:i + 1000]
            payload = {'queries': [{'package': {'ecosystem': e, 'name': n}, 'version': v} for e, n, v in chunk]}
            res = retry(lambda: self._post(payload), what='OSV querybatch', log=self.log,
                        cfg=self.cfg, shutdown=self.shutdown)
            got = {k: [x['id'] for x in (r or {}).get('vulns', [])] for k, r in zip(chunk, res['results'])}
            self.db.osv_pkg_put(got)
            cached.update(got)
        return cached

    def _vuln_details(self, ids: list) -> dict:
        cached = self.db.osv_vuln_get(ids)
        missing = [i for i in ids if i not in cached]
        if not missing:
            return cached
        fetch = lambda vid: retry(lambda: self._get_vuln(vid), what=f'OSV {vid}', log=self.log,
                                  cfg=self.cfg, shutdown=self.shutdown) or {}
        with ThreadPoolExecutor(max_workers=self.cfg['osv_fetch_threads']) as pool:
            fetched = list(pool.map(fetch, missing))
        rows = []
        for vid, v in zip(missing, fetched):
            row = _vuln_row(vid, v)
            rows.append(row)
            cached[vid] = row
        if rows:
            self.db.osv_vuln_put(rows)
        return cached

    def vulns_for(self, packages: list, snapshot_date: str) -> list:
        if not packages:
            return []
        keys = [(e, n, v) for e, n, v, _ in packages]
        by_pkg = self._pkg_vulns(keys)
        # Only advisories in the fixed set need details (the set lists every OSV id of each CVE)
        details = self._vuln_details(sorted({i for ids in by_pkg.values() for i in ids if i in self.osv_ids}))
        out, seen = [], set()
        for e, n, v in keys:
            for vid in by_pkg.get((e, n, v), []):
                if vid not in self.osv_ids:
                    continue  # outside the fixed CVE set
                d = details.get(vid) or {}
                pub = d.get('published') or ''
                if not pub or pub > snapshot_date:
                    continue  # not yet disclosed when this code was written
                cves = [c for c in (d.get('aliases') or '').split(',') if c in self.cves]
                key = (e, n, v, cves[0] if cves else vid)
                if key in seen:
                    continue  # same CVE reported by both PYSEC and GHSA records
                seen.add(key)
                out.append({'package': n, 'version': v, 'vulnerability_id': vid,
                            'severity': d.get('severity', ''), 'description': d.get('summary', ''),
                            'ecosystem': e, 'fix_versions': ','.join(json.loads(d.get('fixed') or '{}').get(n, [])),
                            'published': pub, 'cves': d.get('aliases', '')})
        return out
