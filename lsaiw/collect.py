"""Stratified random sampling of repos by creation month via GitHub GraphQL search.

Each (month, language) cell has a `random` stratum (unscreened draw) and, from `ai_start` on,
an `ai` stratum: candidates from the same search windows that a cheap GraphQL screen (root and
.github files at HEAD, recent commit messages) shows to use an AI coding tool.
"""
import calendar
import json
import random
import threading
import time
from datetime import datetime, timedelta, timezone

import requests

from .config import SCREEN_DIRS, cell_targets
from .infra import ShutdownRequested, retry
from .snapshot import detect_commit_markers, detect_file_markers

GRAPHQL_URL = 'https://api.github.com/graphql'
_FILES = """
      root: object(expression: "HEAD:") { ... on Tree { entries { name type } } }
      gh: object(expression: "HEAD:.github") { ... on Tree { entries { name type } } }"""
_SCREEN = _FILES + """
      defaultBranchRef { target { ... on Commit { history(first: 20) {
        nodes { message author { name email } } } } } }"""
SEARCH_QUERY = """
query($q: String!) {
  rateLimit { remaining resetAt }
  search(query: $q, type: REPOSITORY, first: %d) {
    repositoryCount
    nodes { ... on Repository {
      nameWithOwner url owner { __typename login } primaryLanguage { name }
      stargazerCount forkCount createdAt pushedAt diskUsage isFork isEmpty description%s
    } }
  }
}"""
OWNER_QUERY = """
query {
  rateLimit { remaining resetAt }
%s
}"""
OWNER_PART = """  u%d: user(login: %s) { repositories(first: %d, ownerAffiliations: OWNER, isFork: false,
      orderBy: {field: PUSHED_AT, direction: DESC}) { nodes { nameWithOwner%s } } }"""


def screen_markers(node: dict) -> set:
    """AI-tool markers visible through GraphQL: root and .github entries at HEAD, recent commits."""
    paths, tags = [], set()
    for key, prefix in (('root', ''), ('gh', '.github/')):
        for e in ((node.get(key) or {}).get('entries') or []):
            is_dir = e.get('type') == 'tree'
            paths.append(prefix + e['name'] + ('/' if is_dir else ''))
            if is_dir and not prefix and e['name'].lower() in SCREEN_DIRS:
                tags.add(SCREEN_DIRS[e['name'].lower()])
    tags |= detect_file_markers(paths)
    target = (node.get('defaultBranchRef') or {}).get('target') or {}
    hist = (target.get('history') or {}).get('nodes') or []
    if hist:
        log_text = ''.join(f"{(c.get('author') or {}).get('name', '')} <{(c.get('author') or {}).get('email', '')}>"
                           f"\x1f{c.get('message', '')}\x1e" for c in hist)
        tags |= detect_commit_markers(log_text)[0]
    return tags


class GitHubClient:
    """GraphQL client that rotates tokens and sleeps through primary/secondary rate limits."""

    def __init__(self, tokens: list, cfg: dict, log, shutdown):
        self.tokens = tokens
        self.cfg, self.log, self.shutdown = cfg, log, shutdown
        self._i = 0
        self._reset_at = {}  # token index -> epoch when usable again
        self._lock = threading.Lock()
        self.remaining = None
        self.session = requests.Session()

    def _headers(self, i):
        return {'Authorization': f'bearer {self.tokens[i]}', 'User-Agent': 'lsaiw-research'}

    def _wait_for_token(self):
        while True:
            now = time.time()
            for k in range(len(self.tokens)):
                j = (self._i + k) % len(self.tokens)
                if self._reset_at.get(j, 0) <= now:
                    self._i = j
                    return j
            wait = min(self._reset_at.values()) - now + 5
            self.log.warn(f"All {len(self.tokens)} GitHub token(s) rate-limited; sleeping {wait:.0f}s")
            if self.shutdown.wait(wait):
                raise ShutdownRequested()

    def graphql(self, query: str, variables: dict) -> dict:
        while True:
            with self._lock:
                i = self._wait_for_token()
            r = self.session.post(GRAPHQL_URL, json={'query': query, 'variables': variables},
                                  headers=self._headers(i), timeout=self.cfg['http_timeout'])
            if r.status_code in (403, 429) or 'rate limit' in r.text[:500].lower():
                retry_after = r.headers.get('Retry-After')
                reset = r.headers.get('X-RateLimit-Reset')
                until = time.time() + (int(retry_after) if retry_after else 60)
                if reset and r.headers.get('X-RateLimit-Remaining') == '0':
                    until = int(reset) + 5
                with self._lock:
                    self._reset_at[i] = until
                self.log.warn(f"GitHub rate limit on token #{i + 1}; usable again in {until - time.time():.0f}s")
                continue
            if r.status_code >= 500:
                raise RuntimeError(f"GitHub server error {r.status_code}")
            if r.status_code == 401:
                raise RuntimeError("GitHub bad credentials (401): check keys.env")
            r.raise_for_status()
            data = r.json()
            if data.get('errors') and not data.get('data'):
                raise RuntimeError(f"GraphQL error: {data['errors'][0].get('message')}")
            rl = (data.get('data') or {}).get('rateLimit') or {}
            if 'remaining' in rl:
                self.remaining = rl['remaining']
                if rl['remaining'] < 50:
                    reset = datetime.fromisoformat(rl['resetAt'].replace('Z', '+00:00')).timestamp()
                    with self._lock:
                        self._reset_at[i] = reset + 5
            return data['data']

    def ping(self) -> str:
        r = self.session.get('https://api.github.com/rate_limit', headers=self._headers(self._i),
                             timeout=self.cfg['http_timeout'])
        res = r.json().get('resources', {})
        g = res.get('graphql', {})
        self.remaining = g.get('remaining', self.remaining)
        return f"graphql {g.get('remaining')}/{g.get('limit')}, search {res.get('search', {}).get('remaining')}"


def months(start: tuple, end: tuple) -> list:
    out, (y, m) = [], start
    while (y, m) <= end:
        out.append(f"{y}-{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def _windows(month: str, hours: int) -> list:
    y, m = map(int, month.split('-'))
    start = datetime(y, m, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=calendar.monthrange(y, m)[1])
    out, t = [], start
    while t < end:
        out.append((t, min(t + timedelta(hours=hours), end) - timedelta(seconds=1)))
        t += timedelta(hours=hours)
    return out


def _fmt(t: datetime) -> str:
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


class BudgetReached(Exception):
    pass


class RepoSampler:
    """For each (month, language) cell: query random creation-time windows until both strata are full.

    Random windows (instead of sort-by-stars and take the first page) give an unbiased draw
    of personal repos created that month; taking at most `picks_per_window` per window
    spreads the sample across the month. The ai stratum takes screened-positive candidates
    the random stratum did not pick, so the two never share a repo.
    """

    def __init__(self, gh: GitHubClient, db, cfg: dict, log, shutdown):
        self.gh, self.db, self.cfg, self.log, self.shutdown = gh, db, cfg, log, shutdown
        self.current = None

    def _search(self, lang, t0, t1, screen: bool) -> list:
        q = (f"language:{lang} created:{_fmt(t0)}..{_fmt(t1)} stars:<={self.cfg['max_stars']} "
             f"size:<={self.cfg['max_size_kb']} fork:false is:public")
        query = SEARCH_QUERY % ((self.cfg['screen_page_size'], _SCREEN) if screen else (100, ''))
        data = retry(lambda: self.gh.graphql(query, {'q': q}), what=f"search {lang} {_fmt(t0)}",
                     log=self.log, cfg=self.cfg, shutdown=self.shutdown)
        out = []
        for n in data['search']['nodes']:
            if not n or n.get('isFork') or n.get('isEmpty'):
                continue
            if (n.get('owner') or {}).get('__typename') != 'User':
                continue
            if ((n.get('primaryLanguage') or {}).get('name')) != lang:
                continue
            out.append(n)
        return out

    def _owner_markers(self, nodes: list) -> dict:
        """full_name -> AI markers in the owner's other recently pushed repos (None if the owner is gone)."""
        if not nodes:
            return {}
        n_repos = self.cfg['owner_repos_checked']
        parts = [OWNER_PART % (i, json.dumps(n['owner']['login']), n_repos + 1, _FILES) for i, n in enumerate(nodes)]
        data = retry(lambda: self.gh.graphql(OWNER_QUERY % '\n'.join(parts), {}), what='owner screen',
                     log=self.log, cfg=self.cfg, shutdown=self.shutdown)
        out = {}
        for i, n in enumerate(nodes):
            u = data.get(f'u{i}')
            if not u:
                out[n['nameWithOwner']] = None
                continue
            others = [r for r in u['repositories']['nodes'] if r['nameWithOwner'] != n['nameWithOwner']]
            out[n['nameWithOwner']] = set().union(*(screen_markers(r) for r in others[:n_repos]))
        return out

    def _needs_human_check(self, month: str) -> bool:
        """Can a repo created this month have its snapshot after the human cutoff?"""
        y, m = map(int, month.split('-'))
        last = datetime(y, m, calendar.monthrange(y, m)[1]) + timedelta(days=self.cfg['snapshot_days'])
        return last.date().isoformat() >= self.cfg['human_cutoff']

    @staticmethod
    def _record(n: dict, lang: str, month: str, stratum: str, tags, owner) -> dict:
        return {
            'full_name': n['nameWithOwner'], 'language': lang, 'month': month, 'stratum': stratum,
            'stars': n['stargazerCount'], 'forks': n['forkCount'], 'size_kb': n['diskUsage'],
            'created_at': n['createdAt'], 'pushed_at': n['pushedAt'],
            'clone_url': n['url'] + '.git', 'description': (n.get('description') or '')[:200],
            'screen_ai_types': None if tags is None else ','.join(sorted(tags)),
            'owner_ai': None if owner is None else int(bool(owner)),
            'owner_ai_types': ','.join(sorted(owner)) if owner else None,
        }

    def sample_cell(self, month: str, lang: str):
        """Yields lists of newly inserted repo dicts for one cell."""
        targets = cell_targets(month, self.cfg)
        have = {k: self.db.cell_count(month, lang, k) for k in targets}
        need = lambda k: targets[k] - have[k]
        if all(need(k) <= 0 for k in targets):
            for k in targets:
                if targets[k]:
                    self.db.mark_cell(month, lang, k, targets[k], have[k], 'done')
            return
        human_check = self._needs_human_check(month)
        screen = targets['ai'] > 0 or human_check
        rng = random.Random(f"{self.cfg['seed']}-{month}-{lang}")
        wins = _windows(month, self.cfg['window_hours'])
        rng.shuffle(wins)
        status = None
        for k, (t0, t1) in enumerate(wins[:self.cfg['max_windows_per_cell']]):
            if self.shutdown.shutdown_requested:
                raise ShutdownRequested()
            if self.db.total_repos() >= self.cfg['max_total_repos']:
                status = 'budget'
                break
            self.current = (f"{month} {lang} (window {k + 1}; random {have['random']}/{targets['random']}, "
                            f"ai {have['ai']}/{targets['ai']})")
            nodes = self._search(lang, t0, t1, screen)
            rng.shuffle(nodes)
            tags = {n['nameWithOwner']: screen_markers(n) if screen else None for n in nodes}
            if screen:
                self.db.record_screen(month, lang, _fmt(t0), len(nodes), sum(bool(t) for t in tags.values()))

            rand = nodes[:max(0, min(self.cfg['picks_per_window'], need('random')))]
            positives = [n for n in nodes[len(rand):] if tags[n['nameWithOwner']]]
            ai = positives[:max(0, min(self.cfg['ai_picks_per_window'], need('ai')))]
            # Owner screen only where it matters: random picks that look human and may postdate the cutoff
            owners = self._owner_markers([n for n in rand if human_check and not tags[n['nameWithOwner']]])
            picked = [self._record(n, lang, month, 'random', tags[n['nameWithOwner']],
                                   owners.get(n['nameWithOwner'])) for n in rand]
            picked += [self._record(n, lang, month, 'ai', tags[n['nameWithOwner']], None) for n in ai]
            new = self.db.insert_repos(picked)
            for r in new:
                have[r['stratum']] += 1
            if new:
                yield new
            if all(need(k) <= 0 for k in targets):
                break
        for k in targets:
            if not targets[k]:
                continue
            st = 'done' if need(k) <= 0 else (status or 'short')
            if st == 'short':
                self.log.warn(f"cell {month} {lang} {k}: only {have[k]}/{targets[k]} repos after "
                              f"{self.cfg['max_windows_per_cell']} windows")
            self.db.mark_cell(month, lang, k, targets[k], have[k], st)
        if status == 'budget':
            raise BudgetReached()
