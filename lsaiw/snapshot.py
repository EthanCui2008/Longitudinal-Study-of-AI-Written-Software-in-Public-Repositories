"""Blobless clone -> checkout the commit at created + N days -> LOC, AI markers (at the snapshot and
later, up to HEAD), dependency manifests."""
import hashlib
import os
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

from .config import (BOT_AUTHOR, CODE_EXT, COMMIT_PATTERNS, EXCLUDE_DIRS, MARKER_BASENAMES,
                     MARKER_PREFIXES, MAX_FILE_BYTES)
from .deps import parse_manifests
from .infra import SkipRepo, _is_transient, retry, rmtree_force

GIT_ENV = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GCM_INTERACTIVE': 'never',
           'GIT_LFS_SKIP_SMUDGE': '1'}
GIT_CFG = ['-c', 'core.longpaths=true', '-c', 'core.autocrlf=false', '-c', 'core.symlinks=false',
           '-c', 'advice.detachedHead=false', '-c', 'protocol.file.allow=never']


def git(args, cwd=None, timeout=120) -> str:
    r = subprocess.run(['git', *GIT_CFG, *args], cwd=cwd, capture_output=True, timeout=timeout, env=GIT_ENV)
    if r.returncode != 0:
        raise RuntimeError(f"git {args[0]} rc={r.returncode}: "
                           f"{r.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return r.stdout.decode('utf-8', 'replace')


def safe_name(full_name: str) -> str:
    # Short hashed dir name: git on Windows fails with "'$GIT_DIR' too big" on long paths
    return hashlib.sha1(full_name.encode()).hexdigest()[:12]


def detect_file_markers(paths: list) -> set:
    found = set()
    for p in paths:
        low = p.lower()
        base = low.rsplit('/', 1)[-1]
        if base in MARKER_BASENAMES:
            found.add(MARKER_BASENAMES[base])
        for prefix, tag in MARKER_PREFIXES.items():
            if low.startswith(prefix) or f'/{prefix}' in low:
                found.add(tag)
    return found


def detect_commit_markers(log_text: str):
    """Returns (marker tags, n_commits, n_ai_commits) from `git log` output with \\x1e record separators."""
    tags, n, n_ai = set(), 0, 0
    for rec in log_text.split('\x1e'):
        rec = rec.strip()
        if not rec:
            continue
        n += 1
        author, _, body = rec.partition('\x1f')
        hit = False
        if BOT_AUTHOR.search(author):
            tags.add('bot-author')
            hit = True
        for pat, tag in COMMIT_PATTERNS:
            if pat.search(body):
                tags.add(tag)
                hit = True
        n_ai += hit
    return tags, n, n_ai


def count_loc(root: Path):
    """Lines in target-language files, skipping vendored/minified/oversized files."""
    loc = files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in CODE_EXT or '.min.' in fn:
                continue
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > MAX_FILE_BYTES:
                    continue
                with open(p, 'rb') as f:
                    loc += f.read().count(b'\n') + 1
                files += 1
            except OSError:
                pass
    return loc, files


def take_snapshot(repo: dict, cfg: dict, log, shutdown) -> dict:
    name = repo['full_name']
    dest = cfg['work_dir'] / safe_name(name)
    rmtree_force(dest)
    t0 = time.time()

    def _clone():
        rmtree_force(dest)
        git(['clone', '--filter=blob:none', '--no-checkout', '--single-branch', '--quiet',
             repo['clone_url'], str(dest)], timeout=cfg['clone_timeout'])
    try:
        try:
            retry(_clone, what=f"[{name}] clone", log=log, cfg=cfg, shutdown=shutdown)
        except RuntimeError as e:
            if not _is_transient(str(e)):
                raise SkipRepo(f'repo unavailable: {str(e)[:150]}')  # deleted / private / DMCA
            raise

        created = datetime.fromisoformat(repo['created_at'].replace('Z', '+00:00'))
        snap_date = created + timedelta(days=cfg['snapshot_days'])
        sha = git(['rev-list', '-1', f"--before={snap_date.isoformat()}", 'HEAD'], cwd=dest).strip()
        if not sha:
            raise SkipRepo('no commits before snapshot date')

        # Commits and trees come with a blobless clone, so these need no blob downloads
        log_text = git(['log', '--format=%an <%ae>%x1f%B%x1e', sha], cwd=dest, timeout=180)
        commit_tags, n_commits, n_ai = detect_commit_markers(log_text)
        tree = git(['ls-tree', '-r', '--name-only', sha], cwd=dest).splitlines()
        file_tags = detect_file_markers(tree)
        # AI use that started after the snapshot: such repos are not clean human controls
        later_log = git(['log', '--format=%an <%ae>%x1f%B%x1e', f'{sha}..HEAD'], cwd=dest, timeout=180)
        later_tags = detect_commit_markers(later_log)[0]
        later_tags |= detect_file_markers(git(['ls-tree', '-r', '--name-only', 'HEAD'], cwd=dest).splitlines())

        git(['checkout', '--quiet', sha], cwd=dest, timeout=cfg['clone_timeout'])
        loc, files = count_loc(dest)
        if loc == 0:
            raise SkipRepo('no target-language code at snapshot')
        packages = parse_manifests(dest)
    except BaseException:
        rmtree_force(dest)
        raise

    tags = sorted(commit_tags | file_tags)
    return {
        **repo, 'path': dest, 'snapshot_date': snap_date.date().isoformat(), 'sha': sha,
        'commit_count': n_commits, 'ai_marker': bool(tags), 'ai_marker_types': tags,
        'ai_commit_count': n_ai, 'ai_commit_share': n_ai / n_commits if n_commits else 0.0,
        'later_ai_types': sorted(later_tags - set(tags)),
        'loc': loc, 'code_files': files, 'packages': packages,
        'findings': [], 'deps': [], 'errors': [], 't_start': t0,
    }
