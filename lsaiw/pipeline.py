"""Pipelined stages connected by bounded queues:

    collect (1 thread, GitHub API) -> snapshot (N threads, git I/O)
        -> semgrep batcher (P processes x -j J, CPU) -> deps/OSV (D threads, HTTP) -> SQLite

Bounded queues give back-pressure: clones cannot pile up faster than semgrep consumes them,
so the work dir (RAM disk on Linux) stays small. Scanning starts as soon as the first repos
are sampled instead of waiting for collection to finish.
"""
import os
import queue
import threading
import time
from collections import deque

from .collect import BudgetReached, RepoSampler, months
from .config import cell_targets
from .deps import OSVClient
from .infra import ShutdownRequested, SkipRepo, rmtree_force
from .scan import SemgrepRunner
from .snapshot import take_snapshot


class Stage:
    """Worker-thread group; `done` is set when the last worker exits."""

    def __init__(self, name, n, target, inq, upstream_done):
        self.name, self.n, self.inq, self.upstream_done = name, n, inq, upstream_done
        self.done = threading.Event()
        self.inflight = 0
        self._alive = n
        self._lock = threading.Lock()
        self.threads = [threading.Thread(target=self._wrap, args=(target,), daemon=True, name=f'{name}-{i}')
                        for i in range(n)]

    def _wrap(self, target):
        try:
            target(self)
        finally:
            with self._lock:
                self._alive -= 1
                if self._alive == 0:
                    self.done.set()

    def start(self):
        for t in self.threads:
            t.start()

    def get(self, shutdown, drain: bool = False, timeout: float = 0.5):
        """Next item, or None when upstream is finished and the queue is empty (or on shutdown unless draining)."""
        while True:
            if shutdown.shutdown_requested and not drain:
                return None
            try:
                return self.inq.get(timeout=timeout)
            except queue.Empty:
                if self.upstream_done.is_set() and self.inq.empty():
                    return None

    def busy(self, delta):
        with self._lock:
            self.inflight += delta


def put(q, item, shutdown, drain: bool = False) -> bool:
    """Blocking put that gives up on shutdown (back-pressure without deadlock).

    drain=True keeps waiting through a shutdown; only safe when the consumer also drains.
    """
    while drain or not shutdown.shutdown_requested:
        try:
            q.put(item, timeout=0.5)
            return True
        except queue.Full:
            pass
    return False


class Pipeline:
    def __init__(self, cfg, db, gh, log, shutdown):
        self.cfg, self.db, self.gh, self.log, self.shutdown = cfg, db, gh, log, shutdown
        self.sampler = RepoSampler(gh, db, cfg, log, shutdown)
        self.semgrep = SemgrepRunner(cfg, log, shutdown)
        self.osv = OSVClient(db, cfg, log, shutdown)
        P, B = cfg['semgrep_procs'], cfg['semgrep_batch_size']
        self.q_clone = queue.Queue(maxsize=64)
        self.q_scan = queue.Queue(maxsize=P * B * 2)   # bounds clones on disk
        self.q_deps = queue.Queue(maxsize=256)
        self.collect_done = threading.Event()
        self.started = time.time()
        self.finished_times = deque(maxlen=2000)
        self.counts = {'queued': 0, 'done': 0, 'skipped': 0, 'failed': 0}
        self.phase = 'starting'
        self._clock = threading.Lock()
        self._since_backup = 0

        self.stages = {
            'snapshot': Stage('snapshot', cfg['clone_workers'], self._snapshot_worker, self.q_clone, self.collect_done),
        }
        self.stages['semgrep'] = Stage('semgrep', P, self._semgrep_worker, self.q_scan, self.stages['snapshot'].done)
        self.stages['deps'] = Stage('deps', cfg['deps_workers'], self._deps_worker, self.q_deps,
                                    self.stages['semgrep'].done)

    # -- counters ----------------------------------------------------------
    def _count(self, key, n=1):
        with self._clock:
            self.counts[key] += n
            if key in ('done', 'skipped', 'failed'):
                self.finished_times.append(time.time())

    def target_total(self) -> int:
        per_lang = sum(sum(cell_targets(m, self.cfg).values()) for m in months(self.cfg['start'], self.cfg['end']))
        return min(per_lang * len(self.cfg['languages']), self.cfg['max_total_repos'])

    # -- stage: collect ----------------------------------------------------
    def _collector(self):
        try:
            # Resume: repos sampled earlier but not yet finished go first
            pending = self.db.resumable_repos(self.cfg['max_repo_attempts'])
            if pending:
                self.log.info(f"Resuming {len(pending)} pending/failed repos from the DB")
            for r in pending:
                if not put(self.q_clone, r, self.shutdown):
                    return
                self._count('queued')
            self.phase = 'collecting + scanning'
            for month in months(self.cfg['start'], self.cfg['end']):
                for lang in self.cfg['languages']:
                    strata = [k for k, n in cell_targets(month, self.cfg).items() if n]
                    cells = [self.db.cell(month, lang, k) for k in strata]
                    if all(c and c['status'] in ('done', 'short') for c in cells):
                        continue
                    for batch in self.sampler.sample_cell(month, lang):
                        for r in batch:
                            if not put(self.q_clone, r, self.shutdown):
                                return
                            self._count('queued')
            self.phase = 'scanning (collection complete)'
            self.log.info("Collection complete")
        except BudgetReached:
            self.phase = 'scanning (repo budget reached)'
            self.log.warn(f"Repo budget of {self.cfg['max_total_repos']:,} reached; collection stopped")
        except ShutdownRequested:
            pass
        except Exception as e:
            self.log.error(f"collector crashed: {e!r}; scanning what was collected. Re-run to resume.")
        finally:
            self.sampler.current = None
            self.collect_done.set()

    # -- stage: snapshot ---------------------------------------------------
    def _snapshot_worker(self, st: Stage):
        while (repo := st.get(self.shutdown)) is not None:
            name = repo['full_name']
            st.busy(1)
            try:
                snap = take_snapshot(repo, self.cfg, self.log, self.shutdown)
                if not put(self.q_scan, snap, self.shutdown):
                    rmtree_force(snap['path'])
            except SkipRepo as e:
                self.db.mark_repo(name, 'skipped', str(e))
                self._count('skipped')
            except ShutdownRequested:
                pass
            except Exception as e:
                self.db.log_error(name, 'snapshot', str(e))
                self.db.mark_repo(name, 'failed', f'snapshot: {e}', bump_attempt=True)
                self.log.repo_event(name, 'snapshot', f'FAIL: {str(e)[:150]}')
                self._count('failed')
            finally:
                st.busy(-1)

    # -- stage: semgrep ----------------------------------------------------
    def _take_batch(self, st: Stage):
        first = st.get(self.shutdown)
        if first is None:
            return None
        batch, deadline = [first], time.time() + self.cfg['semgrep_batch_wait']
        while len(batch) < self.cfg['semgrep_batch_size'] and time.time() < deadline:
            try:
                batch.append(self.q_scan.get(timeout=0.5))
            except queue.Empty:
                if st.upstream_done.is_set() or self.shutdown.shutdown_requested:
                    break
        return batch

    def _semgrep_worker(self, st: Stage):
        while (batch := self._take_batch(st)) is not None:
            st.busy(len(batch))
            t0 = time.time()
            try:
                failed = self.semgrep.scan(batch)
            except Exception as e:
                failed = batch
                for s in batch:
                    s['errors'].append(('semgrep', str(e)[:300]))
            finally:
                for s in batch:
                    rmtree_force(s['path'])
                st.busy(-len(batch))
            self.log.info(f"semgrep batch: {len(batch)} repos, "
                          f"{sum(len(s['findings']) for s in batch)} findings ({time.time() - t0:.0f}s)")
            failed_names = {s['full_name'] for s in failed}
            for s in batch:
                if s['full_name'] in failed_names:
                    # A repo without a scan would count as zero findings and bias the result: exclude it.
                    for stage, err in s['errors']:
                        self.db.log_error(s['full_name'], stage, err)
                    self.db.mark_repo(s['full_name'], 'failed', s['errors'][-1][1] if s['errors'] else 'semgrep',
                                      bump_attempt=True)
                    self._count('failed')
                else:
                    # drain: never throw away a finished semgrep scan; the deps stage drains on shutdown
                    put(self.q_deps, s, self.shutdown, drain=True)

    # -- stage: deps + write -----------------------------------------------
    def _deps_worker(self, st: Stage):
        # drain=True: finish OSV lookups for repos that were already scanned, even on shutdown
        while (s := st.get(self.shutdown, drain=True)) is not None:
            st.busy(1)
            try:
                try:
                    s['deps'] = self.osv.vulns_for(s['packages'], s['snapshot_date'])
                    s['deps_ok'] = True
                except Exception as e:
                    s['deps'], s['deps_ok'] = [], False
                    s['errors'].append(('osv', str(e)[:300]))
                s['scan_seconds'] = time.time() - s['t_start']
                self.db.save_repo_result(s)
                self._count('done')
                self._maybe_backup()
            except Exception as e:
                self.log.error(f"[{s['full_name']}] write failed: {e!r}")
                self._count('failed')
            finally:
                st.busy(-1)

    def _maybe_backup(self):
        with self._clock:
            self._since_backup += 1
            due = self._since_backup >= self.cfg['snapshot_every']
            if due:
                self._since_backup = 0
        if due:
            dest = self.db.backup(self.cfg['snapshot_dir'], self.cfg['snapshots_keep'])
            self.log.info(f"DB snapshot saved -> {dest.name}")

    # -- run ---------------------------------------------------------------
    def save_state(self):
        self.db.set_state('last_run', {**self.counts, 'saved_at': time.strftime('%Y-%m-%dT%H:%M:%S')})

    def run(self):
        rmtree_force(self.cfg['work_dir'])  # leftovers from an interrupted run
        self.cfg['work_dir'].mkdir(parents=True, exist_ok=True)
        self.shutdown.set_save_callback(self.save_state)
        self.log.info(f"Workers: clone={self.cfg['clone_workers']}, semgrep={self.cfg['semgrep_procs']}"
                      f"x-j{self.cfg['semgrep_jobs']} (batch {self.cfg['semgrep_batch_size']}), "
                      f"deps={self.cfg['deps_workers']}; work dir {self.cfg['work_dir']}")
        if os.name == 'nt':
            self.log.info(f"Tip: a Windows Defender exclusion for {self.cfg['work_dir']} speeds up cloning")
        threading.Thread(target=self._collector, daemon=True, name='collector').start()
        for st in self.stages.values():
            st.start()
        # Join with a timeout so the main thread keeps receiving Ctrl+C
        while not self.stages['deps'].done.wait(1.0):
            pass
        self.phase = 'stopped (resume by re-running)' if self.shutdown.shutdown_requested else 'finished'
        self.save_state()
        self.db.backup(self.cfg['snapshot_dir'], self.cfg['snapshots_keep'])
        rmtree_force(self.cfg['work_dir'])
        elapsed = (time.time() - self.started) / 3600
        self.log.info(f"Pipeline {self.phase}: {self.counts} in {elapsed:.2f}h")
