"""CLI for the LSAIW pipeline.

    python run.py rules [--refresh]     # freeze the rule subset (rules/core.yml) and CVE set (rules/cves.json)
    python run.py run [--test]          # collect + scan, pipelined; live dashboard on :8765
    python run.py dashboard [--test]    # view an existing DB without running anything
    python run.py analyze [--test] [--detrend]
    python run.py export [--test]       # CSVs in the original column layout
"""
import argparse
import sys
import time

from lsaiw.config import ROOT, build_config


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('command', choices=['rules', 'run', 'dashboard', 'analyze', 'export'])
    ap.add_argument('--test', action='store_true', help='tiny sample (2 repos per stratum, 2025-05..07) into results_test/')
    ap.add_argument('--host', default=None, help='dashboard bind address (0.0.0.0 to view from another device)')
    ap.add_argument('--port', type=int, default=None)
    ap.add_argument('--no-dashboard', action='store_true')
    ap.add_argument('--refresh', action='store_true', help='rules: re-download the full Semgrep packs first')
    ap.add_argument('--detrend', action='store_true', help='also report first-difference correlations')
    ap.add_argument('--work-dir', default=None, help='where clones go (default: /dev/shm on Linux, ./repos otherwise)')
    args = ap.parse_args(argv)

    cfg = build_config(args.test, dashboard_host=args.host, dashboard_port=args.port, work_dir=args.work_dir)
    cfg['results_dir'].mkdir(parents=True, exist_ok=True)

    from lsaiw.infra import PipelineLogger
    log = PipelineLogger(cfg['log_file'])

    if args.command == 'rules':
        from lsaiw.deps import select_cves
        from lsaiw.scan import fetch_rules, select_rules
        if args.refresh or not list((cfg['rules_dir'] / 'packs').glob('*.yml')):
            fetch_rules(cfg['rules_dir'], log)
        select_rules(cfg['rules_dir'], cfg['rules_per_lang'], log)
        select_cves(cfg['rules_dir'], cfg, log)

    elif args.command == 'run':
        from lsaiw.collect import GitHubClient
        from lsaiw.dashboard import StatsSource, start_dashboard
        from lsaiw.db import DB, ensure_healthy
        from lsaiw.infra import GracefulShutdown, KeepAlive, load_tokens
        from lsaiw.pipeline import Pipeline
        from lsaiw.scan import semgrep_version

        shutdown = GracefulShutdown(log)
        ensure_healthy(cfg['db_path'], cfg['snapshot_dir'], log)
        db = DB(cfg['db_path'])
        version = semgrep_version()
        prev = db.get_state('semgrep_version')
        if prev and prev != version:
            log.warn(f"Semgrep version changed ({prev} -> {version}); findings may not be comparable across runs")
        db.set_state('semgrep_version', version)
        db.set_state('config', {k: str(v) for k, v in cfg.items()})

        gh = GitHubClient(load_tokens(ROOT), cfg, log, shutdown)
        log.info(f"GitHub: {gh.ping()} | semgrep {version}")
        keepalive = KeepAlive(gh.ping, cfg['keepalive_interval'], log)
        keepalive.start()

        pipe = Pipeline(cfg, db, gh, log, shutdown)
        if not args.no_dashboard:
            start_dashboard(StatsSource(cfg, pipe, log), cfg['dashboard_host'], cfg['dashboard_port'], log)
        try:
            pipe.run()
        finally:
            keepalive.stop()
            db.close()

    elif args.command == 'dashboard':
        from lsaiw.dashboard import StatsSource, start_dashboard
        if not cfg['db_path'].exists():
            sys.exit(f"No database at {cfg['db_path']}")
        if start_dashboard(StatsSource(cfg, None, log), cfg['dashboard_host'], cfg['dashboard_port'], log):
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    elif args.command == 'analyze':
        from lsaiw.analyze import run
        run(cfg, detrend=args.detrend)

    elif args.command == 'export':
        from lsaiw.db import export_csvs
        for name, n in export_csvs(cfg['db_path'], cfg['results_dir']).items():
            print(f"  {name:32s} {n:>10,} rows")


if __name__ == '__main__':
    main()
