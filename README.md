# Longitudinal Study of AI-Written Software in Public Repositories

Measures how security findings in personal **Python and JavaScript** GitHub repositories (2017 to 2026) relate to
the spread of large language models. The proliferation measures are:

1. **LLM release events.** A monthly step index for GitHub Copilot GA (2022-06), ChatGPT (2022-11), GPT-4 (2023-03),
   Claude Code (2025-02) and Codex / Copilot coding agent (2025-05).
2. **Repo-level AI markers.** Files such as `CLAUDE.md`, `AGENTS.md`, `.cursorrules` and `.github/copilot-instructions.md`,
   commit trailers such as `Co-Authored-By: Claude`, and AI bot authors.

The output is raw Pearson and Spearman correlations at three levels (by month, by repo, by CWE), plus repo-level
comparisons of AI-marked repos against human-written controls.

## Sample design (about 17,600 repos, hard cap 20,000)

Each (creation month, language) cell has up to two strata, drawn from the same random creation-time search windows:

| Stratum | Months | Per language per month | Total | Used for |
|---|---|---|---|---|
| `random` | 2017-01 to 2022-12 | 15 | 2,160 | Time series, pre-LLM human baseline |
| `random` | 2023-01 to 2026-07 | 50 | 4,300 | Time series, same-period human controls |
| `ai` | 2023-01 to 2026-07 | up to 130 | up to 11,180 | AI-marked repos for the group comparisons |

- The **random** stratum is an unscreened draw, so month-level shares and series use only it.
- The **ai** stratum oversamples AI-marked repos, which are rare in a random draw. Every search candidate is screened in
  the same GraphQL query: root and `.github` entries at HEAD, plus the last 20 commit messages. Candidates the random
  stratum did not pick are enrolled only if the screen finds AI-tool markers. The screening tallies (`screens` table)
  give a month-by-month prevalence estimate from tens of thousands of candidates.
- AI cells in 2023–2024 will usually fall short of 130, because marked repos were rarer then. Cells that fall short
  are marked `short`, and the unused budget is simply not spent. `max_total_repos` stops collection at 20,000 whatever
  happens.

## Keeping AI-written code out of the human controls

AI use is often undisclosed, so an unmarked repo is not necessarily human-written. Each scanned repo is put in one group:

| Group | Rule |
|---|---|
| `ai` | AI-tool markers at the snapshot: files, commit trailers or bot authors |
| `human_pre` | Snapshot before **2021-06-29**, the GitHub Copilot technical preview, when no AI coding tool was public. Human-written by construction |
| `human_post` | Later snapshot and all four checks clean: (1) no markers at the snapshot, (2) none added later (commits up to HEAD, files at HEAD), (3) none in the GraphQL screen, (4) none in the owner's 10 most recently pushed other repos |
| `unclear` | Everything else, e.g. markers added after the snapshot, or an owner who uses Cursor elsewhere. Never used as a control |

Checks (2) to (4) look at present-day behaviour, so they also exclude people who adopted AI after writing the scanned
code. That is deliberately conservative: it costs control repos, but it removes most known AI users from the control.
Undisclosed AI use that leaves no trace anywhere cannot be detected. It biases the same-period comparison towards
zero, so a difference found there is a lower bound. The `human_pre` baseline has no such contamination, but it
differs from the AI group in time, with the trends that come with that.

`analyze` reports three contrasts in `group_comparisons.csv`. Each gives medians, Mann–Whitney U, rank-biserial and
point-biserial r for findings/KLOC, high-severity/KLOC and dependency CVEs:

1. `ai` vs `human_post`, within months where both exist (the main contrast)
2. `ai` vs `human_pre` (no contamination, but time-confounded)
3. `ai` vs `human_post` + `unclear` (sensitivity check: how much the exclusions matter)

## What is measured

Every repo is checked against two fixed sets, frozen into `rules/` by `python run.py rules`:

- **100 Semgrep rules** (`rules/core.yml`): 50 Python and 50 JavaScript, chosen from the frozen `security-audit`,
  `owasp-top-ten` and `cwe-top-25` packs (`rules/packs/`). Within each language, rules are ranked with language-level
  rules (`python.lang.*`, `javascript.lang.*`, which apply to any repo) before framework-specific ones, then by severity,
  likelihood and confidence. They are then taken round-robin across CWEs, so near-duplicate rules for one CWE cannot fill
  the quota. The result covers 44 Python and 29 JavaScript CWEs.
- **100 dependency CVEs** (`rules/cves.json`): 50 PyPI and 50 npm. These are CRITICAL/HIGH advisories with a CVE id,
  published 2017–2026, in 30 popular packages per ecosystem (`CVE_SEED_PACKAGES` in `lsaiw/config.py`). Packages take
  turns in popularity order, so each contributes 1–3 CVEs. A CVE counts for a repo only if a pinned dependency version
  is affected and the CVE was published by the repo's snapshot date.

## Design choices that remove known confounds

| Choice | Why |
|---|---|
| Sample by **creation** month, analyse the commit at **created + 90 days** | `pushed:` buckets mix abandoned and active repos. With this choice, every repo has the same exposure time. |
| Random creation-time windows, equal N per language per month (per stratum) | Sorting by stars and taking the first page selects only 0-star repos and lets the language mix drift. |
| Fixed rule and CVE sets (`rules/`) and a pinned Semgrep version | `--config auto` and the live advisory DB change over time. |
| Findings per KLOC, counted on the same files as LOC | Bigger repos have more findings. |
| OSV advisories counted only if **published by the snapshot date** | A scan against today's advisory DB charges old code for CVEs disclosed years later. |
| Repos whose scan failed are excluded, not counted as 0 | Otherwise a failed scan would look like clean code. |

## Quick start

```bash
python -m venv .venv && .venv/Scripts/activate      # Linux/WSL: source .venv/bin/activate
pip install -r requirements.txt
cp keys.env.example keys.env                         # add your GitHub token(s)

python run.py rules            # rebuild rules/core.yml + rules/cves.json (already committed; --refresh re-downloads packs)
python run.py run --test       # tiny run: 2 repos per stratum, 2025-05 to 2025-07 -> results_test/
python run.py run              # full run (resumable)
python run.py analyze          # correlations + figures -> results/analysis/
python run.py export           # CSVs in the original layout -> results/
```

While `run` is going, open **http://127.0.0.1:8765**. The page shows progress, ETA, throughput, queue depth per stage
(which reveals the bottleneck), CPU and RAM, findings/KLOC, AI-marker share, errors by stage, a findings/KLOC sparkline
with LLM release lines, live raw correlations, and the log tail. It updates by Server-Sent Events every 2 s, and
`/stats.json` serves the same data for scripts. Use `--host 0.0.0.0` to watch from a phone on the same network, or
`python run.py dashboard` to view an existing DB without running anything.

## Performance

The stages run concurrently, connected by bounded queues:

```
collect (GraphQL) -> snapshot (12 git threads) -> semgrep (2 procs x -j4, batched) -> OSV (4 threads) -> SQLite
```

- **100 rules instead of 689:** loading the rules takes about 8 s per Semgrep call instead of 38 s.
- **Batched Semgrep:** a call scans up to 16 repos at once, so the remaining rule-load cost is paid once per batch.
- **Tuned for an 8-thread / 32 GB laptop:** Semgrep uses every core (2 processes × `-j 4`, up to 6 GB each), and
  12 clone threads overlap network I/O. Advisory details are fetched 16 at a time, and only for the fixed CVE set.
- **Blobless clones** (`--filter=blob:none`) download only the files at the snapshot commit. Commit history for AI-marker
  detection comes without downloading any file contents.
- **OSV `querybatch`** replaces pip-audit and npm audit: no Node install, up to 1,000 packages per request, results
  cached in the DB.
- Worker counts are auto-sized from CPU count and free RAM. Override them in `lsaiw/config.py`.
- A full run is about 17,600 repos (see Sample design). Screening is part of the search query itself, and owner checks add
  one small GraphQL query per window. AI cells need many windows when markers are rare, so GitHub's search rate limits
  can make collection the bottleneck. Add more tokens in `keys.env` to rotate them.
- **Faster still: run under WSL2.** Clones then go to the `/dev/shm` RAM disk automatically, and Linux git and Semgrep
  are faster than on Windows. On native Windows, add a Defender exclusion for `repos/`, because real-time scanning
  inspects every cloned file.

## Resilience

- SQLite in WAL mode, **one transaction per repo**: a crash never leaves partial rows. Re-running resumes pending
  repos, and failed repos are retried up to 3 times across runs.
- Transient errors (timeouts, 5xx, rate limits) are retried with exponential backoff (15/30/60 s). Permanent ones
  (deleted or DMCA'd repos) are skipped.
- **Ctrl+C once:** stops cloning, finishes and saves Semgrep batches already in flight, then exits. **Ctrl+C twice:**
  exits immediately; unfinished repos stay pending.
- The DB is snapshotted every 250 repos (last 3 kept). An integrity check runs at startup and restores the latest
  snapshot if the DB is corrupt.
- GitHub tokens are rotated and the client sleeps through rate limits. A keep-alive pings the API every 5 minutes.

## Layout

```
run.py                 CLI: rules | run | dashboard | analyze | export
lsaiw/config.py        parameters, LLM events, AI-marker patterns
lsaiw/collect.py       GraphQL client and stratified sampler
lsaiw/snapshot.py      clone, checkout at created+90d, LOC, AI markers
lsaiw/scan.py          batched Semgrep with per-repo fallback
lsaiw/deps.py          manifest parsing and OSV date-filtered lookups
lsaiw/pipeline.py      concurrent stages and shutdown handling
lsaiw/db.py            SQLite store, backups, CSV export
lsaiw/dashboard.py     live browser dashboard
lsaiw/analyze.py       correlations and figures
rules/core.yml         the 100 Semgrep rules that are run
rules/cves.json        the 100 dependency CVEs that are counted
rules/packs/           full frozen Semgrep packs the rules are chosen from
```

## Outputs

- `results/pipeline.db`: everything, including repos, findings, dependency vulns, errors and the OSV cache
- `results/analysis/correlations.csv`: Pearson r, Spearman ρ, p-values and n. CWE rows also carry Benjamini–Hochberg q-values.
- `results/analysis/group_comparisons.csv`: the `ai` vs human-control contrasts above, per language and overall.
- `results/analysis/monthly.csv`, `monthly_cwe.csv` (findings/KLOC per CWE by month), `repos_scanned.csv`, `timeseries.png`, `ai_markers.png`

Note: two series that both trend over time will correlate strongly whatever the cause. `analyze --detrend` adds
first-difference correlations, and the `ai` vs `human_post` comparison (same months, different repos) is the
comparison least affected by time trends.

## License

MIT License. See [LICENSE](LICENSE) for details.
