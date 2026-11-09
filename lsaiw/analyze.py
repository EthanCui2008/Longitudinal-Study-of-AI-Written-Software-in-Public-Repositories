"""Raw correlations between security findings and LLM proliferation (release events, AI markers).

Month-level series use only the `random` stratum (an unweighted draw); the `ai` stratum exists to
give the repo-level group comparisons enough AI-marked repos. Groups:

    ai          AI-tool markers at the snapshot (files, commit trailers, bot authors)
    human_pre   snapshot before the first public AI coding tool (cfg['human_cutoff'])
    human_post  later snapshot, no markers at the snapshot, none added later, none in the
                screen at HEAD, and none in the owner's other recent repos
    unclear     everything else (e.g. AI markers added after the snapshot): never a control
"""
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

from .config import LLM_EVENTS, event_index
from .db import connect


def _corr(x, y, label: str, level: str, detrended: bool = False) -> dict:
    x, y = pd.Series(x, dtype=float), pd.Series(y, dtype=float)
    ok = x.notna() & y.notna()
    x, y = x[ok], y[ok]
    row = {'level': level, 'measure': label, 'detrended': detrended, 'n': len(x),
           'pearson_r': np.nan, 'pearson_p': np.nan, 'spearman_rho': np.nan, 'spearman_p': np.nan}
    if len(x) >= 3 and x.nunique() > 1 and y.nunique() > 1:
        row['pearson_r'], row['pearson_p'] = stats.pearsonr(x, y)
        row['spearman_rho'], row['spearman_p'] = stats.spearmanr(x, y)
    return row


def _bh(p: pd.Series) -> pd.Series:
    """Benjamini-Hochberg q-values (NaN-safe)."""
    q = pd.Series(np.nan, index=p.index)
    pv = p.dropna().sort_values()
    if pv.empty:
        return q
    m = len(pv)
    adj = (pv * m / np.arange(1, m + 1))[::-1].cummin()[::-1].clip(upper=1)
    q[adj.index] = adj
    return q


def assign_groups(repos: pd.DataFrame, cutoff: str) -> pd.Series:
    ai = repos['ai_marker'] == 1
    pre = repos['snapshot_date'] < cutoff
    clean = ((repos['later_ai'] == 0) & (repos['owner_ai'] == 0)
             & (repos['screen_ai_types'].fillna('') == '') & repos['screen_ai_types'].notna())
    return pd.Series(np.select([ai, pre, clean], ['ai', 'human_pre', 'human_post'], 'unclear'), index=repos.index)


def load(db_path: Path, cutoff: str):
    conn = connect(db_path, readonly=True)
    repos = pd.read_sql("SELECT * FROM repos WHERE status='done' AND loc>0", conn)
    findings = pd.read_sql(
        "SELECT f.repo_name, f.severity, f.cwe FROM findings f JOIN repos r ON r.full_name=f.repo_name "
        "WHERE r.status='done' AND r.loc>0", conn)
    screens = pd.read_sql("SELECT month, SUM(candidates) AS screened, SUM(with_ai) AS screened_ai "
                          "FROM screens GROUP BY month", conn)
    conn.close()
    repos['fpk'] = repos['n_findings'] * 1000 / repos['loc']
    repos['high_pk'] = repos['n_high'] * 1000 / repos['loc']
    repos['event'] = repos['month'].map(event_index)
    repos['group'] = assign_groups(repos, cutoff)
    return repos, findings, screens


def monthly_table(repos: pd.DataFrame, screens: pd.DataFrame) -> pd.DataFrame:
    """Random stratum only. screen_ai_share = share of all screened search candidates with AI markers
    at HEAD, a far larger (if HEAD-based) prevalence sample than the scanned repos."""
    repos = repos[repos['stratum'] == 'random']
    g = repos.groupby('month')
    deps = repos[repos['deps_ok'] == 1].groupby('month')
    m = pd.DataFrame({
        'n_repos': g.size(),
        'kloc': g['loc'].sum() / 1000,
        'findings': g['n_findings'].sum(),
        'high': g['n_high'].sum(),
        'ai_share': g['ai_marker'].mean(),
        'ai_commit_share': g['ai_commit_share'].mean(),
        'dep_vulns_per_repo': deps['n_deps'].mean(),
    }).reset_index()
    m['findings_per_kloc'] = m['findings'] / m['kloc']
    m['high_per_kloc'] = m['high'] / m['kloc']
    m['event'] = m['month'].map(event_index)
    m = m.merge(screens, on='month', how='left')
    m['screen_ai_share'] = m['screened_ai'] / m['screened']
    return m


def cwe_monthly(repos: pd.DataFrame, findings: pd.DataFrame, top: int = 25) -> pd.DataFrame:
    """Rows = month, columns = CWE (count per KLOC); one finding can map to several CWEs. Random stratum."""
    repos = repos[repos['stratum'] == 'random']
    f = findings.merge(repos[['full_name', 'month']], left_on='repo_name', right_on='full_name')
    f = f.assign(cwe=f['cwe'].fillna('').str.split(r',(?=\s*CWE-)')).explode('cwe')
    f['cwe'] = f['cwe'].str.strip()
    f = f[f['cwe'].str.startswith('CWE-')]
    counts = f.groupby(['month', 'cwe']).size().unstack(fill_value=0)
    keep = counts.sum().sort_values(ascending=False).head(top).index
    kloc = repos.groupby('month')['loc'].sum() / 1000
    counts = counts.reindex(index=kloc.index, fill_value=0)[keep]
    return counts.div(kloc, axis=0)


def correlations(repos, monthly, cwe, detrend: bool) -> pd.DataFrame:
    rows = []
    outcomes = {'findings/KLOC': 'findings_per_kloc', 'high-severity/KLOC': 'high_per_kloc',
                'dep vulns/repo': 'dep_vulns_per_repo'}
    variants = [(False, monthly)]
    if detrend:
        variants.append((True, monthly.set_index('month').diff().reset_index()))
    for dt, m in variants:
        for label, col in outcomes.items():
            rows.append(_corr(m['event'], m[col], f'{label} vs release-event index', 'month', dt))
            rows.append(_corr(m['ai_share'], m[col], f'{label} vs AI-marker share', 'month', dt))
            rows.append(_corr(m['screen_ai_share'], m[col], f'{label} vs screened AI share', 'month', dt))
        rows.append(_corr(m['event'], m['ai_share'], 'AI-marker share vs release-event index', 'month', dt))
        rows.append(_corr(m['event'], m['screen_ai_share'], 'screened AI share vs release-event index', 'month', dt))

    rand = repos[repos['stratum'] == 'random']
    for lang, sub in [('all', rand)] + list(rand.groupby('language')):
        lvl = f'repo ({lang})'
        rows.append(_corr(sub['ai_marker'], sub['fpk'], 'findings/KLOC vs AI marker (point-biserial)', lvl))
        rows.append(_corr(sub['ai_commit_share'], sub['fpk'], 'findings/KLOC vs AI commit share', lvl))
        rows.append(_corr(sub['event'], sub['fpk'], 'findings/KLOC vs release-event index', lvl))
        d = sub[sub['deps_ok'] == 1]
        rows.append(_corr(d['ai_marker'], d['n_deps'], 'dep vulns vs AI marker', lvl))

    cw = cwe.copy()
    cw['event'] = cw.index.map(event_index)
    cw['ai_share'] = monthly.set_index('month')['ai_share']
    for c in cwe.columns:
        rows.append(_corr(cw['event'], cw[c], f'{c} /KLOC vs release-event index', 'month-cwe'))
        rows.append(_corr(cw['ai_share'], cw[c], f'{c} /KLOC vs AI-marker share', 'month-cwe'))

    out = pd.DataFrame(rows)
    cwe_rows = out['level'] == 'month-cwe'
    out.loc[cwe_rows, 'pearson_q_bh'] = _bh(out.loc[cwe_rows, 'pearson_p'])
    return out


COMPARISONS = [
    ('AI vs human, same period', 'ai', ['human_post']),
    ('AI vs human, pre-LLM baseline', 'ai', ['human_pre']),
    ('AI vs all unmarked, same period (sensitivity)', 'ai', ['human_post', 'unclear']),
]
GROUP_OUTCOMES = {'findings/KLOC': 'fpk', 'high-severity/KLOC': 'high_pk', 'dep vulns/repo': 'n_deps'}


def group_comparisons(repos: pd.DataFrame) -> pd.DataFrame:
    """Raw two-group contrasts at repo level: medians, Mann-Whitney U, rank-biserial and point-biserial r.

    Same-period contrasts keep only months where both groups have repos, so the comparison is
    within months rather than across them.
    """
    rows = []
    for name, a, b in COMPARISONS:
        for lang, sub in [('all', repos)] + list(repos.groupby('language')):
            x, y = sub[sub['group'] == a], sub[sub['group'].isin(b)]
            if 'pre-LLM' not in name:
                both = set(x['month']) & set(y['month'])
                x, y = x[x['month'].isin(both)], y[y['month'].isin(both)]
            for label, col in GROUP_OUTCOMES.items():
                xa, ya = (x, y) if col != 'n_deps' else (x[x['deps_ok'] == 1], y[y['deps_ok'] == 1])
                xa, ya = xa[col].dropna(), ya[col].dropna()
                row = {'comparison': name, 'language': lang, 'outcome': label, 'n_ai': len(xa), 'n_control': len(ya),
                       'median_ai': xa.median(), 'median_control': ya.median(),
                       'mean_ai': xa.mean(), 'mean_control': ya.mean(),
                       'mw_p': np.nan, 'rank_biserial': np.nan, 'pointbiserial_r': np.nan, 'pointbiserial_p': np.nan}
                if len(xa) >= 3 and len(ya) >= 3:
                    u, row['mw_p'] = stats.mannwhitneyu(xa, ya, alternative='two-sided')
                    row['rank_biserial'] = 2 * u / (len(xa) * len(ya)) - 1  # >0: AI group higher
                    lab = np.r_[np.ones(len(xa)), np.zeros(len(ya))]
                    if np.r_[xa, ya].std() > 0:
                        row['pointbiserial_r'], row['pointbiserial_p'] = stats.pointbiserialr(lab, np.r_[xa, ya])
                rows.append(row)
    return pd.DataFrame(rows)


def figures(monthly: pd.DataFrame, repos: pd.DataFrame, out: Path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    x = pd.to_datetime(monthly['month'])
    fig, ax = plt.subplots(figsize=(12, 4.5))
    ax.plot(x, monthly['findings_per_kloc'], color='#2563eb', lw=1.6, label='findings / KLOC')
    ax.set_ylabel('Semgrep findings per KLOC')
    ax2 = ax.twinx()
    ax2.plot(x, monthly['ai_share'] * 100, color='#d97706', lw=1.2, label='% repos with AI markers')
    ax2.set_ylabel('% repos with AI markers')
    for m, name in LLM_EVENTS:
        ax.axvline(pd.Timestamp(m), color='grey', ls='--', lw=0.8)
        ax.text(pd.Timestamp(m), ax.get_ylim()[1], name, rotation=90, va='top', ha='right', fontsize=7, color='grey')
    ax.set_title('Security findings by repo creation month vs LLM proliferation')
    ax.spines[['top']].set_visible(False)
    fig.legend(loc='upper left', bbox_to_anchor=(0.07, 0.9), frameon=False)
    fig.tight_layout()
    fig.savefig(out / 'timeseries.png', dpi=150)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    axes[0].scatter(monthly['ai_share'] * 100, monthly['findings_per_kloc'], s=14, alpha=.7, color='#2563eb')
    axes[0].set_xlabel('% repos with AI markers (month)')
    axes[0].set_ylabel('findings / KLOC (month)')
    order = ['human_pre', 'human_post', 'unclear', 'ai']
    groups = [repos.loc[repos['group'] == k, 'fpk'] for k in order]
    axes[1].boxplot(groups, tick_labels=[f"{k}\n(n={len(v)})" for k, v in zip(order, groups)], showfliers=False)
    axes[1].set_ylabel('findings / KLOC (repo)')
    for a in axes:
        a.spines[['top', 'right']].set_visible(False)
    fig.tight_layout()
    fig.savefig(out / 'ai_markers.png', dpi=150)
    plt.close(fig)


def run(cfg: dict, detrend: bool = False) -> pd.DataFrame:
    out = cfg['results_dir'] / 'analysis'
    out.mkdir(parents=True, exist_ok=True)
    repos, findings, screens = load(cfg['db_path'], cfg['human_cutoff'])
    if repos.empty:
        raise SystemExit('No scanned repos yet: run `python run.py run` first.')
    monthly = monthly_table(repos, screens)
    cwe = cwe_monthly(repos, findings)
    corr = correlations(repos, monthly, cwe, detrend)
    groups = group_comparisons(repos)

    monthly.to_csv(out / 'monthly.csv', index=False)
    cwe.to_csv(out / 'monthly_cwe.csv')
    repos.drop(columns=['description']).to_csv(out / 'repos_scanned.csv', index=False)
    corr.to_csv(out / 'correlations.csv', index=False)
    groups.to_csv(out / 'group_comparisons.csv', index=False)
    figures(monthly, repos, out)

    with pd.option_context('display.width', 160, 'display.max_colwidth', 70, 'display.float_format', '{:.3f}'.format):
        cols = ['level', 'measure', 'n', 'pearson_r', 'pearson_p', 'spearman_rho', 'spearman_p']
        print(corr[corr['level'] != 'month-cwe'][cols + ['detrended']].to_string(index=False))
        top = corr[corr['level'] == 'month-cwe'].reindex(
            corr[corr['level'] == 'month-cwe']['pearson_r'].abs().sort_values(ascending=False).index).head(10)
        print('\nTop CWE correlations (q = Benjamini-Hochberg across all CWE tests):')
        print(top[['measure', 'n', 'pearson_r', 'pearson_p', 'pearson_q_bh', 'spearman_rho']].to_string(index=False))
        print('\nRepos per group:', repos['group'].value_counts().to_dict())
        print('\nGroup comparisons (all languages; rank-biserial > 0 means the AI group is higher):')
        g = groups[groups['language'] == 'all']
        print(g[['comparison', 'outcome', 'n_ai', 'n_control', 'median_ai', 'median_control', 'mw_p',
                 'rank_biserial']].to_string(index=False))
    print(f"\nWrote {out}/correlations.csv, group_comparisons.csv, monthly.csv, monthly_cwe.csv, "
          f"repos_scanned.csv, timeseries.png, ai_markers.png")
    return corr
