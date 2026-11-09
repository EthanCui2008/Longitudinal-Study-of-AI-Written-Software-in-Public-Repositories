"""Lightweight live dashboard: stdlib HTTP server + Server-Sent Events, read-only on the DB.

    /            single inline HTML page (no CDN, no framework)
    /events      SSE stream, one JSON stats object every 2 s
    /stats.json  the same object for polling / scripts
    /healthz     "ok" (container healthcheck)
"""
import json
import os
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import LLM_EVENTS, event_index
from .db import connect


def _rank(xs):
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def pearson(x, y):
    n = len(x)
    if n < 3:
        return None
    mx, my = sum(x) / n, sum(y) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(x, y))
    sxx = sum((a - mx) ** 2 for a in x)
    syy = sum((b - my) ** 2 for b in y)
    return sxy / (sxx * syy) ** 0.5 if sxx and syy else None


def corr(x, y) -> dict:
    return {'r': pearson(x, y), 'rho': pearson(_rank(x), _rank(y)), 'n': len(x)}


class StatsSource:
    """Builds the stats object from the DB (read-only connection) plus live pipeline counters."""

    def __init__(self, cfg, pipeline=None, log=None, keepalive=None):
        self.cfg, self.pipeline, self.log, self.keepalive = cfg, pipeline, log, keepalive
        self._conn = None
        self._lock = threading.Lock()
        self._cache, self._cache_t = None, 0
        self._corr, self._corr_t = {}, 0

    def _db(self):
        if self._conn is None:
            self._conn = connect(self.cfg['db_path'], readonly=True)
        return self._conn

    def _correlations(self, c, monthly):
        ms = [m for m in monthly if m['loc'] > 0]
        out = {}
        if ms:
            fpk = [m['fpk'] for m in ms]
            out['monthly findings/KLOC vs release-event index'] = corr([m['event'] for m in ms], fpk)
            out['monthly findings/KLOC vs AI-marker share'] = corr([m['ai_share'] for m in ms], fpk)
            out['monthly AI-marker share vs release-event index'] = corr([m['event'] for m in ms],
                                                                         [m['ai_share'] for m in ms])
        rows = c.execute("SELECT ai_marker, n_findings*1000.0/loc FROM repos "
                         "WHERE status='done' AND loc>0 AND stratum='random'").fetchall()
        if rows:
            out['repo AI marker vs findings/KLOC'] = corr([r[0] for r in rows], [r[1] for r in rows])
        return out

    def stats(self) -> dict:
        with self._lock:
            now = time.time()
            if self._cache and now - self._cache_t < 1.5:
                return self._cache
            c = self._db()
            status = {r[0]: r[1] for r in c.execute('SELECT status, COUNT(*) FROM repos GROUP BY status')}
            tot = c.execute("SELECT COALESCE(SUM(n_findings),0), COALESCE(SUM(n_high),0), COALESCE(SUM(loc),0), "
                            "AVG(CASE WHEN stratum='random' THEN ai_marker END), COALESCE(SUM(n_deps),0) "
                            "FROM repos WHERE status='done'").fetchone()
            strata = {r[0]: r[1] for r in c.execute(
                "SELECT stratum, COUNT(*) FROM repos WHERE status='done' GROUP BY stratum")}
            scr = c.execute('SELECT COALESCE(SUM(candidates),0), COALESCE(SUM(with_ai),0) FROM screens').fetchone()
            monthly = [{'month': r[0], 'n': r[1], 'findings': r[2], 'loc': r[3], 'ai_share': r[4] or 0.0,
                        'fpk': (r[2] * 1000.0 / r[3]) if r[3] else 0.0, 'event': event_index(r[0])}
                       for r in c.execute("SELECT month, COUNT(*), SUM(n_findings), SUM(loc), AVG(ai_marker) "
                                          "FROM repos WHERE status='done' AND stratum='random' "
                                          "GROUP BY month ORDER BY month")]
            errors = {r[0]: r[1] for r in c.execute('SELECT stage, COUNT(*) FROM errors GROUP BY stage')}
            if now - self._corr_t > 30:
                self._corr, self._corr_t = self._correlations(c, monthly), now

            s = {
                'now': time.strftime('%H:%M:%S'),
                'status': status,
                'totals': {'findings': tot[0], 'high': tot[1], 'kloc': tot[2] / 1000,
                           'findings_per_kloc': tot[0] * 1000 / tot[2] if tot[2] else 0,
                           'ai_share': tot[3] or 0, 'dep_vulns': tot[4],
                           'strata': strata, 'screened': scr[0], 'screened_ai': scr[1]},
                'errors': errors,
                'monthly': monthly,
                'events': [{'month': m, 'name': n} for m, n in LLM_EVENTS],
                'corr': self._corr,
                'log': list(self.log.tail) if self.log else [],
            }
            p = self.pipeline
            if p:
                finished = sum(status.get(k, 0) for k in ('done', 'skipped', 'failed'))
                recent = [t for t in p.finished_times if t > now - 900]
                rate = len(recent) / ((now - max(recent[0], p.started)) / 60) if len(recent) > 1 else 0
                remaining = max(0, p.target_total() - finished)
                s['run'] = {
                    'phase': p.phase, 'elapsed_h': (now - p.started) / 3600, 'target': p.target_total(),
                    'finished': finished, 'rate_per_min': rate,
                    'eta_h': remaining / rate / 60 if rate else None,
                    'collecting': p.sampler.current,
                    'gh_remaining': p.gh.remaining,
                    'queues': {'to clone': p.q_clone.qsize(), 'to semgrep': p.q_scan.qsize(),
                               'to OSV': p.q_deps.qsize()},
                    'inflight': {k: st.inflight for k, st in p.stages.items()},
                    'workers': {k: st.n for k, st in p.stages.items()},
                }
            s['system'] = self._system()
            self._cache, self._cache_t = s, now
            return s

    def _system(self):
        out = {}
        try:
            import psutil
            out['cpu'] = psutil.cpu_percent(interval=None)
            out['ram'] = psutil.virtual_memory().percent
        except Exception:
            pass
        wd = self.cfg['work_dir']
        try:
            out['disk_free_gb'] = shutil.disk_usage(wd if wd.exists() else wd.parent).free / 2**30
        except Exception:
            pass
        return out


def _make_handler(source: StatsSource):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype: str):
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            try:
                if self.path == '/healthz':
                    self._send(b'ok', 'text/plain')
                elif self.path in ('/', '/index.html'):
                    self._send(PAGE.encode('utf-8'), 'text/html; charset=utf-8')
                elif self.path == '/stats.json':
                    self._send(json.dumps(source.stats(), default=str).encode(), 'application/json')
                elif self.path == '/events':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/event-stream')
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('X-Accel-Buffering', 'no')  # reverse proxies (tailscale serve): don't buffer
                    self.end_headers()
                    while True:
                        self.wfile.write(f"data: {json.dumps(source.stats(), default=str)}\n\n".encode())
                        self.wfile.flush()
                        time.sleep(2)
                else:
                    self.send_error(404)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
    return Handler


def start_dashboard(source: StatsSource, host: str, port: int, log) -> bool:
    """Starts the server in a daemon thread; on bind failure logs a warning and the pipeline continues."""
    try:
        srv = ThreadingHTTPServer((host, port), _make_handler(source))
    except OSError as e:
        log.warn(f"Dashboard disabled (cannot bind {host}:{port}: {e})")
        return False
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True, name='dashboard').start()
    if host in ('0.0.0.0', '', '::'):
        public = os.getenv('LSAIW_PUBLIC_URL')
        log.info(f"Dashboard listening on all interfaces, port {port}"
                 + (f" (open {public})" if public else ''))
    else:
        log.info(f"Dashboard: http://{host}:{port} (this machine only; --host 0.0.0.0 to share)")
    return True


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LSAIW Pipeline</title>
<style>
:root{--bg:#fafaf9;--card:#fff;--fg:#1c1917;--mute:#78716c;--line:#e7e5e4;--acc:#2563eb;--ok:#16a34a;--warn:#d97706;--bad:#dc2626}
@media (prefers-color-scheme:dark){:root{--bg:#0c0a09;--card:#1c1917;--fg:#f5f5f4;--mute:#a8a29e;--line:#292524;--acc:#60a5fa;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;padding:16px}
h1{font-size:18px;margin:0 0 4px}.sub{color:var(--mute);margin-bottom:14px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(160px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;min-width:0}
.k{color:var(--mute);font-size:12px}.v{font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}
.wide{grid-column:1/-1}.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%;background:var(--acc)}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}td,th{padding:4px 6px;border-bottom:1px solid var(--line);text-align:right}
td:first-child,th:first-child{text-align:left}pre{margin:0;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow:auto}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--warn);margin-right:6px}.dot.on{background:var(--ok)}
svg{width:100%;height:120px;display:block}
</style></head><body>
<h1>LSAIW pipeline</h1><div class="sub"><span id="dot" class="dot"></span><span id="phase">connecting…</span> · updated <span id="now">-</span></div>
<div class="grid">
 <div class="card wide"><div class="k">Progress</div><div class="v" id="prog">-</div><div class="bar"><i id="pbar" style="width:0"></i></div><div class="k" id="eta"></div></div>
 <div class="card"><div class="k">Done / skipped / failed</div><div class="v" id="dsf">-</div></div>
 <div class="card"><div class="k">Throughput</div><div class="v" id="rate">-</div></div>
 <div class="card"><div class="k">Findings / KLOC</div><div class="v" id="fpk">-</div></div>
 <div class="card"><div class="k">AI markers (random stratum)</div><div class="v" id="ai">-</div></div>
 <div class="card"><div class="k">Scanned random / ai stratum</div><div class="v" id="strata">-</div></div>
 <div class="card"><div class="k">Screened candidates with AI</div><div class="v" id="scr">-</div></div>
 <div class="card"><div class="k">Findings (high)</div><div class="v" id="find">-</div></div>
 <div class="card"><div class="k">Dep vulns (date-filtered)</div><div class="v" id="deps">-</div></div>
 <div class="card"><div class="k">CPU / RAM / work-dir free</div><div class="v" id="sys">-</div></div>
 <div class="card"><div class="k">GitHub API left</div><div class="v" id="gh">-</div></div>
 <div class="card wide"><div class="k">Findings / KLOC by creation month, random stratum (dashed = LLM releases)</div><svg id="spark" viewBox="0 0 600 120" preserveAspectRatio="none"></svg></div>
 <div class="card wide"><div class="k">Raw correlations (refreshed every 30 s)</div><table id="corr"></table></div>
 <div class="card"><div class="k">Stage queues / in-flight / workers</div><table id="queues"></table></div>
 <div class="card"><div class="k">Errors by stage</div><table id="errs"></table></div>
 <div class="card wide"><div class="k">Collecting</div><div id="coll">-</div></div>
 <div class="card wide"><div class="k">Log</div><pre id="log"></pre></div>
</div>
<script>
const $=id=>document.getElementById(id), f=(x,d=2)=>x==null?'–':Number(x).toFixed(d), n=x=>x==null?'–':Number(x).toLocaleString();
function rows(el,head,data){el.innerHTML='<tr>'+head.map(h=>'<th>'+h+'</th>').join('')+'</tr>'+data.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')}
function spark(m,events){const s=$('spark');if(!m.length){s.innerHTML='';return}
 const W=600,H=120,mx=Math.max(...m.map(x=>x.fpk))||1,X=i=>m.length<2?W/2:i*W/(m.length-1),Y=v=>H-6-(v/mx)*(H-12);
 let g=events.map(e=>{const i=m.findIndex(x=>x.month>=e.month);return i<0?'':`<line x1="${X(i)}" x2="${X(i)}" y1="0" y2="${H}" stroke="currentColor" stroke-opacity=".35" stroke-dasharray="3 3"><title>${e.month} ${e.name}</title></line>`}).join('');
 g+=`<polyline fill="none" stroke="var(--acc)" stroke-width="2" vector-effect="non-scaling-stroke" points="${m.map((x,i)=>X(i)+','+Y(x.fpk)).join(' ')}"/>`;
 s.innerHTML=g}
function render(s){
 const st=s.status||{},r=s.run,t=s.totals;$('now').textContent=s.now;$('phase').textContent=r?r.phase:'viewer (no pipeline attached)';
 if(r){$('prog').textContent=n(r.finished)+' / '+n(r.target);$('pbar').style.width=Math.min(100,100*r.finished/Math.max(1,r.target))+'%';
  $('eta').textContent='elapsed '+f(r.elapsed_h,1)+' h · ETA '+(r.eta_h==null?'–':f(r.eta_h,1)+' h');$('rate').textContent=f(r.rate_per_min,1)+'/min';
  $('gh').textContent=n(r.gh_remaining);$('coll').textContent=r.collecting||'—';
  rows($('queues'),['stage','queue','busy','workers'],[['snapshot',r.queues['to clone'],r.inflight.snapshot,r.workers.snapshot],['semgrep',r.queues['to semgrep'],r.inflight.semgrep,r.workers.semgrep],['deps/OSV',r.queues['to OSV'],r.inflight.deps,r.workers.deps]]);
 }else{$('prog').textContent=n(st.done||0)+' done';}
 $('dsf').textContent=n(st.done||0)+' / '+n(st.skipped||0)+' / '+n(st.failed||0);
 $('fpk').textContent=f(t.findings_per_kloc,3);$('ai').textContent=f(100*t.ai_share,1)+'%';
 $('strata').textContent=n((t.strata||{}).random||0)+' / '+n((t.strata||{}).ai||0);
 $('scr').textContent=t.screened?f(100*t.screened_ai/t.screened,1)+'% of '+n(t.screened):'–';
 $('find').textContent=n(t.findings)+' ('+n(t.high)+')';$('deps').textContent=n(t.dep_vulns);
 $('sys').textContent=f(s.system.cpu,0)+'% / '+f(s.system.ram,0)+'% / '+f(s.system.disk_free_gb,0)+' GB';
 rows($('corr'),['measure','Pearson r','Spearman ρ','n'],Object.entries(s.corr||{}).map(([k,v])=>[k,f(v.r,3),f(v.rho,3),n(v.n)]));
 rows($('errs'),['stage','count'],Object.entries(s.errors||{}));
 spark(s.monthly||[],s.events||[]);$('log').textContent=(s.log||[]).slice().reverse().join('\n');}
let es;function poll(){fetch('/stats.json').then(r=>r.json()).then(render).catch(()=>{}).finally(()=>setTimeout(poll,3000))}
try{es=new EventSource('/events');es.onopen=()=>$('dot').classList.add('on');es.onmessage=e=>render(JSON.parse(e.data));
 es.onerror=()=>{$('dot').classList.remove('on');es.close();poll()}}catch(e){poll()}
</script></body></html>"""
