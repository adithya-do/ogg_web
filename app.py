#!/usr/bin/env python3
"""
OGG Web Monitor & Control — Local-only (same server)
- Multiple local GoldenGate homes (YAML or auto-discovery fallback)
- Status: Manager + processes with 10s auto-refresh
- Controls: Start/Stop MGR, Start/Stop/Kill extracts/replicats, bulk start/stop
- Params editor (dirprm/*.prm) with timestamped backups
- ADD TRANDATA via DBLOGIN (prefers useridalias)
- Diagnostics: /api/health, /api/debug
- Plain fallback at /simple
Run as the same OS user that owns OGG (e.g., 'oracle').
"""

import os, re, time, shutil, subprocess, json
from typing import Dict, Any, List, Tuple
from flask import Flask, request, jsonify, Response, make_response
import yaml

APP_TITLE   = "OGG Web Monitor & Control (Local)"
CONFIG_PATH = os.environ.get("OGG_WEB_CONFIG", "/opt/oracle/ogg_web/config/ogg_local.yaml")
LISTEN_HOST = os.environ.get("OGG_WEB_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("OGG_WEB_PORT", "5000"))
POLL_SECONDS= int(os.environ.get("OGG_POLL_SECONDS", "10"))

# Where to try discovering ggsci when YAML is missing/empty
DISCOVERY_ROOTS = ["/u01","/u02","/u03","/opt/oracle","/opt/ogg","/opt"]

app = Flask(__name__)

# ------------------------------ Helpers ------------------------------

def _json_no_cache(payload, code=200):
    r = make_response(json.dumps(payload), code)
    r.mimetype = "application/json"
    r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return r

# ------------------------------ Config & discovery ------------------------------

def load_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Config not found: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if "homes" not in data or not isinstance(data["homes"], list):
        raise ValueError("config must contain a 'homes' list")
    return data

def discover_homes(max_hits:int=6) -> List[Dict[str, Any]]:
    homes: List[Dict[str, Any]] = []
    # PATH-based discovery
    for p in os.environ.get("PATH","").split(":"):
        exe = os.path.join(p, "ggsci")
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            gh = os.path.dirname(exe)
            if all(h.get("gg_home") != gh for h in homes):
                homes.append({"name": os.path.basename(gh) or gh, "gg_home": gh})
    # Shallow search common roots
    for root in DISCOVERY_ROOTS:
        for d, subdirs, files in os.walk(root):
            depth = d.count(os.sep) - root.count(os.sep)
            if depth > 4:
                subdirs[:] = []
                continue
            if "ggsci" in files:
                gh = d
                if all(h.get("gg_home") != gh for h in homes):
                    homes.append({"name": os.path.basename(gh) or gh, "gg_home": gh})
                    if len(homes) >= max_hits: break
        if len(homes) >= max_hits: break
    return homes

def attach_defaults(homes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach ORACLE_HOME/TNS_ADMIN defaults so actions can work even when YAML is minimal."""
    ORACLE_HOME = os.environ.get("ORACLE_HOME", "").rstrip("/")
    TNS_ADMIN  = os.environ.get("TNS_ADMIN", (ORACLE_HOME + "/network/admin" if ORACLE_HOME else ""))
    out = []
    for h in homes:
        gh   = (h.get("gg_home") or "").rstrip("/")
        name = h.get("name") or os.path.basename(gh) or gh
        out.append({
            "name": name,
            "gg_home": gh,
            "oracle_home": h.get("oracle_home", ORACLE_HOME),
            "tns_admin":   h.get("tns_admin", TNS_ADMIN),
            "db_name":     h.get("db_name", ""),
            "useridalias": h.get("useridalias", ""),
            "show_lag":    h.get("show_lag", False),
        })
    return out

def _find_home(home_name: str) -> Dict[str, Any]:
    # Prefer config (if available), else discovery with defaults
    try:
        cfg = load_config()
        for h in cfg["homes"]:
            nm = h.get("name") or h.get("gg_home")
            if home_name == nm:
                return h
    except Exception:
        pass
    for h in attach_defaults(discover_homes()):
        nm = h.get("name") or h.get("gg_home")
        if home_name == nm:
            return h
    raise KeyError("Home not found")

# ------------------------------ ggsci helpers ------------------------------

def _build_env(home: Dict[str, Any]) -> Dict[str, str]:
    env = os.environ.copy()
    gg_home = home["gg_home"].rstrip("/")
    oracle_home = home.get("oracle_home","").rstrip("/")
    if not oracle_home:
        raise RuntimeError("oracle_home not set (set YAML or export ORACLE_HOME)")
    tns_admin = home.get("tns_admin") or (oracle_home + "/network/admin")
    path_extra = home.get("path_extra", "")
    env["OGG_HOME"] = gg_home
    env["ORACLE_HOME"] = oracle_home
    env["TNS_ADMIN"] = tns_admin
    env["PATH"] = f"{gg_home}:{oracle_home}/bin:{path_extra}:{env.get('PATH','')}" if path_extra else f"{gg_home}:{oracle_home}/bin:{env.get('PATH','')}"
    env["LD_LIBRARY_PATH"] = f"{oracle_home}/lib:{env.get('LD_LIBRARY_PATH','')}"
    return env

def _run_ggsci(home: Dict[str, Any], lines: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    env = _build_env(home)
    ggsci = os.path.join(home["gg_home"], "ggsci")
    script = "\n".join(lines) + "\n"
    try:
        p = subprocess.run([ggsci], input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=env, check=False)
        return p.returncode, p.stdout.decode(errors="ignore"), p.stderr.decode(errors="ignore")
    except FileNotFoundError:
        return 1, "", f"ggsci not found at {ggsci}"
    except subprocess.TimeoutExpired:
        return 124, "", "ggsci command timed out"

# ------------------------------ Parsers ------------------------------

MANAGER_STATUS_RE = re.compile(r"Manager\s+is\s+(RUNNING|DOWN)!?", re.IGNORECASE)
PROC_LINE_RE = re.compile(
    r"^(EXTRACT|REPLICAT)\s+(?:(?:\w\w)\s+)?([A-Za-z0-9_\-\.]+)\s+(RUNNING|STOPPED|ABENDED|STARTING|STOPPING|RETRYING)(?:\s+([0-9: \-]+))?",
    re.IGNORECASE
)
LAG_LINE_RE = re.compile(r"Lag\s+at\s+Chkpt\s*:\s*([0-9:]+|[0-9]+\s*seconds|None)", re.IGNORECASE)
SINCE_LINE_RE = re.compile(r"Time\s+Since\s+Chkpt\s*:\s*([0-9:]+|[0-9]+\s*seconds|None)", re.IGNORECASE)

def _parse_info_all(text: str) -> Dict[str, Any]:
    lines = [ln.rstrip() for ln in text.splitlines()]
    manager = None
    procs: List[Dict[str, Any]] = []
    for ln in lines:
        m = MANAGER_STATUS_RE.search(ln)
        if m:
            manager = m.group(1).upper()
            continue
        p = PROC_LINE_RE.match(ln.strip())
        if p:
            procs.append({
                "type": p.group(1).upper(),
                "name": p.group(2),
                "status": p.group(3).upper(),
                "lag": None,
                "since": None,
            })
    return {"manager": manager, "processes": procs}

def _augment_lag(home: Dict[str, Any], procs: List[Dict[str, Any]], timeout: int = 20) -> None:
    for pr in procs:
        if pr.get("status") != "RUNNING":
            continue
        rc, out, _ = _run_ggsci(home, [f"info {pr['name']}"], timeout=timeout)
        if rc != 0:
            continue
        lag_m = LAG_LINE_RE.search(out)
        since_m = SINCE_LINE_RE.search(out)
        pr["lag"] = (lag_m.group(1) if lag_m else None)
        pr["since"] = (since_m.group(1) if since_m else None)

# ------------------------------ API ------------------------------

@app.get("/api/health")
def api_health():
    info = {"config_path": CONFIG_PATH, "exists": os.path.exists(CONFIG_PATH)}
    try:
        cfg = load_config()
        info["homes_count"] = len(cfg.get("homes", []))
    except Exception as e:
        info["error"] = str(e)
    return _json_no_cache(info)

@app.get("/api/homes")
def api_homes():
    source="config"; err=None; homes=[]
    try:
        cfg=load_config()
        homes=[{
            "name":h.get("name") or h.get("gg_home"),
            "gg_home":h.get("gg_home"),
            "oracle_home":h.get("oracle_home",""),
            "tns_admin":h.get("tns_admin",""),
            "useridalias":h.get("useridalias",""),
            "show_lag":h.get("show_lag",False)
        } for h in cfg["homes"]]
    except Exception as e:
        source="discovery"; err=str(e); homes=attach_defaults(discover_homes())
    return _json_no_cache({"homes":homes,"source":source,"error":err,"config_path":CONFIG_PATH})

@app.get("/api/debug")
def api_debug():
    dbg = {
        "config_path": CONFIG_PATH,
        "exists": os.path.exists(CONFIG_PATH),
        "time": time.ctime(),
        "env_ORACLE_HOME": os.environ.get("ORACLE_HOME",""),
        "env_TNS_ADMIN": os.environ.get("TNS_ADMIN",""),
    }
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            dbg["config_head"] = "".join(f.readlines()[:60])
    except Exception as e:
        dbg["config_head_err"] = str(e)
    try:
        cfg = load_config()
        dbg["cfg_homes_count"] = len(cfg.get("homes", []))
        dbg["cfg_homes"] = cfg.get("homes", [])
    except Exception as e:
        dbg["cfg_error"] = str(e)
        dbg["discovered"] = attach_defaults(discover_homes())
    return _json_no_cache(dbg)

@app.get("/api/status")
def api_status():
    home_name = request.args.get("home")
    if not home_name:
        return _json_no_cache({"error": "home is required"}, 400)
    try:
        home = _find_home(home_name)
    except Exception as e:
        return _json_no_cache({"error": str(e)}, 404)

    rc1, mgr_out, _ = _run_ggsci(home, ["info mgr"], timeout=20)
    m = MANAGER_STATUS_RE.search(mgr_out or "")
    manager = m.group(1).upper() if m else None

    rc2, out, err = _run_ggsci(home, ["info all"], timeout=40)
    parsed = _parse_info_all(out)
    if manager is None:
        manager = parsed.get("manager")
    procs = parsed.get("processes", [])
    if home.get("show_lag"):
        _augment_lag(home, procs, timeout=20)
    return _json_no_cache({"manager": manager, "processes": procs})

@app.post("/api/control")
def api_control():
    data = request.get_json(force=True)
    for k in ("home","target_type","action"):
        if not data.get(k):
            return _json_no_cache({"error": f"Missing field: {k}"}, 400)
    try:
        home = _find_home(data["home"])
    except Exception as e:
        return _json_no_cache({"error": str(e)}, 404)

    target_type = data["target_type"].lower()
    action = data["action"].lower()
    name = data.get("target_name")

    if target_type == "mgr":
        if   action == "start": cmd = "start mgr"
        elif action == "stop":  cmd = "stop mgr!"
        else: return _json_no_cache({"error": "Unsupported action for mgr"}, 400)
    else:
        if not name: return _json_no_cache({"error": "target_name is required for extract/replicat"}, 400)
        if   action == "start": cmd = f"start {name}"
        elif action == "stop":  cmd = f"stop {name}"
        elif action == "kill":  cmd = f"kill {name}"
        else: return _json_no_cache({"error": "Unsupported action"}, 400)

    rc, out, err = _run_ggsci(home, [cmd], timeout=30)
    return _json_no_cache({"ok": rc == 0, "output": out if out else err})

@app.post("/api/control_bulk")
def api_control_bulk():
    data = request.get_json(force=True)
    for k in ("home","type","action"):
        if not data.get(k):
            return _json_no_cache({"error": f"Missing field: {k}"}, 400)
    try:
        home = _find_home(data["home"])
    except Exception as e:
        return _json_no_cache({"error": str(e)}, 404)

    ptype = data["type"].lower()
    action = data["action"].lower()
    if ptype not in ("extract","replicat"):
        return _json_no_cache({"error": "type must be extract or replicat"}, 400)
    if action not in ("start","stop","kill"):
        return _json_no_cache({"error": "action must be start/stop/kill"}, 400)

    rc, out, err = _run_ggsci(home, ["info all"], timeout=40)
    if rc != 0:
        return _json_no_cache({"error": err or out or "info all failed"}, 502)
    procs = _parse_info_all(out).get("processes", [])

    targets = []
    for p in procs:
        if p.get("type","").lower() != ptype:
            continue
        st = p.get("status")
        if action == "start" and st != "RUNNING":
            targets.append(p["name"])
        elif action == "stop" and st != "STOPPED":
            targets.append(p["name"])
        elif action == "kill":
            targets.append(p["name"])

    if not targets:
        return _json_no_cache({"ok": True, "output": f"No {ptype} processes matched for action {action}"})

    cmds = [ ("start "+n) if action=="start" else ("stop "+n if action=="stop" else "kill "+n) for n in targets ]
    to = max(30, 5*len(cmds))
    rc2, out2, err2 = _run_ggsci(home, cmds, timeout=to)
    return _json_no_cache({"ok": rc2 == 0, "output": out2 if out2 else err2})

@app.get("/api/params")
def api_params_get():
    home_name = request.args.get("home")
    proc = request.args.get("proc")
    if not (home_name and proc):
        return _json_no_cache({"ok": False, "error": "home and proc are required"}, 400)
    try:
        home = _find_home(home_name)
    except Exception as e:
        return _json_no_cache({"ok": False, "error": str(e)}, 404)

    prm_path = f"{home['gg_home'].rstrip('/')}/dirprm/{proc.lower()}.prm"
    try:
        with open(prm_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return _json_no_cache({"ok": True, "content": content})
    except FileNotFoundError:
        return _json_no_cache({"ok": False, "error": f"Param file not found: {prm_path}"}, 404)
    except Exception as e:
        return _json_no_cache({"ok": False, "error": f"Read error: {e}"}, 502)

@app.post("/api/params")
def api_params_save():
    data = request.get_json(force=True)
    for k in ("home","proc","content"):
        if not data.get(k):
            return _json_no_cache({"ok": False, "error": f"Missing field: {k}"}, 400)
    try:
        home = _find_home(data["home"])
    except Exception as e:
        return _json_no_cache({"ok": False, "error": str(e)}, 404)

    prm_path = f"{home['gg_home'].rstrip('/')}/dirprm/{data['proc'].lower()}.prm"
    backup_path = f"{prm_path}.bak.{int(time.time())}"
    try:
        if os.path.exists(prm_path):
            shutil.copy2(prm_path, backup_path)
        with open(prm_path, 'w', encoding='utf-8') as f:
            f.write(data['content'])
        return _json_no_cache({"ok": True, "backup": backup_path})
    except Exception as e:
        return _json_no_cache({"ok": False, "error": f"Write error: {e}"}, 502)

@app.post("/api/add_trandata")
def api_add_trandata():
    data = request.get_json(force=True)
    for k in ("home","object"):
        if not data.get(k):
            return _json_no_cache({"error": f"Missing field: {k}"}, 400)
    try:
        home = _find_home(data["home"])
    except Exception as e:
        return _json_no_cache({"error": str(e)}, 404)

    obj = data["object"].strip()
    useridalias = data.get("useridalias") or home.get("useridalias")
    userid = data.get("userid")
    password = data.get("password")

    cmds = []
    if useridalias:
        cmds.append(f"dblogin useridalias {useridalias}")
    elif userid and password:
        cmds.append(f"dblogin userid {userid}, password {password}")
    else:
        return _json_no_cache({"error": "Provide useridalias (preferred) or userid/password"}, 400)

    cmds.append(f"add trandata {obj}")
    cmds.append("show trandata " + obj)

    rc, out, err = _run_ggsci(home, cmds, timeout=40)
    return _json_no_cache({"ok": rc == 0, "output": out if out else err})

# ------------------------------ UI ------------------------------

# NOTE: not an f-string; JS backticks `${...}` are safe.
INDEX_HTML_TMPL = """
<!doctype html>
<html lang='en'><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>__TITLE__</title>
<style>
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans'; margin:0; background:#0b1020; color:#e6eefc; }
header { padding:12px 16px; background:#0e1530; border-bottom:1px solid #1d2a52; display:flex; align-items:center; gap:12px; position:sticky; top:0; z-index:10; }
.tag { background:#12214a; color:#9ec5ff; padding:4px 8px; border-radius:999px; font-size:12px; }
.container { padding: 16px; }
.grid { display:grid; grid-template-columns: 280px 1fr; gap:16px; }
.card { background:#101833; border:1px solid #1a2750; border-radius:14px; box-shadow: 0 1px 0 rgba(255,255,255,0.04) inset; }
.card h3 { margin:0; padding:12px 14px; border-bottom:1px solid #1a2750; font-size:16px; color:#cfe2ff; }
.scroll { max-height: 70vh; overflow:auto; }
.home { padding:10px 12px; border-bottom:1px dashed #1a2750; cursor:pointer; }
.home:hover { background:#0f1730; }
table { width:100%; border-collapse: collapse; }
th, td { padding:8px 10px; border-bottom:1px solid #1a2750; font-size:14px; }
th { text-align:left; color:#9ec5ff; position:sticky; top:0; background:#101833; }
.ok { color:#47d147; font-weight:600; }
.warn { color:#ffd24d; font-weight:600; }
.bad { color:#ff6b6b; font-weight:700; }
.btn { background:#172552; color:#cfe2ff; border:1px solid #243a7a; padding:6px 10px; border-radius:10px; cursor:pointer; font-size:12px; }
.btn:hover { background:#1a2a5c; }
.btn.red { background:#4f1420; border-color:#7a2436; }
.btn.green { background:#0f3a26; border-color:#1a6b49; }
.toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:10px; align-items:center; }
.muted { color:#94a3b8; font-size:12px; }
textarea { width:100%; height: 50vh; background:#0a132c; color:#e6eefc; border:1px solid #1a2750; border-radius:12px; padding:10px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
.err { background:#2a1020; border:1px solid #7a2442; padding:8px; border-radius:10px; margin:6px 0; white-space:pre-wrap; display:none; }
</style></head>
<body>
<header>
  <div style="font-weight:700">__TITLE__</div>
  <div class="tag">Refresh: __POLL__s</div>
  <a href="/simple" style="margin-left:auto;color:#9ec5ff">Plain view</a>
  <a href="/api/debug" style="margin-left:8px;color:#9ec5ff">Debug JSON</a>
</header>
<div class="container">
  <div class="grid">
    <div class="card">
      <h3>GoldenGate Homes (local)</h3>
      <div id="homes" class="scroll"></div>
      <div id="homesErr" class="err"></div>
    </div>
    <div class="card">
      <h3 id="panelTitle">Status</h3>
      <div style="padding: 12px">
        <div class="toolbar">
          <button class="btn" onclick="refreshNow()">Manual Refresh</button>
          <button class="btn green" onclick="doBulk('extract','start')">Start All Extracts</button>
          <button class="btn" onclick="doBulk('extract','stop')">Stop All Extracts</button>
          <button class="btn green" onclick="doBulk('replicat','start')">Start All Replicats</button>
          <button class="btn" onclick="doBulk('replicat','stop')">Stop All Replicats</button>
          <span class="muted" id="lastRef">—</span>
        </div>
        <div id="statusArea"></div>
      </div>
    </div>
  </div>
</div>
<script>
let current = null;

function showHomesErr(msg) {
  const he = document.getElementById('homesErr');
  he.style.display = 'block';
  he.textContent = msg;
}

async function loadHomes() {
  const div = document.getElementById('homes');
  try {
    const r = await fetch('/api/homes', {cache:'no-store'});
    const data = await r.json();
    div.innerHTML = '';
    if (data.error) {
      showHomesErr(`Config error: ${data.error}\nConfig path: ${data.config_path || ''}`);
    }
    let list = data.homes || [];
    if ((!list || list.length === 0) && data.discovered && data.discovered.length > 0) {
      showHomesErr("Using auto-discovered homes (set ORACLE_HOME/TNS_ADMIN or YAML to enable controls).");
      list = data.discovered;
    }
    if (!list || list.length === 0) {
      showHomesErr(`No GoldenGate homes found.\nCheck ${data.config_path || 'config file'}.`);
      return;
    }
    list.forEach(home => {
      const hd = document.createElement('div');
      hd.className = 'home';
      hd.textContent = `• ${home.name}  —  ${home.gg_home || ''}`;
      hd.onclick = () => { current = {home: home.name}; refreshNow(); document.getElementById('panelTitle').textContent = `${home.name}`; };
      div.appendChild(hd);
    });
    if (!current && list.length > 0) {
      current = {home: list[0].name};
      document.getElementById('panelTitle').textContent = list[0].name;
      refreshNow();
    }
  } catch (e) {
    showHomesErr(`Failed to load homes: ${e}`);
  }
}

async function refreshNow() {
  if (!current) return;
  const qs = new URLSearchParams(current).toString();
  const r = await fetch('/api/status?' + qs, {cache:'no-store'});
  const data = await r.json();
  renderStatus(data);
  document.getElementById('lastRef').textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
}

function renderStatus(data) {
  const area = document.getElementById('statusArea');
  if (data.error) { area.innerHTML = `<div class="bad">${data.error}</div>`; return; }
  const mgrCls = (data.manager === 'RUNNING') ? 'ok' : 'bad';
  let html = '';
  html += `<div style="margin-bottom:10px">Manager: <span class="${mgrCls}">${data.manager || 'UNKNOWN'}</span>
    <span style="margin-left:10px">
      <button class="btn green" onclick="doAction('mgr','start')">Start MGR</button>
      <button class="btn red" onclick="doAction('mgr','stop')">Stop MGR</button>
    </span>
  </div>`;
  html += `<table>
    <thead><tr><th>Type</th><th>Name</th><th>Status</th><th>Lag</th><th>Since</th><th>Actions</th></tr></thead><tbody>`;
  (data.processes || []).forEach(p => {
    const cls = p.status === 'RUNNING' ? 'ok' : (p.status === 'ABENDED' ? 'bad' : 'warn');
    html += `<tr>
      <td>${p.type}</td>
      <td><code>${p.name}</code></td>
      <td class="${cls}">${p.status}</td>
      <td>${p.lag || ''}</td>
      <td>${p.since || ''}</td>
      <td>
        <button class="btn green" onclick="doAction('${p.type.toLowerCase()}','start','${p.name}')">Start</button>
        <button class="btn" onclick="doAction('${p.type.toLowerCase()}','stop','${p.name}')">Stop</button>
        <button class="btn red" onclick="doAction('${p.type.toLowerCase()}','kill','${p.name}')">Kill</button>
        <button class="btn" onclick="openParams('${p.name}')">Params</button>
      </td>
    </tr>`
  });
  html += `</tbody></table>`;

  html += `<div style="margin-top:12px; padding-top:12px; border-top:1px dashed #1a2750">
    <div style="font-weight:600; margin-bottom:6px">ADD TRANDATA</div>
    <input id="obj" placeholder="SCHEMA.TABLE" style="background:#0a132c;color:#e6eefc;border:1px solid #1a2750;border-radius:8px;padding:6px"/>
    <input id="alias" placeholder="useridalias (optional overrides config)" style="background:#0a132c;color:#e6eefc;border:1px solid #1a2750;border-radius:8px;padding:6px"/>
    <button class="btn" onclick="addTranData()">Run</button>
    <div class="muted">Uses DBLOGIN with useridalias when available.</div>
    <pre id="trandataOut" style="white-space:pre-wrap"></pre>
  </div>`;

  area.innerHTML = html;
}

async function doAction(targetType, action, targetName=null) {
  if (!current) return;
  const payload = { ...current, target_type: targetType, action: action };
  if (targetName) payload.target_name = targetName;
  const r = await fetch('/api/control', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const data = await r.json();
  alert((data.ok ? 'OK\\n' : 'ERR\\n') + (data.output || data.error || ''));
  refreshNow();
}

async function doBulk(ptype, action) {
  if (!current) return;
  const payload = { home: current.home, type: ptype, action: action };
  const r = await fetch('/api/control_bulk', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const data = await r.json();
  alert((data.ok ? 'OK\\n' : 'ERR\\n') + (data.output || data.error || ''));
  refreshNow();
}

async function openParams(procName) {
  if (!current) return;
  const qs = new URLSearchParams({...current, proc: procName}).toString();
  const r = await fetch('/api/params?' + qs);
  const data = await r.json();
  if (!data.ok) { alert('Error: ' + (data.error || '')); return; }
  const txt = prompt('Edit params for ' + procName + ' (will overwrite file). A backup will be created.', data.content);
  if (txt === null) return;
  const save = await fetch('/api/params', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({...current, proc: procName, content: txt})});
  const res = await save.json();
  alert(res.ok ? 'Saved' : 'Error: ' + (res.error || ''));
}

async function addTranData() {
  if (!current) return;
  const obj = document.getElementById('obj').value.trim();
  const alias = document.getElementById('alias').value.trim();
  if (!obj) { alert('Provide SCHEMA.TABLE'); return; }
  const payload = { ...current, object: obj };
  if (alias) payload.useridalias = alias;
  const r = await fetch('/api/add_trandata', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const data = await r.json();
  document.getElementById('trandataOut').textContent = data.output || data.error || '';
}

setInterval(() => { if (current) refreshNow(); }, __POLL__ * 1000);
loadHomes();
</script>
</body></html>
"""

SIMPLE_HTML = """<!doctype html><meta charset='utf-8'><title>Homes list</title>
<pre id='out'>Loading...</pre>
<script>
fetch('/api/homes',{cache:'no-store'}).then(r=>r.json()).then(d=>{
  document.getElementById('out').textContent = JSON.stringify(d,null,2);
}).catch(e=>{document.getElementById('out').textContent='ERR '+e});
</script>"""

# Fill placeholders safely (no f-strings!)
INDEX_HTML = INDEX_HTML_TMPL.replace("__TITLE__", APP_TITLE).replace("__POLL__", str(POLL_SECONDS))

# ------------------------------ UI routes ------------------------------

@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.get("/simple")
def simple():
    return Response(SIMPLE_HTML, mimetype="text/html")

# ------------------------------ Main ------------------------------

if __name__ == "__main__":
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    print(f"* {APP_TITLE} http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"* Using config: {CONFIG_PATH}")
    try:
        with open(CONFIG_PATH,'r',encoding='utf-8') as f:
            print('* Config head:\n'+''.join(f.readlines()[:30]))
    except Exception as e:
        print(f"* Config read issue: {e}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
