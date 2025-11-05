#!/usr/bin/env python3
"""
OGG Web Monitor & Control — Local‑only (same server) edition
===========================================================

What this does (MVP)
--------------------
* Monitors Oracle GoldenGate **on the same Linux server** where this app runs.
* Supports **multiple GoldenGate homes** on this server.
* Starts/stops **Manager, Extract, Replicat**; can **kill** a process.
* Views/edits **dirprm/*.prm** files with automatic timestamped backups.
* Runs **ADD TRANDATA** using `DBLOGIN useridalias` (preferred) or userid/password.
* Exports `OGG_HOME`, `ORACLE_HOME`, `TNS_ADMIN`, `PATH`, `LD_LIBRARY_PATH` per home before running **ggsci**.
* Auto‑refreshes status every **10 seconds**.
* Runs under the **same OS user** who owns GoldenGate (e.g., `oracle`). **No SSH. No sudo.**

Quick start
-----------
1) Log in as the OGG owner (e.g., `oracle`). Place this file at `/opt/ogg_web/app.py`.
2) Create config: `/opt/ogg_web/config/ogg_local.yaml` using the sample below.
3) Create venv & install deps:
   ```bash
   cd /opt/ogg_web
   python3 -m venv .venv && source .venv/bin/activate
   pip install flask==3.0.3 pyyaml==6.0.2
   ```
4) Run the app:
   ```bash
   OGG_WEB_CONFIG=/opt/ogg_web/config/ogg_local.yaml \
   OGG_WEB_PORT=5000 \
   python app.py
   ```
   Open `http://<server>:5000` from your desktop on the same network.

Config file: /opt/ogg_web/config/ogg_local.yaml (sample)
-------------------------------------------------------
# Minimal single‑server config: list your local GG homes
homes:
  - name: OGG19
    gg_home: /u01/app/ogg/19.1.0
    oracle_home: /u01/app/oracle/product/19.3.0/dbhome_1
    tns_admin: /u01/app/oracle/product/19.3.0/dbhome_1/network/admin
    db_name: PRODDB
    useridalias: OGG_PRODDB            # preferred for DBLOGIN
    path_extra: /usr/bin               # optional
    show_lag: false                    # set true to call `info <proc>` for lag/since
  - name: OGG21
    gg_home: /u01/app/ogg/21.8.0
    oracle_home: /u01/app/oracle/product/19.3.0/dbhome_1
    tns_admin: /u01/app/oracle/product/19.3.0/dbhome_1/network/admin
    db_name: PRODDB
    useridalias: OGG_PRODDB

Notes & security
----------------
* Run this service **as the OGG owner user** (e.g., `oracle`). It reads/writes files under your GG homes.
* No SSH keys or sudo needed.
* For production, put it behind **Nginx** with basic auth and TLS.

"""

from __future__ import annotations
import os
import re
import time
import json
import shutil
import subprocess
from typing import Dict, Any, List, Tuple
from flask import Flask, request, jsonify, Response
import yaml

APP_TITLE = "OGG Web Monitor & Control (Local)"
CONFIG_PATH = os.environ.get("OGG_WEB_CONFIG", os.path.join(os.path.dirname(__file__), "config", "ogg_local.yaml"))
LISTEN_HOST = os.environ.get("OGG_WEB_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("OGG_WEB_PORT", "5000"))
POLL_SECONDS = int(os.environ.get("OGG_POLL_SECONDS", "10"))

app = Flask(__name__)

# ------------------------------
# Config
# ------------------------------

def load_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Config not found: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if "homes" not in data or not isinstance(data["homes"], list):
        raise ValueError("config must contain a 'homes' list")
    return data

# ------------------------------
# Local ggsci execution helpers
# ------------------------------

def _build_env(home: Dict[str, Any]) -> Dict[str, str]:
    env = os.environ.copy()
    gg_home = home["gg_home"].rstrip("/")
    oracle_home = home["oracle_home"].rstrip("/")
    tns_admin = home.get("tns_admin", f"{oracle_home}/network/admin")
    path_extra = home.get("path_extra", "")
    env["OGG_HOME"] = gg_home
    env["ORACLE_HOME"] = oracle_home
    env["TNS_ADMIN"] = tns_admin
    base_path = f"{gg_home}:{oracle_home}/bin:{env.get('PATH','')}"
    if path_extra:
        base_path = f"{gg_home}:{oracle_home}/bin:{path_extra}:{env.get('PATH','')}"
    env["PATH"] = base_path
    env["LD_LIBRARY_PATH"] = f"{oracle_home}/lib:{env.get('LD_LIBRARY_PATH','')}"
    return env


def _run_ggsci(home: Dict[str, Any], lines: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Run ggsci locally and feed commands via STDIN. We set env per home."""
    env = _build_env(home)
    ggsci = os.path.join(home["gg_home"], "ggsci")
    script = "\n".join(lines) + "\n"
    try:
        proc = subprocess.run(
            [ggsci], input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, env=env, check=False
        )
        return proc.returncode, proc.stdout.decode(errors="ignore"), proc.stderr.decode(errors="ignore")
    except FileNotFoundError as e:
        return 1, "", f"ggsci not found at {ggsci}"
    except subprocess.TimeoutExpired:
        return 124, "", "ggsci command timed out"

# ------------------------------
# Parsers for 'info all' and friends
# ------------------------------
MANAGER_STATUS_RE = re.compile(r"Manager\s+is\s+(RUNNING|DOWN)!?", re.IGNORECASE)
PROC_LINE_RE = re.compile(
    r"^(EXTRACT|REPLICAT)\s+(?:(?:\w\w)\s+)?([A-Za-z0-9_\-\.]+)\s+(RUNNING|STOPPED|ABENDED|STARTING|STOPPING|RETRYING)(?:\s+([0-9: \-]+))?",
    re.IGNORECASE)
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
        rc, out, _ = _run_ggsci(home, [f"info {pr['name']}"] , timeout=timeout)
        if rc != 0:
            continue
        lag_m = LAG_LINE_RE.search(out)
        since_m = SINCE_LINE_RE.search(out)
        pr["lag"] = (lag_m.group(1) if lag_m else None)
        pr["since"] = (since_m.group(1) if since_m else None)

# ------------------------------
# UI (single page)
# ------------------------------
INDEX_HTML = f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\"/>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{APP_TITLE}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans'; margin:0; background:#0b1020; color:#e6eefc; }}
    header {{ padding:12px 16px; background:#0e1530; border-bottom:1px solid #1d2a52; display:flex; align-items:center; gap:12px; position:sticky; top:0; z-index:10; }}
    .tag {{ background:#12214a; color:#9ec5ff; padding:4px 8px; border-radius:999px; font-size:12px; }}
    .container {{ padding: 16px; }}
    .grid {{ display:grid; grid-template-columns: 280px 1fr; gap:16px; }}
    .card {{ background:#101833; border:1px solid #1a2750; border-radius:14px; box-shadow: 0 1px 0 rgba(255,255,255,0.04) inset; }}
    .card h3 {{ margin:0; padding:12px 14px; border-bottom:1px solid #1a2750; font-size:16px; color:#cfe2ff; }}
    .scroll {{ max-height: 70vh; overflow:auto; }}
    .home {{ padding:10px 12px; border-bottom:1px dashed #1a2750; cursor:pointer; }}
    .home:hover {{ background:#0f1730; }}
    table {{ width:100%; border-collapse: collapse; }}
    th, td {{ padding:8px 10px; border-bottom:1px solid #1a2750; font-size:14px; }}
    th {{ text-align:left; color:#9ec5ff; position:sticky; top:0; background:#101833; }}
    .ok {{ color:#47d147; font-weight:600; }}
    .warn {{ color:#ffd24d; font-weight:600; }}
    .bad {{ color:#ff6b6b; font-weight:700; }}
    .btn {{ background:#172552; color:#cfe2ff; border:1px solid #243a7a; padding:6px 10px; border-radius:10px; cursor:pointer; font-size:12px; }}
    .btn:hover {{ background:#1a2a5c; }}
    .btn.red {{ background:#4f1420; border-color:#7a2436; }}
    .btn.green {{ background:#0f3a26; border-color:#1a6b49; }}
    .toolbar {{ display:flex; gap:8px; margin-bottom:10px; align-items:center; }}
    .muted {{ color:#94a3b8; font-size:12px; }}
    textarea {{ width:100%; height: 50vh; background:#0a132c; color:#e6eefc; border:1px solid #1a2750; border-radius:12px; padding:10px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace; }}
    .row-actions button {{ margin-right:6px; }}
  </style>
</head>
<body>
<header>
  <div style=\"font-weight:700\">{APP_TITLE}</div>
  <div class=\"tag\">Refresh: {POLL_SECONDS}s</div>
</header>
<div class=\"container\">
  <div class=\"grid\">
    <div class=\"card\">
      <h3>GoldenGate Homes (local)</h3>
      <div id=\"homes\" class=\"scroll\"></div>
    </div>
    <div class=\"card\">
      <h3 id=\"panelTitle\">Status</h3>
      <div style=\"padding: 12px\">
        <div class=\"toolbar\">
          <button class=\"btn\" onclick=\"refreshNow()\">Manual Refresh</button>
          <span class=\"muted\" id=\"lastRef\">—</span>
        </div>
        <div id=\"statusArea\"></div>
      </div>
    </div>
  </div>
</div>
<script>
let current = null; // {home}

async function loadHomes() {
  const r = await fetch('/api/homes');
  const data = await r.json();
  const div = document.getElementById('homes');
  div.innerHTML = '';
  data.homes.forEach(home => {
    const hd = document.createElement('div');
    hd.className = 'home';
    hd.textContent = `• ${home.name}  —  ${home.gg_home}`;
    hd.onclick = () => { current = {home: home.name}; refreshNow(); document.getElementById('panelTitle').textContent = `${home.name}`; };
    div.appendChild(hd);
  });
}

async function refreshNow() {
  if (!current) return;
  const qs = new URLSearchParams(current).toString();
  const r = await fetch('/api/status?' + qs);
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
    <span class="row-actions">
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
  alert((data.ok ? 'OK\n' : 'ERR\n') + (data.output || data.error || ''));
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

setInterval(() => { if (current) refreshNow(); }, {POLL_SECONDS} * 1000);
loadHomes();
</script>
</body>
</html>
"""

# ------------------------------
# Flask routes
# ------------------------------
@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.get("/api/homes")
def list_homes():
    cfg = load_config()
    homes = [{"name": h.get("name") or h.get("gg_home"), "gg_home": h.get("gg_home")} for h in cfg["homes"]]
    return jsonify({"homes": homes})


def _find_home(home_name: str) -> Dict[str, Any]:
    cfg = load_config()
    for h in cfg["homes"]:
        if home_name == (h.get("name") or h.get("gg_home")):
            return h
    raise KeyError("Home not found in config")

@app.get("/api/status")
def api_status():
    home_name = request.args.get("home")
    if not home_name:
        return jsonify({"error": "home is required"}), 400
    try:
        home = _find_home(home_name)
    except Exception as e:
        return jsonify({"error": str(e)}), 404

    # info mgr for manager status
    rc1, mgr_out, _ = _run_ggsci(home, ["info mgr"], timeout=25)
    manager = None
    m = MANAGER_STATUS_RE.search(mgr_out or "")
    if m: manager = m.group(1).upper()

    # info all for process list
    rc2, out, err = _run_ggsci(home, ["info all"], timeout=25)
    parsed = _parse_info_all(out)
    if manager is None:
        manager = parsed.get("manager")
    procs = parsed.get("processes", [])

    if home.get("show_lag"):
        _augment_lag(home, procs, timeout=20)

    return jsonify({"manager": manager, "processes": procs})

@app.post("/api/control")
def api_control():
    data = request.get_json(force=True)
    for k in ("home","target_type","action"):
        if not data.get(k):
            return jsonify({"error": f"Missing field: {k}"}), 400
    try:
        home = _find_home(data["home"])
    except Exception as e:
        return jsonify({"error": str(e)}), 404

    target_type = data["target_type"].lower()  # 'mgr' | 'extract' | 'replicat'
    action = data["action"].lower()           # 'start' | 'stop' | 'kill'
    name = data.get("target_name")

    if target_type == "mgr":
        if action == "start": cmd = "start mgr"
        elif action == "stop": cmd = "stop mgr!"
        else: return jsonify({"error": "Unsupported action for mgr"}), 400
    else:
        if not name: return jsonify({"error": "target_name is required for extract/replicat"}), 400
        if action == "start": cmd = f"start {name}"
        elif action == "stop": cmd = f"stop {name}"
        elif action == "kill": cmd = f"kill {name}"
        else: return jsonify({"error": "Unsupported action"}), 400

    rc, out, err = _run_ggsci(home, [cmd], timeout=30)
    return jsonify({"ok": rc == 0, "output": out if out else err})

@app.get("/api/params")
def api_params_get():
    home_name = request.args.get("home")
    proc = request.args.get("proc")
    if not (home_name and proc):
        return jsonify({"ok": False, "error": "home and proc are required"}), 400
    try:
        home = _find_home(home_name)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404

    prm_path = f"{home['gg_home'].rstrip('/')}/dirprm/{proc.lower()}.prm"
    try:
        with open(prm_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return jsonify({"ok": True, "content": content})
    except FileNotFoundError:
        return jsonify({"ok": False, "error": f"Param file not found: {prm_path}"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": f"Read error: {e}"}), 502

@app.post("/api/params")
def api_params_save():
    data = request.get_json(force=True)
    for k in ("home","proc","content"):
        if not data.get(k):
            return jsonify({"ok": False, "error": f"Missing field: {k}"}), 400
    try:
        home = _find_home(data["home"])
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404

    prm_path = f"{home['gg_home'].rstrip('/')}/dirprm/{data['proc'].lower()}.prm"
    backup_path = f"{prm_path}.bak.{int(time.time())}"
    try:
        if os.path.exists(prm_path):
            shutil.copy2(prm_path, backup_path)
        with open(prm_path, 'w', encoding='utf-8') as f:
            f.write(data['content'])
        return jsonify({"ok": True, "backup": backup_path})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Write error: {e}"}), 502

@app.post("/api/add_trandata")
def api_add_trandata():
    data = request.get_json(force=True)
    for k in ("home","object"):
        if not data.get(k):
            return jsonify({"error": f"Missing field: {k}"}), 400
    try:
        home = _find_home(data["home"])
    except Exception as e:
        return jsonify({"error": str(e)}), 404

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
        return jsonify({"error": "Provide useridalias (preferred) or userid/password"}), 400

    cmds.append(f"add trandata {obj}")
    cmds.append("show trandata " + obj)

    rc, out, err = _run_ggsci(home, cmds, timeout=40)
    return jsonify({"ok": rc == 0, "output": out if out else err})

# ------------------------------
# Main
# ------------------------------
if __name__ == "__main__":
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    print(f"* Starting {APP_TITLE} on http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"* Using config: {CONFIG_PATH}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)

"""
Production (Gunicorn + Nginx) quick notes
-----------------------------------------
1) Gunicorn (inside venv):
   $ pip install gunicorn
   $ /opt/ogg_web/.venv/bin/gunicorn -w 3 -b 127.0.0.1:8080 app:app

2) Systemd unit `/etc/systemd/system/ogg-web.service`:
   [Unit]
   Description=OGG Web Monitor & Control (Local)
   After=network.target

   [Service]
   User=oracle
   WorkingDirectory=/opt/ogg_web
   Environment=OGG_WEB_CONFIG=/opt/ogg_web/config/ogg_local.yaml
   ExecStart=/opt/ogg_web/.venv/bin/gunicorn -w 4 -b 127.0.0.1:8080 app:app
   Restart=always

   [Install]
   WantedBy=multi-user.target

3) Nginx site (HTTP example — add TLS in prod):
   server {
     listen 80;
     server_name ogg-web.local;
     location / {
       proxy_pass http://127.0.0.1:8080;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_read_timeout 75s;
     }
   }

Hardening ideas
---------------
* Add Basic Auth or OAuth in front of the app.
* Limit OS access to the host (admin subnet/VPN).
* Use `useridalias` for DBLOGIN (no plaintext DB creds).
"""
