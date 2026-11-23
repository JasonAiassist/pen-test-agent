#!/usr/bin/env python3
"""PenEnv vulnerability tracker - stdlib-only HTTP service.

Serves the dashboard UI and a JSON API on 127.0.0.1:8766:
  GET  /                    dashboard UI
  GET  /api/summary         counts by severity/status + run trend
  GET  /api/findings        findings list (?status=&severity=&q=)
  POST /api/findings/{id}/status   set manual status
  GET  /api/runs            ingested scan runs
  GET  /api/run/{dir}/report       penetration_test_report.md
  GET  /api/run/{dir}/vuln/{fid}.md    per-finding report
  POST /api/ingest          re-ingest strix_runs/

Projects (engagement configs persisted across scans):
  GET    /api/projects                list projects
  POST   /api/projects                create  {name, config}
  GET    /api/projects/{id}           read    (?reveal=1 to unmask secrets)
  POST   /api/projects/{id}           update  {name?, config?}
  DELETE /api/projects/{id}           delete
  GET    /api/projects/{id}/history   per-project scan history (before/after)

  POST   /api/projects/validate       dry-run validation {config} -> {issues}

Agent config (Strix model provider + model; stored in ~/.config/penenv/agent.json, keys masked):
  GET    /api/agent                   providers, selection, effective model, Strix default
  POST   /api/agent/providers         create provider {name, kind, api_base, api_key, api_type}
  POST   /api/agent/providers/{id}    update provider (masked key sent back = keep stored key)
  DELETE /api/agent/providers/{id}    remove provider
  POST   /api/agent/providers/{id}/models   ask the provider for its model list (host-side)
  POST   /api/agent/active            select {provider_id, model, reasoning_effort}; "" = Strix default
  POST   /api/agent/import-strix      create a provider from ~/.strix/cli-config.json

Keysafe secrets (password, api_key) are masked ("********") on read unless
?reveal=1 (audited); when a masked value is sent back on save, the stored
secret for that entry id is kept. Saves are validated by scope.py: format,
duplicates within/across scope lists, and hat-level gating. Errors -> HTTP 400
with {"error", "issues": [...]}; warnings are returned alongside ok.
"""
from __future__ import annotations

import hashlib
import html
import secrets
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RUNS_DIR = ROOT / "strix_runs"
STATIC = HERE / "static"
PENENV_BIN = ROOT / "bin" / "penenv"
LAUNCH_DIR = ROOT / "scan_audit" / "launches"  # per-launch combined stdout/stderr logs
REPORTS_DIR = ROOT / "reports"                 # generated HTML/PDF/DOCX pen-test reports
# 8765 is taken by the local phoneme-server (omarchy voice-avatar); use 8766.
PORT = int(os.environ.get("PENENV_PORT") or 8766)

sys.path.insert(0, str(HERE))
import ingest as ingest_mod  # noqa: E402
import agentcfg  # noqa: E402
import authenticator  # noqa: E402
import authorisation as auth_mod  # noqa: E402
import migrations  # noqa: E402
import policy  # noqa: E402
import scope  # noqa: E402
import report as report_mod  # noqa: E402

STATUS_ORDER = {"open": 0, "reopened": 0, "accepted": 1, "false_positive": 2, "fixed": 3}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SECRET_MASK = "********"


class ApiError(Exception):
    def __init__(self, code: int, message: str, **extra):
        super().__init__(message)
        self.code, self.payload = code, {"error": message, **extra}


def db() -> sqlite3.Connection:
    con = sqlite3.connect(ingest_mod.DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def ensure_projects_table() -> None:
    con = db()
    con.execute(
        """CREATE TABLE IF NOT EXISTS projects(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL UNIQUE,
               config TEXT NOT NULL,
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL
           )"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS key_access_audit(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               action TEXT NOT NULL,
               project_id INTEGER,
               project_name TEXT,
               entry_labels TEXT,
               at TEXT NOT NULL
           )"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS scan_tokens(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               project_id INTEGER NOT NULL,
               token_hash TEXT NOT NULL UNIQUE,
               run_label TEXT,
               policy_summary TEXT,
               created_at TEXT NOT NULL,
               expires_at REAL NOT NULL,
               revoked_at TEXT
           )"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS scan_events(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               scan_id INTEGER NOT NULL,
               kind TEXT NOT NULL,
               detail TEXT,
               at TEXT NOT NULL
           )"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS scan_launches(
               id TEXT PRIMARY KEY,
               project_id INTEGER NOT NULL,
               project_name TEXT,
               pid INTEGER,
               argv TEXT,
               dry_run INTEGER DEFAULT 0,
               log_path TEXT,
               started_at TEXT NOT NULL,
               ended_at TEXT,
               exit_code INTEGER,
               status TEXT NOT NULL
           )"""
    )
    con.commit()
    auth_mod.ensure_table(con)
    con.close()


SCAN_TOKEN_TTL = 12 * 3600  # hard upper bound; penenv revokes as soon as the scan ends


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
    except (OSError, TypeError, ValueError):
        return False
    return True


def _exit_meaning(rc) -> str:
    # Strix -n exits 2 when findings meet --fail-on; that is a completed scan, not an error.
    return {0: "clean (no findings)", 2: "completed — findings reported"}.get(
        rc, "stopped" if isinstance(rc, int) and rc < 0 else "error")


def _norm_scope_entry(s: str) -> str:
    return ingest_mod.norm_target(s)


def _run_targets(run_row) -> list[str]:
    return [t for t in (run_row["targets"] or "").split(",") if t]


def _mask_config(cfg: dict) -> dict:
    out = json.loads(json.dumps(cfg))  # deep copy of plain JSON data
    for entry in out.get("keysafe", []) or []:
        if isinstance(entry, dict):
            for f in scope.SECRET_FIELDS:
                if entry.get(f):
                    entry[f] = SECRET_MASK
    return out


def _normalise_config(cfg: dict) -> dict:
    """Coerce a client config to the v2 shape (unknown keys are kept)."""
    cfg = dict(cfg)
    cfg["schema"] = migrations.CONFIG_VERSION
    for k in ("endpoints", "out_of_scope"):
        cfg[k] = [{"type": str(e.get("type") or ""), "data": str(e.get("data") or "").strip()}
                  if isinstance(e, dict) else e for e in (cfg.get(k) or [])]
    creds = []
    for e in cfg.get("keysafe") or []:
        if not isinstance(e, dict):
            creds.append(e)
            continue
        c = {f: str(e.get(f) or "") for f in scope.CRED_FIELDS}
        for f in ("label", "login_url", "username", "domain", "otp_ref", "role"):
            c[f] = c[f].strip()
        c["id"] = c["id"] or migrations.new_cred_id()
        creds.append(c)
    cfg["keysafe"] = creds
    if cfg.get("hat") not in scope.HATS:
        cfg["hat"] = "grey"
    if cfg.get("position") not in scope.POSITIONS:
        cfg["position"] = scope.default_position(cfg["hat"])
    cfg["switches"] = policy.migrate_switches(cfg.get("switches"))
    cfg["authorisation"] = str(cfg.get("authorisation") or "").strip()
    raw_stack = cfg.get("stack")
    cfg["stack"] = ([str(s).strip() for s in raw_stack if str(s).strip()]
                    if isinstance(raw_stack, list) else [])
    try:
        cfg["aggression"] = max(0, min(5, int(cfg.get("aggression", 2))))
    except (TypeError, ValueError):
        cfg["aggression"] = 2
    return cfg


def _merge_secrets(new_cfg: dict, old_cfg: dict) -> dict:
    """Where the client sent the mask back, keep the stored secret of the same entry id."""
    old_by_id = {o.get("id"): o for o in (old_cfg or {}).get("keysafe", []) or []
                 if isinstance(o, dict) and o.get("id")}
    for entry in new_cfg.get("keysafe", []) or []:
        if not isinstance(entry, dict):
            continue
        prev = old_by_id.get(entry.get("id"), {})
        for f in scope.SECRET_FIELDS:
            if entry.get(f) == SECRET_MASK:
                entry[f] = prev.get(f, "")
    return new_cfg


def validate_config(cfg: dict, resolver=scope.default_resolver) -> list[dict]:
    ins, outs = cfg.get("endpoints") or [], cfg.get("out_of_scope") or []
    creds = cfg.get("keysafe") or []
    issues = scope.check_endpoints(ins, outs)
    issues += scope.check_credentials(creds, ins)
    issues += scope.check_hat(cfg.get("hat", "grey"), ins, creds, resolver)
    issues += scope.check_position(cfg.get("position") or scope.default_position(cfg.get("hat")), ins, resolver)
    return issues


# Tests swap this for a deterministic fake resolver.
RESOLVER = scope.default_resolver


def _validated(cfg: dict) -> tuple[dict, list[dict]]:
    issues = validate_config(cfg, RESOLVER)
    errs = scope.errors(issues)
    if errs:
        raise ApiError(400, f"{len(errs)} problem(s) must be fixed before saving: " + errs[0]["message"],
                       issues=issues)
    return cfg, issues


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        if isinstance(obj, dict) and "error" in obj and code == 200:
            code = 404 if "unknown" in str(obj["error"]) else 400
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _fail(self, exc: Exception) -> None:
        if isinstance(exc, ApiError):
            return self._json(exc.payload, exc.code)
        if isinstance(exc, json.JSONDecodeError):
            return self._json({"error": "request body is not valid JSON"}, 400)
        return self._json({"error": str(exc)}, 500)

    def _static(self, name: str) -> None:
        f = (STATIC / name).resolve()
        if not f.is_relative_to(STATIC) or not f.is_file():
            return self._json({"error": "not found"}, 404)
        ctype = {".html": "text/html", ".js": "text/javascript",
                 ".css": "text/css"}.get(f.suffix, "application/octet-stream")
        self._send(200, f.read_bytes(), f"{ctype}; charset=utf-8")

    # ---- routing --------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._static("index.html")
        if u.path.startswith("/static/"):
            return self._static(u.path[len("/static/"):])
        try:
            if u.path == "/api/summary":
                return self._json(self.api_summary())
            if u.path == "/api/findings":
                return self._json(self.api_findings(parse_qs(u.query)))
            if u.path == "/api/runs":
                return self._json(self.api_runs())
            if u.path == "/api/policy/catalogue":
                return self._json(self.api_policy_catalogue())
            if u.path == "/api/agent":
                return self._json(self.api_agent())
            parts = u.path.split("/")
            if len(parts) == 3 and parts[1] == "api" and parts[2] == "authorisations":
                return self._json(self.api_auth_list())
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "authorisations":
                return self._json(self.api_auth_get(parts[3]))
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "projects" and parts[4] == "preflight":
                return self._json(self.api_project_preflight(parts[3]))
            if len(parts) >= 3 and parts[1] == "api" and parts[2] == "launches":
                qs = parse_qs(u.query)
                if len(parts) == 3:
                    return self._json(self.api_launches_list(qs))
                if len(parts) == 4:
                    return self._json(self.api_launch_get(parts[3], qs))
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "reports":
                return self._serve_generated_report(parts[3])
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "run" and parts[4] == "report":
                return self._serve_report(parts[3])
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "run":
                return self._serve_finding_md(parts[3], parts[4])
            if len(parts) >= 3 and parts[1] == "api" and parts[2] == "projects":
                qs = parse_qs(u.query)
                if len(parts) == 3:
                    return self._json(self.api_projects_list())
                pid = parts[3]
                if len(parts) == 4:
                    return self._json(self.api_project_get(pid, reveal=("reveal" in qs)))
                if len(parts) == 5 and parts[4] == "history":
                    return self._json(self.api_project_history(pid))
                if len(parts) == 5 and parts[4] == "scans":
                    return self._json(self.api_project_scans(pid))
            return self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            return self._fail(exc)

    def do_POST(self):
        u = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            parts = u.path.split("/")
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "findings" and parts[4] == "status":
                return self._json(self.api_set_status(parts[3], body))
            if u.path == "/api/ingest":
                return self._json(ingest_mod.ingest(verbose=False))
            if u.path == "/api/projects/validate":
                return self._json(self.api_project_validate(body))
            if len(parts) >= 3 and parts[1] == "api" and parts[2] == "agent":
                return self._json(self.api_agent_post(parts[3:], body))
            if len(parts) == 3 and parts[1] == "api" and parts[2] == "authorisations":
                return self._json(self.api_auth_save(body))
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "authorisations":
                return self._json(self.api_auth_save(body, parts[3]))
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "authorisations" and parts[4] == "revoke":
                return self._json(self.api_auth_revoke(parts[3], body))
            if len(parts) == 3 and parts[1] == "api" and parts[2] == "projects":
                return self._json(self.api_project_create(body))
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "projects":
                return self._json(self.api_project_update(parts[3], body))
            if (len(parts) == 6 and parts[1] == "api" and parts[2] == "projects"
                    and parts[4] == "mfa" and parts[5] in ("register", "code")):
                return self._json(self.api_mfa(parts[3], parts[5], body))
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "projects" and parts[4] == "scan-token":
                return self._json(self.api_scan_token(parts[3], body))
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "projects" and parts[4] == "launch":
                return self._json(self.api_project_launch(parts[3], body))
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "projects" and parts[4] == "report":
                return self._json(self.api_build_report(body, pid=parts[3]))
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "run" and parts[4] == "report":
                return self._json(self.api_build_report(body, run_dir=parts[3]))
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "launches" and parts[4] == "stop":
                return self._json(self.api_launch_stop(parts[3]))
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "scan-channel":
                return self._json(self.api_scan_channel(parts[3], body))
            return self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            return self._fail(exc)

    def do_DELETE(self):
        u = urlparse(self.path)
        try:
            parts = u.path.split("/")
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "projects":
                return self._json(self.api_project_delete(parts[3]))
            if len(parts) == 5 and parts[1:4] == ["api", "agent", "providers"]:
                return self._json(self._agent_call(agentcfg.delete_provider, parts[4]) or {"ok": True})
            return self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            return self._fail(exc)

    # ---- agent config ----------------------------------------------------
    @staticmethod
    def _agent_call(fn, *a):
        try:
            return fn(*a)
        except agentcfg.AgentConfigError as e:
            raise ApiError(404 if str(e).startswith("unknown") else 400, str(e)) from None

    def api_agent(self):
        return {**agentcfg.masked(agentcfg.load()), "effective": agentcfg.effective(),
                "strix_default": agentcfg.strix_default(), "kinds": agentcfg.kinds(),
                "efforts": list(agentcfg.EFFORTS), "config_path": str(agentcfg.CONFIG_PATH)}

    def api_agent_post(self, rest: list[str], body: dict):
        if rest == ["providers"]:
            p = self._agent_call(agentcfg.save_provider, body)
            return {**p, "api_key": agentcfg._mask_key(p["api_key"])}
        if len(rest) == 2 and rest[0] == "providers":
            p = self._agent_call(agentcfg.save_provider, body, rest[1])
            return {**p, "api_key": agentcfg._mask_key(p["api_key"])}
        if len(rest) == 3 and rest[0] == "providers" and rest[2] == "models":
            return self._agent_call(agentcfg.list_models, rest[1])
        if rest == ["active"]:
            return {"active": self._agent_call(agentcfg.set_active, body), "effective": agentcfg.effective()}
        if rest == ["import-strix"]:
            return self._agent_call(agentcfg.import_strix_default)
        raise ApiError(404, "not found")

    # ---- API implementations -------------------------------------------
    def api_summary(self):
        con = db()
        by_sev_open, by_status, runs = {}, {}, []
        for r in con.execute("SELECT severity, COUNT(*) c FROM findings "
                             "WHERE status IN ('open','reopened') GROUP BY severity"):
            by_sev_open[r["severity"]] = r["c"]
        for r in con.execute("SELECT status, COUNT(*) c FROM findings GROUP BY status"):
            by_status[r["status"]] = r["c"]
        trend = []
        for r in con.execute("SELECT dir,name,started,findings_count FROM runs ORDER BY dir"):
            trend.append({"dir": r["dir"], "name": r["name"], "started": r["started"],
                          "findings": r["findings_count"]})
        targets = [r["target"] for r in con.execute(
            "SELECT DISTINCT target FROM findings ORDER BY target")]
        last = con.execute("SELECT MAX(ingested_at) t FROM runs").fetchone()["t"]
        con.close()
        return {"open_by_severity": by_sev_open, "by_status": by_status,
                "runs": trend, "targets": targets, "last_ingest": last}

    def api_findings(self, qs):
        con = db()
        sql = ("SELECT f.*, o.evidence FROM findings f "
               "LEFT JOIN occurrences o ON o.finding_id=f.id AND o.run_dir=f.last_run "
               "WHERE 1=1")
        args: list = []
        status = (qs.get("status") or [""])[0]
        if status and status != "all":
            if status == "active":
                sql += " AND f.status IN ('open','reopened')"
            else:
                sql += " AND f.status=?"
                args.append(status)
        sev = (qs.get("severity") or [""])[0]
        if sev:
            sql += " AND f.severity=?"
            args.append(sev.upper())
        q = (qs.get("q") or [""])[0].strip().lower()
        rows = [dict(r) for r in con.execute(sql + " ORDER BY f.severity, f.target", args)]
        con.close()
        if q:
            def match(r):
                hay = " ".join(str(r.get(k) or "") for k in
                               ("title", "target", "endpoint", "method", "evidence")).lower()
                return q in hay
            rows = [r for r in rows if match(r)]
        rows.sort(key=lambda r: (STATUS_ORDER.get(r["status"], 9),
                                 SEV_RANK.get(r["severity"], 9), r["target"]))
        return rows

    def api_runs(self):
        con = db()
        runs = [dict(r) for r in con.execute("SELECT * FROM runs ORDER BY dir DESC")]
        con.close()
        return runs

    def api_set_status(self, fid, body):
        status = str(body.get("status") or "").strip()
        if status not in {"open", "fixed", "accepted", "false_positive"}:
            return {"error": "status must be open|fixed|accepted|false_positive"}
        con = db()
        row = con.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
        if row is None:
            con.close()
            return {"error": "unknown finding"}
        fixed_in = None
        if status == "fixed":
            fixed_in = "manual"
        elif row["status"] == "fixed":
            fixed_in = None
        con.execute("UPDATE findings SET status=?, fixed_in_run=? WHERE id=?",
                    (status, fixed_in, fid))
        con.commit()
        con.close()
        return {"ok": True, "id": fid, "status": status}

    # ---- projects -------------------------------------------------------
    def api_projects_list(self):
        con = db()
        rows = con.execute(
            "SELECT id, name, config, created_at, updated_at FROM projects ORDER BY name").fetchall()
        con.close()
        out = []
        for r in rows:
            cfg = json.loads(r["config"])
            out.append({
                "id": r["id"], "name": r["name"], "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "endpoints_count": len(cfg.get("endpoints", []) or []),
                "hat": cfg.get("hat"), "aggression": cfg.get("aggression"),
                "keysafe_count": len(cfg.get("keysafe", []) or []),
            })
        return {"projects": out}

    def api_project_get(self, pid, reveal=False):
        con = db()
        r = con.execute("SELECT id, name, config, created_at, updated_at "
                        "FROM projects WHERE id=?", (pid,)).fetchone()
        if r is None:
            con.close()
            return {"error": "unknown project"}
        cfg = json.loads(r["config"])
        if reveal:
            labels = "; ".join(
                f"{e.get('label') or '?'} ({e.get('username', '')})".strip()
                for e in (cfg.get("keysafe", []) or []) if isinstance(e, dict)
                and any(e.get(f) for f in scope.SECRET_FIELDS))
            con.execute("INSERT INTO key_access_audit(action, project_id, project_name,"
                        " entry_labels, at) VALUES (?,?,?,?,?)",
                        ("reveal_secret", int(pid), r["name"], labels, now_ts()))
            con.commit()
        else:
            cfg = _mask_config(cfg)
        con.close()
        return {"id": r["id"], "name": r["name"], "config": cfg,
                "issues": validate_config(cfg, RESOLVER),
                "created_at": r["created_at"], "updated_at": r["updated_at"]}

    def api_project_validate(self, body):
        cfg = body.get("config")
        if not isinstance(cfg, dict):
            raise ApiError(400, "config object required")
        cfg = _normalise_config(cfg)
        sw = policy.resolve_switches(cfg)
        return {"issues": validate_config(cfg, RESOLVER),
                "policy": {"switches": sw, "warnings": policy.switch_warnings(cfg),
                           "level": policy.LEVELS[cfg["aggression"]]}}

    # ---- engagement authorisations (research-mode contract gate) ---------------
    @staticmethod
    def _auth_id(aid) -> int:
        try:
            return int(aid)
        except (TypeError, ValueError):
            raise ApiError(404, "unknown authorisation")

    @staticmethod
    def _auth_view(rec: dict) -> dict:
        today = auth_mod._today()
        exp = rec.get("expires") or ""
        try:
            expired = bool(exp) and auth_mod._dt.date.fromisoformat(exp) < today
        except ValueError:
            expired = True
        state = "revoked" if rec.get("revoked_at") else ("expired" if expired else "active")
        return {**{k: v for k, v in rec.items() if k != "inline"}, "state": state}

    def api_auth_list(self):
        con = db()
        try:
            return {"authorisations": [self._auth_view(r) for r in auth_mod.list_records(con)]}
        finally:
            con.close()

    def api_auth_get(self, aid):
        aid = self._auth_id(aid)
        con = db()
        try:
            row = con.execute("SELECT ref FROM authorisations WHERE id=?", (aid,)).fetchone()
            if not row:
                raise ApiError(404, "unknown authorisation")
            rec = auth_mod.get_record(con, row["ref"])
            return {**self._auth_view(rec), "audit": auth_mod.audit_trail(con, aid)}
        finally:
            con.close()

    def api_auth_save(self, body, aid=None):
        if not isinstance(body, dict):
            raise ApiError(400, "authorisation object required")
        aid = None if aid is None else self._auth_id(aid)
        con = db()
        try:
            rec, errs = auth_mod.save_record(con, body, aid)
        finally:
            con.close()
        if errs:
            code = 404 if errs == ["unknown authorisation"] else (409 if "already exists" in errs[0] else 400)
            raise ApiError(code, f"{len(errs)} problem(s): " + "; ".join(errs), problems=errs)
        return {"ok": True, **self._auth_view(rec)}

    def api_auth_revoke(self, aid, body):
        aid = self._auth_id(aid)
        con = db()
        try:
            rec = auth_mod.revoke_record(con, aid, str((body or {}).get("reason") or "").strip())
        finally:
            con.close()
        if rec is None:
            raise ApiError(404, "unknown authorisation")
        return {"ok": True, **self._auth_view(rec)}

    def api_policy_catalogue(self):
        def auto_txt(rule):
            return {"never": "off unless switched on", "source": "on when a source path is set",
                    "creds": "on unless Black hat"}.get(rule, f"on from L{rule}")
        return {"switches": [{"id": s["id"], "label": s["label"], "cls": s["cls"], "auto": auto_txt(s["auto"]),
                              "needs_auth": bool(s.get("needs_auth"))} for s in policy.SWITCHES],
                "levels": policy.LEVELS, "precedence": "switch > aggression level > hat level > profile defaults"}

    def api_project_create(self, body):
        name = str(body.get("name") or "").strip()
        cfg = body.get("config")
        if not name:
            raise ApiError(400, "name required")
        if not isinstance(cfg, dict):
            cfg = {}
        if any(v == SECRET_MASK for c in cfg.get("keysafe") or [] if isinstance(c, dict)
               for v in c.values()):
            raise ApiError(400, "a new project cannot contain masked secrets")
        cfg, issues = _validated(_normalise_config(cfg))
        con = db()
        try:
            con.execute("INSERT INTO projects(name, config, created_at, updated_at) "
                        "VALUES (?,?,?,?)",
                        (name, json.dumps(cfg, ensure_ascii=False), now_ts(), now_ts()))
            con.commit()
            pid = con.execute("SELECT last_insert_rowid() i").fetchone()["i"]
        except sqlite3.IntegrityError:
            con.close()
            raise ApiError(409, "a project with that name already exists")
        con.close()
        return {"ok": True, "id": pid, "issues": issues}

    def api_project_update(self, pid, body):
        con = db()
        row = con.execute("SELECT name, config FROM projects WHERE id=?", (pid,)).fetchone()
        if row is None:
            con.close()
            raise ApiError(404, "unknown project")
        name = str(body.get("name") or row["name"]).strip() or row["name"]
        issues: list = []
        if "config" in body and isinstance(body["config"], dict):
            old_cfg = json.loads(row["config"])
            cfg = _merge_secrets(_normalise_config(body["config"]), old_cfg)
            try:
                cfg, issues = _validated(cfg)
            except ApiError:
                con.close()
                raise
            cfg_json = json.dumps(cfg, ensure_ascii=False)
        else:
            cfg_json = row["config"]
        try:
            con.execute("UPDATE projects SET name=?, config=?, updated_at=? WHERE id=?",
                        (name, cfg_json, now_ts(), pid))
            con.commit()
        except sqlite3.IntegrityError:
            con.close()
            raise ApiError(409, "a project with that name already exists")
        con.close()
        return {"ok": True, "id": int(pid), "issues": issues}

    def _audit(self, con, action, pid, pname, labels):
        con.execute("INSERT INTO key_access_audit(action, project_id, project_name, entry_labels, at)"
                    " VALUES (?,?,?,?,?)", (action, int(pid), pname, labels, now_ts()))

    def api_mfa(self, pid, op, body):
        """Register / recover one-time codes through the KeePassXC authenticator."""
        password = body.get("kdbx_password")
        if not isinstance(password, str) or not password:
            raise ApiError(400, "KeePassXC master password required")
        con = db()
        try:
            row = con.execute("SELECT name, config FROM projects WHERE id=?", (pid,)).fetchone()
            if row is None:
                raise ApiError(404, "unknown project")
            cfg = json.loads(row["config"])
            if cfg.get("hat") == "black":
                raise ApiError(400, "Black hat projects carry no credentials or MFA")
            cred = next((c for c in cfg.get("keysafe") or []
                         if isinstance(c, dict) and c.get("id") == body.get("cred_id")), None)
            if cred is None:
                raise ApiError(404, "unknown login — save the project first")
            label = f"{cred.get('label') or '?'} ({cred.get('username', '')})"
            try:
                if op == "register":
                    res = authenticator.register(row["name"], cred, str(body.get("secret") or ""), password)
                    cred["otp_ref"] = res["otp_ref"]
                    con.execute("UPDATE projects SET config=?, updated_at=? WHERE id=?",
                                (json.dumps(cfg, ensure_ascii=False), now_ts(), pid))
                    self._audit(con, "mfa_register", pid, row["name"], label)
                    con.commit()
                    return {"ok": True, "otp_ref": res["otp_ref"], "code": res["code"],
                            "remaining": res["remaining"], "created_db": res["created_db"]}
                if not cred.get("otp_ref"):
                    raise ApiError(400, "this login has no MFA registered")
                res = authenticator.code(cred["otp_ref"], password)
                self._audit(con, "mfa_code", pid, row["name"], label)
                con.commit()
                return {"ok": True, "code": res["code"], "remaining": res["remaining"]}
            except authenticator.AuthError as e:
                self._audit(con, f"mfa_{op}_failed", pid, row["name"], label)
                con.commit()
                raise ApiError(e.code, str(e)) from None
        finally:
            con.close()

    # ---- scan-time channel (T2.5): per-scan token, audited, revoked at scan end ----
    def api_scan_token(self, pid, body):
        con = db()
        try:
            row = con.execute("SELECT name FROM projects WHERE id=?", (pid,)).fetchone()
            if row is None:
                raise ApiError(404, "unknown project")
            token = secrets.token_urlsafe(32)
            cur = con.execute(
                "INSERT INTO scan_tokens(project_id, token_hash, run_label, policy_summary, created_at, expires_at)"
                " VALUES (?,?,?,?,?,?)",
                (int(pid), _token_hash(token), str(body.get("run_label") or ""),
                 json.dumps(body.get("policy_summary") or {}, ensure_ascii=False)[:20000],
                 now_ts(), time.time() + SCAN_TOKEN_TTL))
            con.commit()
            return {"token": token, "scan_id": cur.lastrowid}
        finally:
            con.close()

    def _scan_by_token(self, con, token):
        if not isinstance(token, str) or not token:
            raise ApiError(401, "scan token required")
        row = con.execute("SELECT * FROM scan_tokens WHERE token_hash=?", (_token_hash(token),)).fetchone()
        if row is None or row["revoked_at"] or row["expires_at"] < time.time():
            raise ApiError(401, "scan token is not valid (unknown, expired or the scan has ended)")
        return row

    def api_scan_channel(self, op, body):
        con = db()
        try:
            scan = self._scan_by_token(con, body.get("token"))
            pid = scan["project_id"]
            if op == "revoke":
                con.execute("UPDATE scan_tokens SET revoked_at=? WHERE id=?", (now_ts(), scan["id"]))
                con.commit()
                return {"ok": True}
            if op == "events":
                evs = body.get("events") or []
                for ev in evs[:5000]:
                    con.execute("INSERT INTO scan_events(scan_id, kind, detail, at) VALUES (?,?,?,?)",
                                (scan["id"], str(ev.get("kind") or "event")[:64],
                                 str(ev.get("detail") or "")[:4000], str(ev.get("at") or now_ts())[:40]))
                con.commit()
                return {"ok": True, "recorded": len(evs[:5000])}
            if op not in ("credential", "otp"):
                raise ApiError(404, "not found")
            prow = con.execute("SELECT name, config FROM projects WHERE id=?", (pid,)).fetchone()
            cfg = json.loads(prow["config"])
            if cfg.get("hat") == "black":
                raise ApiError(403, "Black hat projects carry no credentials or MFA")
            sw = policy.resolve_switches(cfg)
            if not sw["use_credentials" if op == "credential" else "use_mfa"]["on"]:
                raise ApiError(403, f"switched off for this project: {'use_credentials' if op == 'credential' else 'use_mfa'}")
            want = str(body.get("label") or "")
            cred = next((c for c in cfg.get("keysafe") or [] if isinstance(c, dict)
                         and want and want in (c.get("label"), c.get("username"))), None)
            label = f"{want} (scan {scan['id']})"
            if cred is None:
                self._audit(con, f"scan_{op}_unknown", pid, prow["name"], label)
                con.commit()
                raise ApiError(404, f"unknown login label {want!r}")
            if op == "credential":
                self._audit(con, "scan_credential", pid, prow["name"], label)
                con.commit()
                return {f: cred.get(f, "") for f in ("label", "role", "login_url", "domain",
                                                     "username", "password", "api_key")}
            if not cred.get("otp_ref"):
                raise ApiError(400, "this login has no MFA registered")
            try:
                res = authenticator.code(cred["otp_ref"], str(body.get("kdbx_password") or ""))
            except authenticator.AuthError as e:
                self._audit(con, "scan_otp_failed", pid, prow["name"], label)
                con.commit()
                raise ApiError(e.code, str(e)) from None
            self._audit(con, "scan_otp", pid, prow["name"], label)
            con.commit()
            return {"code": res["code"], "remaining": res["remaining"]}
        finally:
            con.close()

    def api_project_scans(self, pid):
        con = db()
        try:
            out = []
            for r in con.execute("SELECT * FROM scan_tokens WHERE project_id=? ORDER BY id DESC LIMIT 50", (pid,)):
                evs = [dict(e) for e in con.execute(
                    "SELECT kind, detail, at FROM scan_events WHERE scan_id=? ORDER BY id", (r["id"],))]
                out.append({"scan_id": r["id"], "run_label": r["run_label"], "created_at": r["created_at"],
                            "ended_at": r["revoked_at"], "policy": json.loads(r["policy_summary"] or "{}"),
                            "events": evs})
            return {"scans": out}
        finally:
            con.close()

    # ---- launch & monitor a policy-enforced scan from the UI (New scan tab) ----
    def _launch_row(self, con, lid):
        row = con.execute("SELECT * FROM scan_launches WHERE id=?", (lid,)).fetchone()
        if row is None:
            raise ApiError(404, "unknown scan launch")
        return row

    def _launch_view(self, row, offset=0, with_log=True):
        status, rc = row["status"], row["exit_code"]
        if status == "running" and not _pid_alive(row["pid"]):
            # the process ended but the watcher thread did not record it (e.g. server restart)
            status = "unknown"
        log, next_off = "", offset
        if with_log and row["log_path"]:
            try:
                with open(row["log_path"], "rb") as f:
                    f.seek(max(0, offset))
                    data = f.read()
                log = data.decode("utf-8", "replace")
                next_off = max(0, offset) + len(data)
            except OSError:
                pass
        return {
            "id": row["id"], "project_id": row["project_id"], "project_name": row["project_name"],
            "status": status, "running": status == "running", "dry_run": bool(row["dry_run"]),
            "exit_code": rc, "exit_meaning": _exit_meaning(rc) if rc is not None else "",
            "argv": row["argv"], "started_at": row["started_at"], "ended_at": row["ended_at"],
            "log": log, "offset": next_off,
        }

    def _preflight(self, name: str) -> dict:
        """Run the exact scan plan (penenv scan --dry-run) the real scan will use: same policy
        build, docker-network name resolution and refusal rules. Nothing touches the target."""
        try:
            r = subprocess.run([str(PENENV_BIN), "scan", "--project", name, "--dry-run"],
                               cwd=str(ROOT), stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=90, env=dict(os.environ))
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "errors": [f"could not run the scan plan: {e}"], "plan": ""}
        out = (r.stdout or "") + (r.stderr or "")
        errors = [ln.split("ERROR:", 1)[1].strip() for ln in out.splitlines() if "ERROR:" in ln]
        if r.returncode != 0 and not errors:
            errors = [ln for ln in out.strip().splitlines()[-3:]] or [f"scan plan exited {r.returncode}"]
        warnings = [ln.split(":", 1)[1].strip() for ln in out.splitlines()
                    if ln.lstrip().startswith("WARNING:")]
        return {"ok": r.returncode == 0 and not errors, "errors": errors, "warnings": warnings,
                "plan": out, "exit_code": r.returncode}

    def api_project_preflight(self, pid):
        con = db()
        try:
            row = con.execute("SELECT name FROM projects WHERE id=?", (pid,)).fetchone()
            if row is None:
                raise ApiError(404, "unknown project")
            name = row["name"]
        finally:
            con.close()
        return {"project": name, **self._preflight(name)}

    def api_project_launch(self, pid, body):
        con = db()
        try:
            row = con.execute("SELECT id, name, config FROM projects WHERE id=?", (pid,)).fetchone()
            if row is None:
                raise ApiError(404, "unknown project")
            name, cfg = row["name"], json.loads(row["config"])
            dry_run = bool(body.get("dry_run"))
            # A real scan must pass the same gate as Save; a dry-run is allowed to proceed so the
            # plan and the reasons it would be refused are printed (scanrun stops before any docker work).
            if not dry_run:
                issues = validate_config(cfg, RESOLVER)
                errs = scope.errors(issues)
                if errs:
                    raise ApiError(400, f"project has {len(errs)} problem(s) to fix before scanning: "
                                   + errs[0]["message"], issues=issues)
                pf = self._preflight(name)
                if not pf["ok"]:
                    raise ApiError(400, "the scan plan refuses this project: " + "; ".join(pf["errors"]),
                                   preflight_errors=pf["errors"])
            # A real scan with MFA logins would otherwise block on an interactive getpass prompt.
            sw = policy.resolve_switches(cfg)
            needs_mfa = (cfg.get("hat") != "black" and sw.get("use_mfa", {}).get("on")
                         and any(c.get("otp_ref") for c in (cfg.get("keysafe") or [])
                                 if isinstance(c, dict)))
            kdbx_pw = str(body.get("kdbx_password") or "")
            if needs_mfa and not dry_run and not kdbx_pw:
                raise ApiError(400, "this project has MFA-enabled logins — provide the KeePassXC "
                               "authenticator master password to run the scan")

            LAUNCH_DIR.mkdir(parents=True, exist_ok=True)
            lid = secrets.token_hex(6)
            log_path = LAUNCH_DIR / f"{lid}.log"
            argv = [str(PENENV_BIN), "scan", "--project", name]
            if dry_run:
                argv.append("--dry-run")
            prof = str(body.get("profile") or "").strip()
            if prof:
                argv += ["-p", prof]
            mt = body.get("max_turns")
            if isinstance(mt, (int, float)) and int(mt) > 0:
                argv += ["--max-turns", str(int(mt))]
            mb = str(body.get("max_budget") or "").strip()
            if mb:
                argv += ["--max-budget", mb]
            if body.get("keep"):
                argv.append("--keep")
            pw_file = None
            if kdbx_pw and not dry_run:
                pw_file = LAUNCH_DIR / f"{lid}.kdbx-pw"
                fd = os.open(pw_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(kdbx_pw)
                argv += ["--kdbx-password-file", str(pw_file)]

            logf = open(log_path, "wb")
            try:
                proc = subprocess.Popen(
                    argv, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                    stdout=logf, stderr=subprocess.STDOUT,
                    start_new_session=True, env=dict(os.environ))
            except OSError as e:
                logf.close()
                if pw_file:
                    try:
                        os.remove(pw_file)
                    except OSError:
                        pass
                raise ApiError(500, f"could not start scan: {e}") from None

            con.execute(
                "INSERT INTO scan_launches(id, project_id, project_name, pid, argv, dry_run, "
                "log_path, started_at, status) VALUES (?,?,?,?,?,?,?,?,?)",
                (lid, int(pid), name, proc.pid, " ".join(argv[1:]), 1 if dry_run else 0,
                 str(log_path), now_ts(), "running"))
            con.commit()

            def _watch(lid=lid, proc=proc, logf=logf, pw_file=pw_file):
                rc = proc.wait()
                try:
                    logf.close()
                except OSError:
                    pass
                if pw_file:
                    try:
                        os.remove(pw_file)
                    except OSError:
                        pass
                c2 = db()
                try:
                    c2.execute("UPDATE scan_launches SET status=?, exit_code=?, ended_at=? WHERE id=?",
                               ("finished", rc, now_ts(), lid))
                    c2.commit()
                finally:
                    c2.close()

            threading.Thread(target=_watch, name=f"scan-{lid}", daemon=True).start()
            return {"ok": True, "id": lid, "pid": proc.pid, "dry_run": dry_run,
                    "argv": " ".join(argv[1:])}
        finally:
            con.close()

    def api_launches_list(self, qs):
        con = db()
        try:
            params, where = [], ""
            proj = (qs.get("project") or [None])[0]
            if proj:
                where = " WHERE project_id=?"
                params.append(int(proj))
            rows = con.execute(
                "SELECT * FROM scan_launches" + where + " ORDER BY started_at DESC, rowid DESC LIMIT 40",
                params)
            return {"launches": [self._launch_view(r, with_log=False) for r in rows]}
        finally:
            con.close()

    def api_launch_get(self, lid, qs):
        con = db()
        try:
            offset = 0
            try:
                offset = int((qs.get("offset") or ["0"])[0])
            except (TypeError, ValueError):
                offset = 0
            return self._launch_view(self._launch_row(con, lid), offset=offset)
        finally:
            con.close()

    def api_launch_stop(self, lid):
        con = db()
        try:
            row = self._launch_row(con, lid)
            if row["status"] != "running":
                return {"ok": True, "already_ended": True}
            pid = row["pid"]
            try:
                os.killpg(os.getpgid(int(pid)), signal.SIGTERM)
            except (OSError, TypeError, ValueError) as e:
                raise ApiError(409, f"could not stop scan (already gone?): {e}") from None
            return {"ok": True}
        finally:
            con.close()

    def api_project_delete(self, pid):
        con = db()
        cur = con.execute("DELETE FROM projects WHERE id=?", (pid,))
        con.commit()
        con.close()
        if cur.rowcount == 0:
            return {"error": "unknown project"}
        return {"ok": True}

    def api_project_history(self, pid):
        con = db()
        row = con.execute("SELECT id, name, config FROM projects WHERE id=?", (pid,)).fetchone()
        if row is None:
            con.close()
            return {"error": "unknown project"}
        cfg = json.loads(row["config"])
        keys = set()
        for e in cfg.get("endpoints") or []:
            if isinstance(e, str) and e.strip():
                keys.add(_norm_scope_entry(e))
            elif isinstance(e, dict) and not scope.validate_endpoint(e.get("type"), e.get("data")):
                k = scope.scan_target_key(e["type"], e["data"])
                if k:
                    keys.add(k)
        scope_list = sorted(keys)
        scope_set = set(scope_list)

        runs_out = []
        prev_ids: set | None = None
        prev_title_by_id: dict = {}
        for r in con.execute(
                "SELECT dir,name,targets,mode,started,finished,status,findings_count,report_path "
                "FROM runs ORDER BY COALESCE(started,'') ASC, dir ASC"):
            targets = set(_run_targets(r))
            if not (targets & scope_set):
                continue
            occ = con.execute(
                "SELECT o.finding_id fid, o.severity sev FROM occurrences o "
                "WHERE o.run_dir=?", (r["dir"],)).fetchall()
            ids = {o["fid"] for o in occ}
            sev_counts: dict = {}
            for o in occ:
                s = (o["sev"] or "?").upper()
                sev_counts[s] = sev_counts.get(s, 0) + 1
            new = fixed = []
            if prev_ids is not None:
                new_ids = ids - prev_ids
                new = [{"id": i,
                        "severity": (con.execute("SELECT severity FROM findings WHERE id=?",
                                                 (i,)).fetchone() or {"severity": "?"})["severity"],
                        "title": (con.execute("SELECT title FROM findings WHERE id=?",
                                              (i,)).fetchone() or {"title": i})["title"]}
                       for i in new_ids]
                fixed_ids = prev_ids - ids
                fixed = [{"id": i, "severity": prev_title_by_id.get(i, ("?",))[0],
                          "title": prev_title_by_id.get(i, (i,))[1]} for i in fixed_ids]
            else:
                new = [{"id": i, "severity": (con.execute(
                        "SELECT severity FROM findings WHERE id=?", (i,)).fetchone()
                        or {"severity": "?"})["severity"],
                        "title": (con.execute(
                        "SELECT title FROM findings WHERE id=?", (i,)).fetchone()
                        or {"title": i})["title"]} for i in ids]
                fixed = []
            # store current titles/sevs for next iteration's fixed list
            prev_title_by_id = {}
            for o in occ:
                frow = con.execute("SELECT severity, title FROM findings WHERE id=?",
                                   (o["fid"],)).fetchone()
                if frow:
                    prev_title_by_id[o["fid"]] = (frow["severity"], frow["title"])
            prev_ids = ids
            runs_out.append({
                "dir": r["dir"], "name": r["name"], "mode": r["mode"],
                "started": r["started"], "finished": r["finished"], "status": r["status"],
                "report_path": r["report_path"],
                "targets": sorted(targets),
                "total": len(ids),
                "severity": sev_counts,
                "new": new, "fixed": fixed,
            })
        con.close()
        runs_out.reverse()  # newest first
        return {"project": {"id": row["id"], "name": row["name"]},
                "scope": scope_list, "runs": runs_out}

    # ---- static artifacts ------------------------------------------------
    def _serve_report(self, run_dir):
        path = (RUNS_DIR / run_dir / "penetration_test_report.md").resolve()
        if not path.is_relative_to(RUNS_DIR) or not path.is_file():
            return self._json({"error": "report not found"}, 404)
        return self._send(200, path.read_bytes(), "text/plain; charset=utf-8")

    def _serve_finding_md(self, run_dir, name):
        path = (RUNS_DIR / run_dir / "vulnerabilities" / name).resolve()
        if not path.is_relative_to(RUNS_DIR) or not path.is_file():
            return self._json({"error": "finding file not found"}, 404)
        return self._send(200, path.read_bytes(), "text/plain; charset=utf-8")

    # ---- formatted pen-test report (HTML / PDF / Word) ------------------
    _REPORT_CTYPE = {
        ".html": "text/html; charset=utf-8",
        ".pdf": "application/pdf",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }

    def _report_links(self, produced: dict) -> dict:
        """Map the generator's absolute file paths to download URLs under /api/reports/<name>."""
        files = {}
        for fmt in ("html", "pdf", "docx"):
            if produced.get(fmt):
                files[fmt] = "/api/reports/" + Path(produced[fmt]).name
        return files

    def _resolve_report_run(self, run_dir=None, pid=None):
        """Return (run_dir Path, project cfg dict|None) for a report build request."""
        if run_dir:
            d = (RUNS_DIR / run_dir).resolve()
            if not d.is_relative_to(RUNS_DIR) or not (d / "run.json").exists():
                raise ApiError(404, "unknown scan run")
            return d, None
        # by project: newest completed run that matches the project's first endpoint
        cfg = self.api_project_get(pid)["config"]
        cfg = dict(cfg)
        name = None
        con = db()
        try:
            row = con.execute("SELECT name FROM projects WHERE id=?", (pid,)).fetchone()
            name = row["name"] if row else None
        finally:
            con.close()
        cfg["name"] = name or cfg.get("name")
        tgt = (cfg.get("endpoints") or [{}])[0].get("data")
        try:
            d = report_mod.latest_run_for(target_url=tgt)
        except SystemExit as e:
            raise ApiError(404, str(e))
        return d, cfg

    def api_build_report(self, body, run_dir=None, pid=None):
        body = body or {}
        formats = body.get("formats") or ["html", "pdf", "docx"]
        formats = [f for f in formats if f in ("html", "pdf", "docx")] or ["html"]
        d, cfg = self._resolve_report_run(run_dir=run_dir, pid=pid)
        try:
            produced = report_mod.generate(d, REPORTS_DIR, formats,
                                           project=cfg, title=body.get("title"))
        except SystemExit as e:
            raise ApiError(500, str(e))
        return {"run_id": produced["_model"]["run_id"], "model": produced["_model"],
                "files": self._report_links(produced)}

    def _serve_generated_report(self, filename):
        safe = Path(filename).name  # basename only — no traversal
        path = (REPORTS_DIR / safe).resolve()
        if not path.is_relative_to(REPORTS_DIR) or not path.is_file():
            return self._json({"error": "report file not found"}, 404)
        ctype = self._REPORT_CTYPE.get(path.suffix, "application/octet-stream")
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        disp = "inline" if path.suffix == ".html" else "attachment"
        self.send_header("Content-Disposition", f'{disp}; filename="{safe}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    ensure_projects_table()
    report = migrations.run(Path(ingest_mod.DB_PATH))
    if report["migrated"]:
        print(f"migrated {report['migrated']} project(s) to config v{migrations.CONFIG_VERSION}; "
              f"backup: {report['backup']}")
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    pidfile = Path(__file__).resolve().parent / (".tracker.pid" if PORT == 8766 else f".tracker-{PORT}.pid")
    pidfile.write_text(str(os.getpid()))

    def _shutdown(signum, frame):  # noqa: ARG001
        try:
            if pidfile.read_text().strip() == str(os.getpid()):
                pidfile.unlink()
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    print(f"penenv tracker listening on http://127.0.0.1:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
