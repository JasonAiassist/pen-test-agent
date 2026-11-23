"""`penenv scan --project <name>` (T4.4): build the policy, stand up the enforced scan
network, run Strix through bin/penenv-launch.py, then record and tear everything down.

Needs docker access (bin/penenv runs this under the docker group) and a running tracker.

    python3 tracker/scanrun.py --project NAME [--dry-run] [-p PROFILE] [--max-budget USD]
                               [--kdbx-password-file F] [--max-turns N] [--keep]
No free-form Strix arguments are passed through: every Strix flag comes from the policy.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import cvefeed  # noqa: E402
import policy  # noqa: E402
import scope  # noqa: E402

TRACKER = os.environ.get("PENENV_TRACKER_URL", "http://127.0.0.1:8766")
GW_IMAGE = "penenv-egress-gw:2"
STRIX_PY = Path.home() / ".local/share/uv/tools/strix-agent/bin/python"
LAUNCHER = ROOT / "bin" / "penenv-launch.py"
AUDIT_ROOT = ROOT / "scan_audit"
CAIDO_PORT = 48080

STUB = """#!/bin/sh
# penenv deny stub: this binary is switched off by the project policy.
echo "penenv policy: denied: $0 $*" >&2
printf '%s\\t%s\\t%s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$0" "$*" >> /penenv-audit/denied.log 2>/dev/null
exit 126
"""


def log(msg: str) -> None:
    print(f"[penenv] {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ tracker
def api(method: str, path: str, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(TRACKER + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"[penenv] tracker {path}: {e.code} {e.read()[:300]!r}") from None
    except OSError as e:
        raise SystemExit(f"[penenv] tracker not reachable at {TRACKER} ({e}); start it: penenv tracker start") from None


def load_project(name: str) -> tuple[int, dict]:
    projects = api("GET", "/api/projects")
    projects = projects.get("projects", projects)
    match = [p for p in projects if p.get("name") == name]
    if not match:
        raise SystemExit(f"[penenv] no project named {name!r} (have: {', '.join(p['name'] for p in projects)})")
    pid = match[0]["id"]
    return pid, api("GET", f"/api/projects/{pid}")["config"]


# ------------------------------------------------------------------- docker
def docker(*args, check=True, capture=True) -> str:
    r = subprocess.run(["docker", *args], text=True, capture_output=capture)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])}…: {(r.stderr or '').strip()[:400]}")
    return (r.stdout or "").strip()


def docker_networks() -> list[dict]:
    """Non-internal user networks with their subnets and container names/aliases -> IPs."""
    out = []
    for name in docker("network", "ls", "--format", "{{.Name}}").splitlines():
        if name in ("host", "none") or name.startswith("penenv-scan-"):
            continue
        info = json.loads(docker("network", "inspect", name))[0]
        if info.get("Internal"):
            continue
        subnets = [c["Subnet"] for c in (info.get("IPAM", {}).get("Config") or []) if "Subnet" in c]
        names = {}
        for cid, c in (info.get("Containers") or {}).items():
            ip = (c.get("IPv4Address") or "").split("/")[0]
            if not ip:
                continue
            names[c.get("Name", "")] = ip
            details = json.loads(docker("inspect", cid))[0]
            for alias in (details["NetworkSettings"]["Networks"].get(name, {}).get("Aliases") or []):
                names[alias] = ip
        out.append({"name": name, "subnets": subnets, "names": names})
    return out


def make_resolver(nets: list[dict]):
    def resolve(host: str) -> list[str]:
        for n in nets:
            if host in n["names"]:
                return [n["names"][host]]
        return scope.default_resolver(host)
    return resolve


def outside_networks(p: dict, nets: list[dict]) -> list[str]:
    """Which networks the gateway must join to reach the allowlist."""
    need, internet = set(), False
    for ip, _ports in p["network"]["allow_tcp"] + p["network"]["allow_udp"]:
        net = ipaddress.ip_network(ip, strict=False)
        hit = [n["name"] for n in nets if n["name"] != "bridge" and any(
            net.subnet_of(ipaddress.ip_network(s)) for s in n["subnets"] if ":" not in s)]
        if hit:
            need.add(hit[0])
        else:
            internet = True
    return sorted(need) + (["bridge"] if internet or not need else [])


def pick_subnet() -> str:
    used = set()
    for name in docker("network", "ls", "-q").splitlines():
        for c in json.loads(docker("network", "inspect", name))[0].get("IPAM", {}).get("Config") or []:
            if "Subnet" in c:
                used.add(c["Subnet"])
    for _ in range(200):
        cand = f"172.31.{random.randint(1, 254)}.0/24"
        if cand not in used:
            return cand
    raise RuntimeError("no free 172.31.x.0/24 subnet")


# ------------------------------------------------------------------- plan
def build(name: str, profile: str | None, use_cve: bool = True):
    pid, cfg = load_project(name)
    nets = docker_networks()
    p = policy.build_policy(cfg, make_resolver(nets))
    strix_targets = [t for t in p["targets"] if "/" not in t or "://" in t]
    if p["level"] > 0 and p["targets"] and not strix_targets:
        p["errors"].append("Strix needs at least one URL, IP or hostname target (CIDR ranges go into the rules text)")
    instructions = p["preamble"]
    if profile:
        prof = ROOT / "profiles" / f"{profile}.md"
        if not prof.is_file():
            raise SystemExit(f"[penenv] unknown profile {profile!r}")
        instructions += "\n" + prof.read_text()
    # Research mode always carries the hypothesis-driven profile, in addition to any chosen one.
    if p.get("research") and profile != "research":
        instructions += "\n" + (ROOT / "profiles" / "research.md").read_text()
    # Host-curated CVE intelligence, injected as instruction text only (the sandbox never
    # reaches the internet for it). Best-effort: silently skipped when no library/stack.
    cve_block = cvefeed.context_for_project(cfg, enabled=use_cve)
    if cve_block:
        instructions += "\n" + cve_block
    p["cve_context"] = bool(cve_block)
    return pid, cfg, p, nets, strix_targets, instructions


def real_paths(image: str, paths: list[str]) -> dict:
    """Resolve symlinks inside the sandbox image (one short offline container)."""
    if not paths:
        return {}
    script = 'for p in "$@"; do if [ -e "$p" ]; then readlink -f "$p"; else echo MISSING; fi; done'
    out = docker("run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c", script, "sh", *paths)
    lines = out.splitlines()
    if len(lines) != len(paths):
        raise RuntimeError("could not resolve sandbox binary paths")
    return {p: (None if r == "MISSING" else r) for p, r in zip(paths, lines)}


def mounts_for(p: dict, stub: Path, work: Path, audit: Path, realpaths: dict) -> tuple[list[dict], list[str]]:
    """Deny mounts. A binary whose real file lies inside a stubbed package directory gets a stub
    copy *inside* that directory's replacement (so its symlinks still resolve to a stub); every
    other binary gets the stub mounted on its real file. Returns (mounts, notes)."""
    dirs = list(p["deny_dirs"])
    dir_src = {}
    for i, d in enumerate(dirs):
        dir_src[d] = work / f"dir{i}"
        dir_src[d].mkdir(parents=True, exist_ok=True)
    mounts, notes, files = [], [], set()
    for path in p["deny_paths"]:
        rp = realpaths.get(path, path)
        if rp is None:
            notes.append(f"{path}: not present in the image (nothing to deny)")
            continue
        holder = next((d for d in dirs if rp == d or rp.startswith(d.rstrip("/") + "/")), None)
        if holder:
            dst = dir_src[holder] / os.path.relpath(rp, holder)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(stub, dst)
            dst.chmod(0o755)
        elif rp not in files:
            files.add(rp)
            mounts.append({"source": str(stub), "target": rp, "read_only": True})
    for d in dirs:
        mounts.append({"source": str(dir_src[d]), "target": d, "read_only": True})
    mounts.append({"source": str(audit), "target": "/penenv-audit", "read_only": False})
    return mounts, notes


def strix_args(p: dict, targets: list[str], instr: Path, budget: str | None, max_turns: int | None) -> list[str]:
    a = []
    for t in targets:
        a += ["-t", t]
    if p["strix"]["whitebox"]:
        a += ["-t", p["strix"]["source_path"]]
    turns = min(p["strix"]["max_turns"], max_turns or p["strix"]["max_turns"])  # can only tighten the policy
    a += ["-m", p["strix"]["scan_mode"], "--max-turns", str(turns),
          "--instruction-file", str(instr), "-n"]
    if budget:
        a += ["--max-budget", budget]
    return a


def summary(p: dict) -> dict:
    return {"level": p["level"], "hat": p["hat"], "position": p["position"], "mode": p["strix"]["scan_mode"],
            "max_turns": p["strix"]["max_turns"], "targets": p["targets"],
            "allow_tcp": p["network"]["allow_tcp"], "deny": p["network"]["deny"],
            "conn_rate": p["network"]["conn_rate"], "bw": p["network"]["bw"],
            "switches_on": sorted(k for k, v in p["switches"].items() if v["on"]),
            "disabled_tools": p["disabled_tools"], "deny_paths": p["deny_paths"],
            "credentials": p["credentials"], "mfa": p["mfa"],
            "research": p.get("research", False), "authorisation": p.get("authorisation_ref", ""),
            "cve_context": p.get("cve_context", False), "warnings": p["warnings"]}


def print_plan(name, p, targets, nets) -> None:
    print(f"== penenv scan plan: {name} ==")
    print(f"level L{p['level']} {p['level_name']} · {p['hat']} hat · {p['position']} position · strix {p['strix']['scan_mode']} "
          f"· max-turns {p['strix']['max_turns']} · whitebox {p['strix']['whitebox']}")
    print("strix targets:", ", ".join(targets) or "(none)")
    n = p["network"]
    print("gateway allow tcp:", ", ".join(f"{a}:{b}" for a, b in n["allow_tcp"]) or "(none: zero target packets)")
    print("gateway allow udp:", ", ".join(f"{a}:{b}" for a, b in n["allow_udp"]) or "(none)")
    print("gateway deny (out of scope):", ", ".join(n["deny"]) or "(none)")
    print("soft exclusions (instruction only):", ", ".join(p["soft_exclusions"]) or "(none)")
    print(f"rate caps: {n['conn_rate']} new conn/s · {n['bw'] or 'unlimited'} bytes/s")
    print("pinned hosts:", json.dumps(n["hosts"]))
    print("gateway joins:", ", ".join(outside_networks(p, nets)) if n["contact"] else "(no outside network)")
    print("switches:")
    for s in policy.SWITCHES:
        r = p["switches"][s["id"]]
        print(f"  {'ON ' if r['on'] else 'off'} {s['id']:<18} {s['cls']:<16} {r['why']}")
    print("deny-stubbed binaries:", len(p["deny_paths"]), "· dirs:", len(p["deny_dirs"]))
    print("Strix tools removed:", ", ".join(p["disabled_tools"]) or "-")
    print("penenv tools:", ", ".join(p["penenv_tools"]) or "-")
    print("credentials (labels only; secrets are fetched by the agent through the audited channel):",
          ", ".join(p["credentials"]) or "-")
    if p.get("research"):
        print(f"research mode: ON (authorisation: {p.get('authorisation_ref') or '(inline)'})")
    print("CVE intelligence injected:", "yes" if p.get("cve_context") else "no")
    for w in p["warnings"]:
        print("WARNING:", w)
    for e in p["errors"]:
        print("ERROR:", e)


# -------------------------------------------------------------- execution
def gateway_counters(gw: str) -> dict:
    try:
        data = json.loads(docker("exec", gw, "nft", "-j", "list", "chain", "inet", "penenv", "forward"))
    except (RuntimeError, ValueError):
        return {}
    out = {}
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        comment = rule.get("comment", "")
        for ex in rule.get("expr", []):
            if "counter" in ex and comment:
                out[comment] = out.get(comment, 0) + ex["counter"]["packets"]
    return out


def start_gateway(p: dict, nets: list[dict], sid: str, net: str, gw: str, poldir: Path) -> tuple[str, str, int]:
    """Internal scan network (host has no IP on it) + egress gateway holding the policy ruleset."""
    subnet = pick_subnet()
    gw_ip = str(ipaddress.ip_network(subnet)[2])
    docker("network", "create", "--internal", "--subnet", subnet,
           "-o", "com.docker.network.bridge.inhibit_ipv4=true", "--label", f"penenv-scan={sid}", net)
    (poldir / "rules.nft").write_text(policy.render_nft(p, subnet))
    docker("create", "--name", gw, "--network", net, "--ip", gw_ip, "--cap-add", "NET_ADMIN",
           "--sysctl", "net.ipv4.ip_forward=1", "-p", f"127.0.0.1::{CAIDO_PORT}", "-e", f"GW_IP={gw_ip}",
           "-v", f"{poldir}:/policy:ro", "--label", f"penenv-scan={sid}", GW_IMAGE)
    if p["network"]["contact"]:
        for n in outside_networks(p, nets):
            docker("network", "connect", n, gw)
    else:
        docker("network", "connect", "bridge", gw)  # host-side Caido channel only; allowlist is empty
    docker("start", gw)
    for _ in range(20):
        if "ready" in docker("logs", gw, check=False):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(f"gateway did not load its ruleset: {docker('logs', gw, check=False)[-400:]}")
    port = int(docker("port", gw, f"{CAIDO_PORT}/tcp").splitlines()[0].rsplit(":", 1)[1])
    return subnet, gw_ip, port


def stop_gateway(net: str, gw: str) -> None:
    for c in docker("ps", "-aq", "--filter", f"network={net}", check=False).splitlines():
        docker("rm", "-f", c, check=False)
    docker("rm", "-f", gw, check=False)
    docker("network", "rm", net, check=False)


def exit_meaning(rc: int) -> str:
    """Strix -n exits 2 when findings meet --fail-on (strix/interface/main.py:551); not a failure."""
    return {0: " = clean", 2: " = completed, findings reported"}.get(rc, " = error")


def run(args) -> int:
    pid, cfg, p, nets, targets, instructions = build(args.project, args.profile,
                                                     use_cve=not args.no_cve)
    print_plan(args.project, p, targets, nets)
    if p["errors"]:
        log("plan has errors; nothing was started")
        return 2
    if args.dry_run:
        print("\n== gateway ruleset ==\n" + policy.render_nft(p, "172.31.X.0/24"))
        print("== rules of engagement given to the agent ==\n" + p["preamble"])
        return 0
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode:
        raise SystemExit("[penenv] docker is not accessible (run through bin/penenv)")

    kdbx_pw = ""
    if "get_mfa_code" in p["penenv_tools"] and p["mfa"]:
        if args.kdbx_password_file:
            f = Path(args.kdbx_password_file)
            if f.stat().st_mode & 0o077:
                raise SystemExit("[penenv] --kdbx-password-file must be mode 0600")
            kdbx_pw = f.read_text().rstrip("\n")
        else:
            kdbx_pw = getpass.getpass("KeePassXC authenticator master password (for MFA during the scan): ")

    sid = secrets.token_hex(4)
    net, gw = f"penenv-scan-{sid}", f"penenv-gw-{sid}"
    audit = AUDIT_ROOT / sid
    audit.mkdir(parents=True, mode=0o700)
    (audit / "denied.log").touch()
    os.chmod(audit, 0o777)  # the sandbox's pentester (uid 1000) and root both append here
    work = Path(tempfile.mkdtemp(prefix=f"penenv-{sid}-"))
    stub, poldir = work / "deny-stub", work / "policy"
    stub.write_text(STUB)
    stub.chmod(0o755)
    poldir.mkdir()
    tok = api("POST", f"/api/projects/{pid}/scan-token", {"run_label": f"scan-{sid}", "policy_summary": summary(p)})
    token, scan_id = tok["token"], tok["scan_id"]
    events = [{"kind": "plan", "detail": json.dumps(summary(p))[:3900]}]
    rc = 1
    try:
        subnet, gw_ip, port = start_gateway(p, nets, sid, net, gw, poldir)
        image = os.environ.get("STRIX_IMAGE") or json.loads(
            (Path.home() / ".strix/cli-config.json").read_text()).get("env", {}).get("STRIX_IMAGE") \
            or "ghcr.io/usestrix/strix-sandbox:1.4.1"
        mounts, notes = mounts_for(p, stub, work / "dirs", audit, real_paths(image, p["deny_paths"]))
        events += [{"kind": "note", "detail": n} for n in notes]
        instr = audit / "instructions.md"
        instr.write_text(instructions)
        launch = audit / "launch.json"
        launch.write_text(json.dumps({
            "disabled_tools": p["disabled_tools"], "penenv_tools": p["penenv_tools"],
            "tracker_url": TRACKER, "token": token, "mounts": mounts,
            "audit_dir": str(audit), "gateway": gw, "gateway_ip": gw_ip, "gateway_published_port": port,
            "hosts": {h: ips[0] for h, ips in p["network"]["hosts"].items() if ips}}))
        launch.chmod(0o600)
        env = {k: v for k, v in os.environ.items() if k not in ("PERPLEXITY_API_KEY", "EXA_API_KEY")
               or p["switches"]["web_search"]["on"]}
        env.pop("NVD_API_KEY", None)  # host-side CVE feed credential; never handed to the agent
        env.update(p["strix"]["env"], STRIX_DOCKER_SANDBOX_NETWORK=net, PENENV_LAUNCH=str(launch),
                   STRIX_RUN_TYPE="penenv")
        fds = ()
        if kdbx_pw:
            r, w = os.pipe()
            os.write(w, (kdbx_pw + "\n").encode())
            os.close(w)
            env["PENENV_KDBX_FD"] = str(r)
            fds = (r,)
        before = set(os.listdir(ROOT / "strix_runs")) if (ROOT / "strix_runs").is_dir() else set()
        cmd = [str(STRIX_PY), str(LAUNCHER), *strix_args(p, targets, instr, args.max_budget, args.max_turns)]
        log(f"scan {sid}: network {net} ({subnet}), gateway {gw} {gw_ip}, Caido channel 127.0.0.1:{port}")
        events.append({"kind": "start", "detail": " ".join(cmd[2:])[:3900]})
        rc = subprocess.run(cmd, cwd=ROOT, env=env, pass_fds=fds).returncode
        for fd in fds:
            os.close(fd)
        after = set(os.listdir(ROOT / "strix_runs")) if (ROOT / "strix_runs").is_dir() else set()
        new_runs = sorted(after - before)
        events.append({"kind": "end", "detail": f"strix exit {rc}{exit_meaning(rc)}; runs: {', '.join(new_runs) or '-'}"})
        (audit / "runs.txt").write_text("\n".join(new_runs))
    except Exception as e:  # noqa: BLE001
        events.append({"kind": "error", "detail": str(e)[:3900]})
        log(f"ERROR: {e}")
    finally:
        counters = gateway_counters(gw)
        events.append({"kind": "gateway_counters", "detail": json.dumps(counters)})
        (audit / "gateway-counters.json").write_text(json.dumps(counters))
        for line in (audit / "denied.log").read_text(errors="replace").splitlines()[:2000]:
            parts = line.split("\t", 2)
            events.append({"kind": "policy_denied", "at": parts[0],
                           "detail": " ".join(parts[1:])[:3900]})
        api("POST", "/api/scan-channel/events", {"token": token, "events": events})
        api("POST", "/api/scan-channel/revoke", {"token": token})
        if not args.keep:
            stop_gateway(net, gw)
        shutil.rmtree(work, ignore_errors=True)
        os.chmod(audit, 0o700)  # the sandbox needed write access only while it ran
        log(f"scan {sid} finished (exit {rc}{exit_meaning(rc)}); denied invocations: "
            f"{sum(1 for e in events if e['kind'] == 'policy_denied')}; gateway drops: "
            f"out-of-scope {counters.get('out-of-scope', 0)}, not-in-scope {counters.get('not-in-scope', 0)}")
    try:
        api("POST", "/api/ingest", {})
    except SystemExit as e:
        log(f"ingest failed: {e}")
    log(f"audit trail: {audit}  ·  tracker scan id {scan_id}")
    return rc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="penenv scan --project")
    ap.add_argument("--project", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("-p", "--profile")
    ap.add_argument("--max-budget")
    ap.add_argument("--kdbx-password-file", help="0600 file holding the authenticator master password")
    ap.add_argument("--keep", action="store_true", help="keep gateway/network for inspection")
    ap.add_argument("--max-turns", type=int, help="lower the per-agent turn cap (never raises the policy value)")
    ap.add_argument("--no-cve", action="store_true",
                    help="do not inject host-curated CVE intelligence into the agent instructions")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
