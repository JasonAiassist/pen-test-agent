"""T5.2 demo: deny stubs inside the real sandbox image (re-runnable, needs docker access).

Builds the mounts exactly as a scan does (scanrun.mounts_for on an L0 policy, where every
binary switch is off), then for every stubbed binary checks that running it by name, by
absolute path, via `bash -c`, via `sudo` and via its package directory all fail, and that
each attempt lands in the audit log. A control run without mounts proves the tools are real.

    echo "python3 scripts/stub-check.py" | newgrp docker
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tracker"))
import policy  # noqa: E402
import scanrun  # noqa: E402

IMG = "ghcr.io/usestrix/strix-sandbox:1.4.1"
cfg = {"hat": "white", "aggression": 0, "switches": {}, "endpoints": [], "out_of_scope": [], "keysafe": []}
p = policy.build_policy(cfg, lambda h: [])
work = Path(tempfile.mkdtemp(prefix="stubcheck-"))
stub, audit = work / "stub", work / "audit"
stub.write_text(scanrun.STUB)
stub.chmod(0o755)
audit.mkdir()
os.chmod(audit, 0o777)
(audit / "denied.log").touch()
os.chmod(audit / "denied.log", 0o666)
mounts, notes = scanrun.mounts_for(p, stub, work / "dirs", audit, scanrun.real_paths(IMG, p["deny_paths"]))
print("notes:", notes or "-")
print("mounts:", len(mounts))

checks = []
for s in policy.SWITCHES:
    for path in s.get("paths", []):
        name = Path(path).name
        checks += [(s["id"], "name", f"{name} --help"), (s["id"], "abs", f"{path} --help"),
                   (s["id"], "bash-c", f"bash -c '{name} --help'"), (s["id"], "sudo", f"sudo -n {path} --help")]
    for d in s.get("dirs", []):
        checks.append((s["id"], "pkgdir", f"find {d} -type f ! -exec grep -q 'penenv deny stub' {{}} \\; -print | grep -q . && exit 0 || exit 1"))
# well-known aliases that resolve to stubbed files
checks += [("netcat", "alias", "nc -h"), ("netcat", "alias", "netcat -h"),
           ("sqlmap", "pkg", "python3 /usr/share/sqlmap/sqlmap.py --version"),
           ("nmap", "pkg", "/usr/lib/nmap/nmap --version"),
           ("browser", "pkg", "/usr/lib/chromium/chromium --version"),
           ("browser", "alias", "agent-browser --version")]

script = "\n".join(f"( {c} ) >/dev/null 2>&1; echo \"{sid}|{how}|$?\"" for sid, how, c in checks)
args = ["docker", "run", "--rm", "--network", "none", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
        "--entrypoint", "bash"]
for m in mounts:
    args += ["--mount", f"type=bind,source={m['source']},target={m['target']}" + (",readonly" if m["read_only"] else "")]
res = subprocess.run(args + [IMG, "-c", script + "\nsudo -n umount /usr/bin/sqlmap; echo \"umount|root|$?\""],
                     capture_output=True, text=True)
if res.returncode and not res.stdout: print("docker run failed:", res.stderr[-1500:])
rows = [ln.split("|") for ln in res.stdout.splitlines() if ln.count("|") == 2]
fails = [r for r in rows if r[2] == "0"]
print(f"{len(rows)} denial checks across {len({r[0] for r in rows})} switches; succeeded (BAD): {len(fails)}")
for r in rows:
    print(f"  {'FAIL' if r[2] == '0' else 'ok  '} {r[0]:<16} {r[1]:<7} exit {r[2]}")
logged = (audit / "denied.log").read_text().splitlines()
print(f"audit log lines: {len(logged)}; sample: {logged[:2]}")

control = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "bash", IMG, "-c",
                          "sqlmap --version >/dev/null 2>&1; echo sqlmap=$?; nuclei -version >/dev/null 2>&1; echo nuclei=$?; "
                          "curl --version >/dev/null; echo curl=$?"], capture_output=True, text=True)
print("control without stubs:", control.stdout.split())
ok = not fails and rows and len(logged) >= sum(1 for r in rows if r[1] in ("name", "abs", "bash-c", "sudo"))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
