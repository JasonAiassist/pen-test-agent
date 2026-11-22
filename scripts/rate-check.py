"""T4.3 demo: measured request rate through the gateway stays under the level cap.

For each level, stands up the real scan network + gateway (scanrun.start_gateway) for a
White-hat policy on the demo app, starts a sandbox exactly as Strix does, and hammers the
target from inside with 40 parallel workers for 15 s (one new connection per request).

    echo "python3 scripts/rate-check.py" | newgrp docker
"""
import json
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tracker"))
import policy  # noqa: E402
import scanrun  # noqa: E402
from scanrun import docker  # noqa: E402

IMG = "ghcr.io/usestrix/strix-sandbox:1.4.1"
DURATION = 15
LOAD = r'''
import sys, threading, time, urllib.request
url, dur = sys.argv[1], float(sys.argv[2])
start = time.time(); end = start + dur; done = []; err = [0]
def w():
    while time.time() < end:
        try:
            req = urllib.request.Request(url, headers={"Connection": "close"})
            with urllib.request.urlopen(req, timeout=3) as r:
                r.read(64)
            done.append(time.time())
        except Exception:
            err[0] += 1
ts = [threading.Thread(target=w) for _ in range(40)]
[t.start() for t in ts]; [t.join() for t in ts]
# steady state: completions inside [start+2s, end], so the initial burst and late SYN retries are excluded
steady = [t for t in done if start + 2 <= t <= end]
print(len(done), err[0], len(steady), dur - 2)
'''

nets = scanrun.docker_networks()
resolve = scanrun.make_resolver(nets)
results, ok_all = [], True
for level in (1, 2, 3):
    cfg = {"hat": "white", "aggression": level, "switches": {}, "keysafe": [], "out_of_scope": [],
           "endpoints": [{"type": "url", "data": "http://juice-shop:3000"}]}
    p = policy.build_policy(cfg, resolve)
    assert not p["errors"], p["errors"]
    ip = p["network"]["hosts"]["juice-shop"][0]
    sid = "rate" + secrets.token_hex(3)
    net, gw = f"penenv-scan-{sid}", f"penenv-gw-{sid}"
    pol = Path(tempfile.mkdtemp())
    try:
        subnet, gw_ip, _ = scanrun.start_gateway(p, nets, sid, net, gw, pol)
        sb = f"penenv-sb-{sid}"
        docker("run", "-d", "--name", sb, "--network", net, "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
               "--entrypoint", "tail", IMG, "-f", "/dev/null")
        docker("exec", "--user", "root", sb, "ip", "route", "replace", "default", "via", gw_ip)
        out = docker("exec", sb, "python3", "-c", LOAD, f"http://{ip}:3000/rest/admin/application-version",
                     str(DURATION))
        done, errs, steady, window = out.split()
        done, errs, steady, window = int(done), int(errs), int(steady), float(window)
        cnt = scanrun.gateway_counters(gw)
        cap, burst = p["network"]["conn_rate"], p["network"]["conn_rate"]
        rate = steady / window                 # sustained request rate at the target
        limit = cap                            # strict: the configured cap is a ceiling
        passed = rate <= limit and steady > 0
        ok_all &= passed
        results.append({"level": level, "cap_per_s": cap, "measured_per_s": round(rate, 2), "allowed_max_per_s": round(limit, 2), "completed": done,
                        "failed_or_dropped": errs, "gateway_conn_cap_drops": cnt.get("conn-cap", 0),
                        "gateway_accepted": cnt.get("in-scope-tcp", 0), "pass": passed})
    finally:
        scanrun.stop_gateway(net, gw)
for r in results:
    print(json.dumps(r))
print("RESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
