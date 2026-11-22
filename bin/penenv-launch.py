"""penenv Strix launcher: applies one scan policy inside the Strix process, then runs Strix.

Run with Strix's own interpreter (penenv does this):
    ~/.local/share/uv/tools/strix-agent/bin/python bin/penenv-launch.py <strix args...>
with PENENV_LAUNCH=<launch.json> (written by tracker/scanrun.py, mode 0600).

What it enforces (see docs/enforcement-matrix.md):
  HARD-tool    removes disabled Strix function tools before any agent is built;
               registers get_test_credential / get_mfa_code only when allowed
  HARD-binary  adds read-only deny-stub bind mounts to the sandbox container
  HARD-net     points the sandbox at the egress gateway: default route, pinned
               /etc/hosts entries, and the gateway DNAT for Strix's Caido channel
Every step fails closed: if a hook point is missing (Strix version drift) the
launcher aborts instead of scanning without the policy.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

CAIDO_PORT = 48080
SUPPORTED_STRIX = ("1.7.",)


def die(msg: str) -> None:
    print(f"[penenv-launch] REFUSING TO SCAN: {msg}", file=sys.stderr)
    sys.exit(3)


def load_launch() -> dict:
    path = os.environ.get("PENENV_LAUNCH")
    if not path:
        die("PENENV_LAUNCH is not set")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


L = load_launch()
KDBX_PASSWORD = ""
if os.environ.get("PENENV_KDBX_FD"):
    with os.fdopen(int(os.environ.pop("PENENV_KDBX_FD")), encoding="utf-8") as f:
        KDBX_PASSWORD = f.read().rstrip("\n")

if not os.environ.get("STRIX_DOCKER_SANDBOX_NETWORK"):
    die("STRIX_DOCKER_SANDBOX_NETWORK is not set (the sandbox would bypass the gateway)")

import importlib.metadata  # noqa: E402

try:
    _ver = importlib.metadata.version("strix-agent")
except importlib.metadata.PackageNotFoundError:
    _ver = "?"
if not _ver.startswith(SUPPORTED_STRIX):
    die(f"strix-agent {_ver} is not a version this launcher was verified against ({SUPPORTED_STRIX})")

from agents import function_tool  # noqa: E402
from agents.sandbox.types import ExposedPortEndpoint  # noqa: E402

import strix.agents.factory as factory  # noqa: E402
from strix.runtime import docker_client as dc  # noqa: E402


# ---- HARD-tool: remove disabled function tools -------------------------------
_names = {t.name for t in factory._BASE_TOOLS}
_unknown = set(L["disabled_tools"]) - _names
if _unknown:
    die(f"policy disables tools Strix does not have: {sorted(_unknown)}")
factory._BASE_TOOLS = tuple(t for t in factory._BASE_TOOLS if t.name not in set(L["disabled_tools"]))
print(f"[penenv-launch] removed {len(_names) - len(factory._BASE_TOOLS)} Strix tools: "
      f"{', '.join(sorted(L['disabled_tools'])) or '-'}", file=sys.stderr)


def _channel(op: str, body: dict) -> dict:
    req = urllib.request.Request(f"{L['tracker_url']}/api/scan-channel/{op}",
                                 data=json.dumps({"token": L["token"], **body}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return {"error": json.loads(e.read()).get("error", str(e))}
        except ValueError:
            return {"error": str(e)}
    except OSError as e:
        return {"error": f"tracker unreachable: {e}"}


@function_tool
def get_test_credential(login_label: str) -> str:
    """Return the test-account login (username, password, login URL, domain, API key) for one keysafe
    login, by its label. Every call is audited. Never copy the password into a report."""
    return json.dumps(_channel("credential", {"label": login_label}))


@function_tool
def get_mfa_code(login_label: str) -> str:
    """Return the current one-time MFA code (TOTP) for one keysafe login, by its label, from the
    penenv KeePassXC authenticator. Codes rotate every 30 seconds; use it immediately. Audited."""
    return json.dumps(_channel("otp", {"label": login_label, "kdbx_password": KDBX_PASSWORD}))


_extra = [t for t in (get_test_credential, get_mfa_code) if t.name in L["penenv_tools"]]
if _extra:
    factory.register_agent_tools(*_extra)
    print(f"[penenv-launch] registered: {', '.join(t.name for t in _extra)}", file=sys.stderr)


# ---- HARD-binary: deny-stub bind mounts ---------------------------------------
_orig_create = dc.StrixDockerSandboxClient._create_container


async def _create_container(self, image, **kw):
    self.strix_bind_mounts = list(self.strix_bind_mounts or []) + list(L["mounts"])
    container = await _orig_create(self, image, **kw)
    mounted = {m.get("Target") for m in container.attrs.get("HostConfig", {}).get("Mounts") or []}
    missing = [m["target"] for m in L["mounts"] if m["target"] not in mounted]
    if missing:
        container.remove(force=True)
        die(f"deny mounts missing from the sandbox: {missing[:5]}")
    return container


dc.StrixDockerSandboxClient._create_container = _create_container


# ---- HARD-net: route via the gateway; Caido channel through the gateway -------
_orig_resolve = dc.StrixDockerSandboxSession._resolve_exposed_port


def _exec(container, cmd: list[str], what: str) -> None:
    res = container.exec_run(cmd, user="root")
    if res.exit_code != 0:
        die(f"{what} failed ({res.exit_code}): {res.output.decode(errors='replace')[:300]}")


async def _resolve_exposed_port(self, port: int):
    ep = await _orig_resolve(self, port)        # sandbox IP on the internal network
    if port != CAIDO_PORT:
        die(f"unexpected exposed port {port}")
    if getattr(self, "_penenv_ready", False):
        return ExposedPortEndpoint(host="127.0.0.1", port=L["gateway_published_port"], tls=False)
    sb = self._container
    gw = sb.client.containers.get(L["gateway"])
    _exec(sb, ["ip", "route", "replace", "default", "via", L["gateway_ip"]], "sandbox default route")
    if L["hosts"]:
        lines = "".join(f"{ip}\t{name}\n" for name, ip in L["hosts"].items())
        _exec(sb, ["sh", "-c", f"printf '%s' '{lines}' >> /etc/hosts"], "sandbox /etc/hosts")
    inner = gw.exec_run(["cat", "/run/penenv-inner"]).output.decode().strip()
    if not inner:
        die("gateway did not report its scan-network interface")
    _exec(gw, ["nft", "add", "rule", "inet", "penenv", "pre", "iifname", "!=", inner, "tcp", "dport",
               str(CAIDO_PORT), "dnat", "ip", "to", f"{ep.host}:{CAIDO_PORT}"], "gateway Caido DNAT")
    self._penenv_ready = True
    with open(os.path.join(L["audit_dir"], "sandbox.json"), "w", encoding="utf-8") as f:
        json.dump({"container": sb.name, "ip": ep.host}, f)
    print(f"[penenv-launch] sandbox {sb.name} ({ep.host}) routed via gateway {L['gateway_ip']}", file=sys.stderr)
    return ExposedPortEndpoint(host="127.0.0.1", port=L["gateway_published_port"], tls=False)


dc.StrixDockerSandboxSession._resolve_exposed_port = _resolve_exposed_port

if __name__ == "__main__":
    from strix.interface.main import main

    sys.argv[0] = "strix"
    if L.get("dry_check"):
        print("[penenv-launch] hooks installed; dry check only", file=sys.stderr)
        sys.exit(0)
    sys.exit(main())
