"""Scan policy builder (T4.2): (aggression, hat, switches) -> one resolved policy.

Pure and stdlib-only. The policy drives every enforcement point:
  - HARD-net     gateway nftables ruleset (render_nft)
  - HARD-binary  deny-stub bind mounts (deny_paths)
  - HARD-tool    Strix function tools removed / penenv tools registered
  - HARD-config  Strix flags and env
  - SOFT-method  rules-of-engagement preamble
docs/enforcement-matrix.md is the human-readable copy of the tables below.

Precedence: switch > aggression level > hat level > profile defaults, with
invariants nothing overrides: out-of-scope is always dropped, Black hat never
gets credential tools, DoS/destructive need a written authorisation reference.
"""
from __future__ import annotations

import ipaddress
from typing import Callable
from urllib.parse import urlsplit

import authorisation
import scope

# ------------------------------------------------------------------ levels
LEVELS = {
    0: {"name": "Passive recon", "mode": "quick", "max_turns": 40, "conn_rate": 0, "bw": 0},
    1: {"name": "Non-intrusive", "mode": "quick", "max_turns": 120, "conn_rate": 5, "bw": 256 * 1024},
    2: {"name": "Standard", "mode": "standard", "max_turns": 300, "conn_rate": 20, "bw": 1024 * 1024},
    3: {"name": "Aggressive", "mode": "standard", "max_turns": 500, "conn_rate": 50, "bw": 4 * 1024 * 1024},
    4: {"name": "Very aggressive", "mode": "deep", "max_turns": 500, "conn_rate": 150, "bw": 10 * 1024 * 1024},
    5: {"name": "Destructive", "mode": "deep", "max_turns": 500, "conn_rate": 500, "bw": None},
}

METHOD_RULES = {
    0: "OSINT only. Do not send any packet to the target (the network blocks it anyway).",
    1: "Non-intrusive only: browse, crawl and fingerprint. No fuzzing, no injection payloads, "
       "no brute force. nmap only as -sT/-sV against the top 100 ports.",
    2: "Standard testing. sqlmap at most --risk 1 --level 2. nuclei must exclude the dos,intrusive tags. "
       "Small wordlists only. Prove a finding, do not exploit beyond proof.",
    3: "Aggressive testing. sqlmap at most --risk 2 --level 3. nuclei must exclude the dos tag. "
       "Proof-of-concept exploit chains on confirmed findings are allowed.",
    4: "Very aggressive testing. sqlmap --risk 3 allowed. Larger wordlists and higher request rates allowed.",
    5: "Destructive-capable testing, limited to what the switches below allow.",
}

H = "/home/pentester"
PIPX = f"{H}/.local/share/pipx/venvs"

# id, label, class, auto-on rule, binaries, directories, strix tools, note
# auto rule: int = on from that level; "never" = off unless switched on;
#            "source" = on when a source path is set; "creds" = on unless Black hat
SWITCHES: list[dict] = [
    {"id": "nmap", "label": "nmap port/service scanning", "cls": "HARD-binary", "auto": 1,
     "paths": ["/usr/bin/nmap"], "dirs": ["/usr/lib/nmap"]},
    {"id": "naabu", "label": "naabu fast port scanner", "cls": "HARD-binary", "auto": 3,
     "paths": ["/usr/bin/naabu"]},
    {"id": "httpx", "label": "httpx HTTP probing", "cls": "HARD-binary", "auto": 1,
     "paths": [f"{H}/go/bin/httpx"]},
    {"id": "katana", "label": "katana crawler", "cls": "HARD-binary", "auto": 1,
     "paths": [f"{H}/go/bin/katana"]},
    {"id": "wafw00f", "label": "wafw00f WAF fingerprinting", "cls": "HARD-binary", "auto": 1,
     "paths": [f"{H}/.local/bin/wafw00f"], "dirs": [f"{PIPX}/wafw00f"]},
    {"id": "ffuf", "label": "ffuf web fuzzing", "cls": "HARD-binary", "auto": 2,
     "paths": ["/usr/bin/ffuf"]},
    {"id": "dirsearch", "label": "dirsearch content discovery", "cls": "HARD-binary", "auto": 2,
     "paths": [f"{H}/.local/bin/dirsearch"], "dirs": [f"{PIPX}/dirsearch"]},
    {"id": "arjun", "label": "arjun parameter discovery", "cls": "HARD-binary", "auto": 2,
     "paths": [f"{H}/.local/bin/arjun"], "dirs": [f"{PIPX}/arjun"]},
    {"id": "nuclei", "label": "nuclei vulnerability templates", "cls": "HARD-binary", "auto": 2,
     "paths": ["/usr/bin/nuclei"], "dirs": [f"{H}/.local/nuclei-templates"]},
    {"id": "sqlmap", "label": "sqlmap SQL injection automation", "cls": "HARD-binary", "auto": 2,
     "paths": ["/usr/bin/sqlmap"], "dirs": ["/usr/share/sqlmap"]},
    {"id": "jwt_tool", "label": "jwt_tool token attacks", "cls": "HARD-binary", "auto": 2,
     "paths": [f"{H}/.local/bin/jwt_tool"]},
    {"id": "netcat", "label": "netcat / ncat raw sockets", "cls": "HARD-binary", "auto": 2,
     "paths": ["/usr/bin/nc.traditional", "/usr/bin/ncat"]},
    {"id": "browser", "label": "Headless browser (agent-browser, chromium)", "cls": "HARD-binary", "auto": 1,
     "paths": ["/usr/bin/chromium", f"{H}/.npm-global/bin/agent-browser"],
     "dirs": ["/usr/lib/chromium", f"{H}/.npm-global/lib/node_modules/agent-browser"]},
    {"id": "curl_wget", "label": "curl / wget", "cls": "HARD-binary", "auto": 1,
     "paths": ["/usr/bin/curl", "/usr/bin/wget"]},
    {"id": "oob_callbacks", "label": "Out-of-band callbacks (interactsh; data goes to a third party)",
     "cls": "HARD-binary+net", "auto": "never", "paths": [f"{H}/go/bin/interactsh-client"],
     "egress_hosts": ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]},
    {"id": "subdomain_enum", "label": "subfinder subdomain enumeration (passive sources stay blocked)",
     "cls": "HARD-binary", "auto": "never", "paths": ["/usr/bin/subfinder"]},
    {"id": "code_scanners", "label": "Source scanners (trufflehog, gitleaks, bandit)", "cls": "HARD-binary",
     "auto": "source", "paths": [f"{H}/.local/bin/trufflehog", "/usr/local/bin/gitleaks",
                                 f"{H}/.local/bin/bandit"], "dirs": [f"{PIPX}/bandit"]},
    {"id": "web_search", "label": "Web search (Perplexity/Exa; queries leave the machine)", "cls": "HARD-tool",
     "auto": "never", "tools": ["web_search", "web_get_contents"]},
    {"id": "subagents", "label": "Sub-agent spawning", "cls": "HARD-tool", "auto": 1,
     "tools": ["create_agent", "send_message_to_agent", "wait_for_agents", "stop_agent", "view_agent_graph"]},
    {"id": "mcp", "label": "MCP servers", "cls": "HARD-tool", "auto": "never",
     "tools": ["list_mcps", "search_mcp_tools", "get_mcp_tool_schema", "describe_mcp", "call_mcp"]},
    {"id": "request_replay", "label": "Proxy request replay", "cls": "HARD-tool", "auto": 1,
     "tools": ["repeat_request"]},
    {"id": "telemetry", "label": "Strix telemetry (PostHog/Scarf)", "cls": "HARD-config", "auto": "never"},
    {"id": "use_credentials", "label": "Use keysafe test credentials", "cls": "HARD-tool", "auto": "creds",
     "penenv_tool": "get_test_credential"},
    {"id": "use_mfa", "label": "Use MFA codes (KeePassXC authenticator)", "cls": "HARD-tool", "auto": "creds",
     "penenv_tool": "get_mfa_code"},
    {"id": "bruteforce", "label": "Password brute force / credential stuffing", "cls": "SOFT-method", "auto": 4},
    {"id": "dos", "label": "DoS / load testing", "cls": "SOFT-method+net", "auto": 5, "needs_auth": True},
    {"id": "destructive", "label": "Destructive / data-altering payloads", "cls": "SOFT-method", "auto": 5,
     "needs_auth": True},
    {"id": "autoexploit", "label": "Exploit confirmed findings beyond proof", "cls": "SOFT-method", "auto": 3},
    {"id": "research", "label": "Security research mode (hypothesis-driven vulnerability chaining and "
     "unknown-flaw discovery)", "cls": "SOFT-method", "auto": "never", "needs_auth": True},
    {"id": "social_engineering", "label": "Social engineering", "cls": "CONTRACT", "auto": "never"},
    {"id": "physical", "label": "Physical testing", "cls": "CONTRACT", "auto": "never"},
    {"id": "notify_critical", "label": "Alert on CRITICAL finding", "cls": "CONTRACT", "auto": "never"},
    {"id": "free_retest", "label": "Free retest included", "cls": "CONTRACT", "auto": "never"},
    {"id": "cvss", "label": "CVSS scoring required", "cls": "CONTRACT", "auto": "never"},
]
SWITCH_BY_ID = {s["id"]: s for s in SWITCHES}
STATES = ("auto", "on", "off")
TARGET_CONTACT = {s["id"] for s in SWITCHES if s["cls"].startswith("HARD-binary")}

# Legacy v2 boolean switches -> v3 ids (True -> on, False -> off: the old box meant "permitted").
LEGACY_SWITCHES = {"se": "social_engineering", "physical": "physical", "dos": "dos",
                   "destructive": "destructive", "auto_exploit": "autoexploit",
                   "creds_allowed": "use_credentials", "bruteforce": "bruteforce",
                   "notify_on_crit": "notify_critical", "retest_free": "free_retest", "cvss": "cvss"}


def migrate_switches(raw) -> dict:
    """Return a complete {id: state} map from a v2 bool map or a partial v3 map."""
    raw = raw if isinstance(raw, dict) else {}
    out = {s["id"]: "auto" for s in SWITCHES}
    for k, v in raw.items():
        sid = LEGACY_SWITCHES.get(k, k) if isinstance(v, bool) else k
        if sid not in out:
            continue
        if isinstance(v, bool):
            out[sid] = "on" if v else "off"
        elif v in STATES:
            out[sid] = v
    return out


def _auto_on(sw: dict, level: int, hat: str, has_source: bool) -> bool:
    rule = sw["auto"]
    if rule == "never":
        return False
    if rule == "source":
        return has_source
    if rule == "creds":
        return hat != "black"
    return level >= rule


def resolve_switches(cfg: dict) -> dict:
    """{id: {"on": bool, "source": "switch"|"level"|"hat"|"invariant", "why": str}}."""
    level = int(cfg.get("aggression", 2))
    hat = cfg.get("hat", "grey")
    has_source = bool((cfg.get("source_path") or "").strip())
    states = migrate_switches(cfg.get("switches"))
    authorised = bool((cfg.get("authorisation") or "").strip())
    out = {}
    for sw in SWITCHES:
        sid, st = sw["id"], states[sw["id"]]
        if st == "auto":
            on = _auto_on(sw, level, hat, has_source)
            src = "hat" if sw["auto"] == "creds" else "level"
            why = f"auto: {'on' if on else 'off'} at L{level}" + (f" / {hat} hat" if src == "hat" else "")
        else:
            on, src, why = st == "on", "switch", f"switched {st}"
        if on and sw["auto"] == "creds" and hat == "black":
            on, src, why = False, "invariant", "Black hat never carries credentials"
        if on and sw.get("needs_auth") and not authorised:
            on, src, why = False, "invariant", "needs the written authorisation reference"
        out[sid] = {"on": on, "source": src, "why": why}
    return out


def switch_warnings(cfg: dict) -> list[str]:
    """Conflicts the UI shows next to the switch grid (T5.4)."""
    level = int(cfg.get("aggression", 2))
    states = migrate_switches(cfg.get("switches"))
    res = resolve_switches(cfg)
    warns = []
    for sw in SWITCHES:
        sid, st = sw["id"], states[sw["id"]]
        if sw["cls"] == "CONTRACT":
            continue  # contract terms gate nothing executable, so they cannot conflict with a level
        auto = _auto_on(sw, level, cfg.get("hat", "grey"), bool((cfg.get("source_path") or "").strip()))
        if st == "on" and not auto and res[sid]["on"]:
            warns.append(f"'{sw['label']}' is switched on and overrides L{level}, which would keep it off")
        if st == "on" and not res[sid]["on"]:
            warns.append(f"'{sw['label']}' is switched on but stays off: {res[sid]['why']}")
        if st == "off" and auto:
            warns.append(f"'{sw['label']}' is switched off although L{level} would allow it")
    if level == 0 and any(res[s]["on"] for s in TARGET_CONTACT):
        warns.append("L0 is no longer passive: a switched-on tool opens the in-scope targets at the gateway")
    return warns


# ---------------------------------------------------------------- network
def _url_port(u) -> int:
    return u.port or (443 if u.scheme.lower() == "https" else 80)


def _v4(addrs) -> list[str]:
    return [a for a in addrs if ipaddress.ip_address(a.split("%")[0]).version == 4]


def build_network(cfg: dict, resolver: Callable[[str], list[str]]) -> dict:
    """Resolve scope entries to gateway sets. Hostnames are pinned to the IPs seen now."""
    allow_tcp, allow_udp, deny, hosts, targets = [], [], [], {}, []
    errors, warnings, soft_exclusions = [], [], []
    position = cfg.get("position") or scope.default_position(cfg.get("hat"))
    if position not in scope.POSITIONS:
        errors.append(f"unknown test position {position!r}")
        position = "external"

    def resolve(host):
        ip = scope._parse_ip(host.strip("[]"))
        if ip is not None:
            return [str(ip)]
        addrs = resolver(host)
        if addrs:
            hosts[host] = _v4(addrs)[:1] or addrs[:1]
        return addrs

    for i, e in enumerate(cfg.get("endpoints") or []):
        t, d = e.get("type"), e.get("data", "")
        if scope.validate_endpoint(t, d):
            errors.append(f"in-scope row {i + 1} is invalid: {d!r}")
            continue
        if position != "both":
            # Re-checked at scan time: DNS may have changed since the project was saved, and an
            # unresolvable name is refused rather than guessed.
            verdict, why = scope.classify_exposure(t, d, resolver)
            want = "public" if position == "external" else "internal"
            if verdict != want:
                errors.append(f"{position} test position, in-scope {d!r}: "
                              f"{why or ('internet-facing' if verdict == 'public' else 'not ' + want)} "
                              "(re-checked at scan time)")
                continue
        if t == "cidr":
            net = ipaddress.ip_network(d, strict=False)
            if net.version != 4:
                errors.append(f"{d}: IPv6 targets are not supported by the scan network")
                continue
            allow_tcp.append((str(net), "0-65535"))
            allow_udp.append((str(net), "0-65535"))
            targets.append(str(net))
            continue
        host = scope.host_of(t, d)
        hip = scope._parse_ip(host.strip("[]"))
        if host == "localhost" or host.endswith(".localhost") or (hip is not None and hip.is_loopback):
            errors.append(f"{d!r} is a loopback address: the sandbox cannot reach the host. "
                          "Use the container name (e.g. http://juice-shop:3000) or a reachable IP")
            continue
        addrs = _v4(resolve(host))
        if not addrs:
            errors.append(f"{d!r}: {host} does not resolve to an IPv4 address")
            continue
        if t == "url":
            u = urlsplit(d)
            for a in addrs:
                allow_tcp.append((a, str(_url_port(u))))
            targets.append(d)
        else:
            for a in addrs:
                allow_tcp.append((a, "0-65535"))
                allow_udp.append((a, "0-65535"))
            targets.append(d if t == "ip" else host)

    allowed_ips = {a for a, _ in allow_tcp}
    allowed_nets = [ipaddress.ip_network(a) for a, _ in allow_tcp]
    for i, e in enumerate(cfg.get("out_of_scope") or []):
        t, d = e.get("type"), e.get("data", "")
        if scope.validate_endpoint(t, d):
            errors.append(f"out-of-scope row {i + 1} is invalid: {d!r}")
            continue
        if t in ("ip", "cidr"):
            net = ipaddress.ip_network(d, strict=False)
            if net.version == 4:
                deny.append(str(net))
                if any(net.overlaps(n) for n in allowed_nets):
                    warnings.append(f"out-of-scope {d} overlaps in-scope addresses; out-of-scope wins (dropped)")
            continue
        host = scope.host_of(t, d)
        addrs = _v4(resolver(host)) if not scope._parse_ip(host.strip("[]")) else [host.strip("[]")]
        shared = [a for a in addrs if a in allowed_ips]
        if t == "url" or shared:
            # A path, or a name sharing an IP with an in-scope target (virtual hosting): the network
            # cannot separate it, so it becomes a SOFT exclusion (preamble + Caido scope rule).
            soft_exclusions.append(d)
            if shared and t != "url":
                warnings.append(f"out-of-scope {d} shares {shared[0]} with an in-scope target: "
                                "excluded by instruction only (cannot be separated at the network layer)")
            elif t == "url" and not shared:
                deny.extend(addrs)
            continue
        deny.extend(addrs)
    deny = sorted({str(ipaddress.ip_network(d, strict=False)) for d in deny})
    return {"position": position, "allow_tcp": allow_tcp, "allow_udp": allow_udp, "deny": deny, "hosts": hosts,
            "targets": targets, "soft_exclusions": soft_exclusions, "errors": errors, "warnings": warnings}


# ----------------------------------------------------------------- policy
def build_policy(cfg: dict, resolver: Callable[[str], list[str]] = scope.default_resolver) -> dict:
    level = max(0, min(5, int(cfg.get("aggression", 2))))
    hat = cfg.get("hat", "grey")
    lv = LEVELS[level]
    sw = resolve_switches(cfg)
    net = build_network(cfg, resolver)
    errors, warnings = list(net["errors"]), list(net["warnings"]) + switch_warnings(cfg)

    contact = level > 0 or any(sw[s]["on"] for s in TARGET_CONTACT)
    conn_rate, bw = lv["conn_rate"], lv["bw"]
    if sw["dos"]["on"]:
        conn_rate, bw = LEVELS[5]["conn_rate"], LEVELS[5]["bw"]
    if contact and conn_rate == 0:
        conn_rate, bw = LEVELS[1]["conn_rate"], LEVELS[1]["bw"]
    if not contact:
        net["allow_tcp"], net["allow_udp"] = [], []

    egress_hosts = []
    for s in SWITCHES:
        if sw[s["id"]]["on"]:
            egress_hosts += s.get("egress_hosts", [])
    for h in egress_hosts:
        for a in _v4(resolver(h)):
            net["allow_tcp"] += [(a, "80"), (a, "443")]

    deny_paths, deny_dirs, disabled_tools, penenv_tools = [], [], [], []
    for s in SWITCHES:
        if sw[s["id"]]["on"]:
            if s.get("penenv_tool"):
                penenv_tools.append(s["penenv_tool"])
            continue
        deny_paths += s.get("paths", [])
        deny_dirs += s.get("dirs", [])
        disabled_tools += s.get("tools", [])

    creds = [c for c in (cfg.get("keysafe") or []) if isinstance(c, dict)]
    if hat == "black" and creds:
        errors.append("Black hat project carries credentials")
    whitebox = hat == "white" and bool((cfg.get("source_path") or "").strip())
    if not net["targets"] and level > 0:
        errors.append("no usable in-scope target")

    # Research mode contract gate (fail-closed): external/destructive/DoS research needs a
    # structured, unexpired authorisation record whose scope covers every in-scope target.
    research = sw["research"]["on"]
    authorisation_ref = ""
    if research:
        rec = authorisation.load_record(cfg)
        ok, reasons = authorisation.authorise_research(
            rec, position=net["position"], destructive=sw["destructive"]["on"],
            dos=sw["dos"]["on"], in_scope=cfg.get("endpoints") or [])
        if ok:
            authorisation_ref = (rec or {}).get("ref", "")
        else:
            research = False
            sw["research"] = {"on": False, "source": "invariant",
                              "why": "research mode refused: " + "; ".join(reasons)}
            errors += ["research mode refused: " + r for r in reasons]

    policy = {
        "level": level, "level_name": lv["name"], "hat": hat, "position": net["position"],
        "strix": {"scan_mode": lv["mode"], "max_turns": lv["max_turns"], "whitebox": whitebox,
                  "source_path": (cfg.get("source_path") or "").strip() if whitebox else "",
                  "env": {"STRIX_TELEMETRY": "1" if sw["telemetry"]["on"] else "0"}},
        "targets": net["targets"],
        "network": {"allow_tcp": net["allow_tcp"], "allow_udp": net["allow_udp"], "deny": net["deny"],
                    "hosts": net["hosts"], "conn_rate": conn_rate if contact else 0, "bw": bw if contact else 0,
                    "contact": contact},
        "deny_paths": deny_paths, "deny_dirs": deny_dirs,
        "disabled_tools": disabled_tools, "penenv_tools": penenv_tools,
        "credentials": [c.get("label") or c.get("username") for c in creds] if "get_test_credential" in penenv_tools else [],
        "mfa": [c.get("label") or c.get("username") for c in creds if c.get("otp_ref")] if "get_mfa_code" in penenv_tools else [],
        "switches": sw, "soft_exclusions": net["soft_exclusions"],
        "research": research, "authorisation_ref": authorisation_ref,
        "errors": errors, "warnings": warnings,
    }
    policy["preamble"] = render_preamble(cfg, policy)
    return policy


def render_preamble(cfg: dict, p: dict) -> str:
    sw = p["switches"]
    agent_facing = [k for k in sw if SWITCH_BY_ID[k]["cls"] not in ("CONTRACT", "HARD-config")]
    on = [SWITCH_BY_ID[k]["label"] for k in agent_facing if sw[k]["on"]]
    off = [SWITCH_BY_ID[k]["label"] for k in agent_facing if not sw[k]["on"]]
    hat_txt = {"white": "WHITE HAT: full knowledge. Use the system description and any source code provided.",
               "grey": "GREY HAT: partial knowledge. No internal documentation or source; test credentials are available.",
               "black": "BLACK HAT: no prior knowledge and no credentials. Enumerate from zero."}[p["hat"]]
    pos_txt = {"external": "TEST POSITION: external — you are attacking from the internet.",
               "internal": "TEST POSITION: internal — you are inside the client network (assumed breach).",
               "both": "TEST POSITION: external and internal targets are both in scope."}[p["position"]]
    lines = [
        "# penenv rules of engagement (binding)",
        f"Aggressiveness L{p['level']} ({p['level_name']}). {METHOD_RULES[p['level']]}",
        hat_txt,
        pos_txt,
        "Scope is enforced by the network: anything not listed below is unreachable. Do not try to get round it.",
        "In scope: " + (", ".join(p["targets"]) or "(none)"),
        "Out of scope (never touch): " + (", ".join(e.get("data", "") for e in cfg.get("out_of_scope") or []) or "(none)"),
    ]
    if p["soft_exclusions"]:
        lines.append("These paths/hosts share an in-scope address and are excluded by this instruction only. "
                     "Never send a request to them: " + ", ".join(p["soft_exclusions"]))
    lines.append("Allowed: " + "; ".join(on))
    lines.append("NOT allowed (disabled binaries fail with 'penenv policy: denied'; do not re-implement them): "
                 + "; ".join(off))
    if p.get("research"):
        lines.append("RESEARCH MODE (authorised): you may form hypotheses and chain weaknesses "
                     "creatively to surface non-obvious and previously-unknown flaws — multi-step "
                     "logic/business-flaw abuse, trust-boundary and state-machine attacks, and the "
                     "composition of individually low-severity issues into a higher-impact chain. "
                     "Every step must still obey the scope, rate and method limits above; prove each "
                     "link with reproducible evidence and stop at proof. Record the hypothesis and "
                     "the chain for every reported finding."
                     + (f" Authorisation reference: {p['authorisation_ref']}." if p.get("authorisation_ref") else ""))
    if p["credentials"]:
        lines.append("Test logins are available through the get_test_credential tool by label: "
                     + ", ".join(p["credentials"]) + ". Never print a password in a report.")
    if p["mfa"]:
        lines.append("For an MFA prompt call get_mfa_code with the login label: " + ", ".join(p["mfa"]))
    if (cfg.get("approach") or "").strip():
        lines.append("Client rules of engagement: " + cfg["approach"].strip())
    if (cfg.get("window") or "").strip():
        lines.append("Testing window: " + cfg["window"].strip())
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- nftables
def render_nft(p: dict, subnet: str, inner_if: str = "@INNER@") -> str:
    """Gateway ruleset. inner_if faces the sandbox (the gateway substitutes @INNER@ at start,
    because Docker does not guarantee interface order); every other interface is the outside."""
    n = p["network"]

    def elems(pairs):
        return ", ".join(f"{a} . {ports}" for a, ports in pairs)

    def set_block(name, kind, items):
        body = f"    elements = {{ {items} }}\n" if items else ""
        return f"  set {name} {{\n    type {kind}\n    flags interval\n{body}  }}\n"

    rate = []
    if n["bw"]:
        rate.append(f"    ip saddr {subnet} limit rate over {n['bw']} bytes/second counter drop comment \"bw-cap\"")
        rate.append(f"    ip daddr {subnet} limit rate over {n['bw']} bytes/second counter drop comment \"bw-cap\"")
    # The kernel token bucket overshoots by ~3% (measured, docs/t43-rate-demo.log), so it is programmed
    # at 97% of the cap, in per-minute units for precision; the configured cap is then a true ceiling.
    per_min = max(1, int(n["conn_rate"] * 60 * 0.97))
    conn = (f"    ip saddr {subnet} ct state new limit rate over {per_min}/minute burst {n['conn_rate']} packets "
            f"counter drop comment \"conn-cap\"\n") if n["contact"] and n["conn_rate"] else ""
    return (
        "flush ruleset\n"
        "table inet penenv {\n"
        + set_block("allow_tcp", "ipv4_addr . inet_service", elems(n["allow_tcp"]))
        + set_block("allow_udp", "ipv4_addr . inet_service", elems(n["allow_udp"]))
        + set_block("deny4", "ipv4_addr", ", ".join(n["deny"]))
        + "  chain input {\n    type filter hook input priority 0; policy drop;\n"
          "    iif lo accept\n    ct state established,related accept\n  }\n"
          "  chain forward {\n    type filter hook forward priority 0; policy drop;\n"
          "    ip daddr @deny4 counter drop comment \"out-of-scope\"\n"
          f"    ct status dnat iifname != \"{inner_if}\" oifname \"{inner_if}\" accept comment \"strix-control\"\n"
          f"    ct status dnat iifname \"{inner_if}\" accept comment \"strix-control-reply\"\n"
        + ("\n".join(rate) + "\n" if rate else "")
        + "    ct state established,related accept\n"
        + conn
        + f"    ip saddr {subnet} ip daddr . tcp dport @allow_tcp counter accept comment \"in-scope-tcp\"\n"
          f"    ip saddr {subnet} ip daddr . udp dport @allow_udp counter accept comment \"in-scope-udp\"\n"
          "    counter drop comment \"not-in-scope\"\n  }\n"
          "  chain pre {\n    type nat hook prerouting priority -100;\n  }\n"
          "  chain post {\n    type nat hook postrouting priority 100;\n"
          f"    ip saddr {subnet} oifname != \"{inner_if}\" masquerade\n"
          f"    ct status dnat oifname \"{inner_if}\" masquerade\n  }}\n"
          "}\n"
    )
