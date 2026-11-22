"""Scope rules for penenv projects: typed endpoint validation, normalisation,
duplicate detection, internet-facing classification and hat-level gating.

Pure functions (stdlib only) so they can be unit-tested without the server.
Every check returns structured issues instead of raising, so the API can
report *all* problems in one response and the UI can mark the exact row.

Issue = {"severity": "error"|"warning", "list": str, "index": int|None,
         "field": str, "message": str}
"""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Callable, Iterable
from urllib.parse import urlsplit

TYPES = ("ip", "hostname", "url", "cidr")
TYPE_LABELS = {"ip": "IP Address", "hostname": "Hostname", "url": "URL", "cidr": "CIDR"}
HATS = ("white", "grey", "black")
# Test position is independent of the hat (knowledge level): where the tester sits.
POSITIONS = ("external", "internal", "both")
POSITION_LABELS = {"external": "External (from the internet)",
                   "internal": "Internal (inside the network / assumed breach)",
                   "both": "External + Internal"}


def default_position(hat: str | None) -> str:
    """Migration default: keeps pre-v4 behaviour (Grey/Black were internet-facing only)."""
    return "both" if hat == "white" else "external"
LISTS = {"in_scope": "In scope", "out_of_scope": "Out of scope"}

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
# Suffixes that are never routable on the public internet (RFC 6761/6762/8375 + common corp use).
_INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".lan", ".corp",
                      ".home", ".home.arpa", ".localdomain", ".test", ".invalid", ".example")
# CGNAT 100.64.0.0/10 is not flagged is_private on every Python version; check it explicitly.
_EXTRA_NON_PUBLIC = (ipaddress.ip_network("100.64.0.0/10"),)


def issue(severity, lst, index, field, message):
    return {"severity": severity, "list": lst, "index": index, "field": field, "message": message}


# ---------------------------------------------------------------- validation
def _valid_hostname(s: str) -> bool:
    s = s[:-1] if s.endswith(".") else s
    if not s or len(s) > 253:
        return False
    labels = s.split(".")
    if all(l.isdigit() for l in labels):  # "1.2.3" is a malformed IP, not a hostname
        return False
    return all(_LABEL.match(l) for l in labels)


def _parse_ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def validate_endpoint(etype: str, data: str) -> str | None:
    """Return None when `data` is a well-formed value of `etype`, else a reason."""
    if etype not in TYPES:
        return f"unknown type {etype!r} (expected one of: {', '.join(TYPE_LABELS.values())})"
    if not isinstance(data, str) or not data.strip():
        return "value is empty"
    if data != data.strip() or any(c.isspace() for c in data):
        return "value must not contain spaces"
    if etype == "ip":
        if "/" in data:
            return "looks like a CIDR range — choose type CIDR"
        return None if _parse_ip(data) else "not a valid IPv4 or IPv6 address"
    if etype == "cidr":
        if "/" not in data:
            return "CIDR needs a prefix length, e.g. 203.0.113.0/24"
        try:
            ipaddress.ip_network(data, strict=False)
        except ValueError:
            return "not a valid IPv4 or IPv6 CIDR range"
        return None
    if etype == "hostname":
        if "://" in data or "/" in data:
            return "looks like a URL — choose type URL"
        if _parse_ip(data):
            return "this is an IP address — choose type IP Address"
        return None if _valid_hostname(data) else "not a valid hostname (letters, digits, hyphens; dot-separated labels)"
    # url
    try:
        u = urlsplit(data)
        port = u.port  # raises ValueError on a bad port
    except ValueError:
        return "not a valid URL (bad port or brackets)"
    if u.scheme.lower() not in ("http", "https"):
        return "URL must start with http:// or https://"
    if u.username or u.password:
        return "URL must not embed credentials — put them in the keysafe"
    host = u.hostname or ""
    if not host:
        return "URL has no host"
    if not (_parse_ip(host) or _valid_hostname(host)):
        return f"URL host {host!r} is not a valid hostname or IP"
    if port is not None and not (0 < port < 65536):
        return "URL port out of range"
    return None


def infer_type(value: str) -> str | None:
    """Best-effort type for a legacy free-text entry; None if nothing fits."""
    v = (value or "").strip()
    for t in ("ip", "cidr", "url", "hostname"):
        if validate_endpoint(t, v) is None:
            return t
    if validate_endpoint("url", "http://" + v) is None and "/" in v:
        return None  # "host/path" without a scheme: ambiguous, flag instead of guessing
    return None


# ------------------------------------------------------------ normalisation
def norm_key(etype: str, data: str) -> str:
    """Canonical comparison key; equal keys are duplicates. Assumes valid input."""
    if etype == "ip":
        return "ip:" + str(ipaddress.ip_address(data))
    if etype == "cidr":
        net = ipaddress.ip_network(data, strict=False)
        if net.num_addresses == 1:  # 10.0.0.5/32 is the same target as 10.0.0.5
            return "ip:" + str(net.network_address)
        return "cidr:" + str(net)
    if etype == "hostname":
        return "host:" + data.lower().rstrip(".")
    u = urlsplit(data)
    scheme = u.scheme.lower()
    host = (u.hostname or "").lower().rstrip(".")
    if ":" in host:
        host = f"[{ipaddress.ip_address(host)}]"
    elif _parse_ip(host):
        host = str(ipaddress.ip_address(host))
    port = u.port
    netloc = host if port in (None, {"http": 80, "https": 443}[scheme]) else f"{host}:{port}"
    path = u.path.rstrip("/")
    return f"url:{scheme}://{netloc}{path}" + (f"?{u.query}" if u.query else "")


def host_of(etype: str, data: str) -> str | None:
    """The host/IP an entry points at (None for CIDR)."""
    if etype in ("ip", "hostname"):
        return data.lower().rstrip(".")
    if etype == "url":
        return (urlsplit(data).hostname or "").lower().rstrip(".")
    return None


def scan_target_key(etype: str, data: str) -> str | None:
    """Key used to match ingested scan targets (scheme-less, like ingest.norm_target)."""
    if etype == "url":
        u = urlsplit(data)
        s = (u.netloc + u.path).lower().rstrip("/")
        return s
    if etype in ("ip", "hostname"):
        return data.lower().rstrip(".")
    return None


# ----------------------------------------------------------- internet-facing
def _ip_is_public(ip) -> bool:
    if any(ip in n for n in _EXTRA_NON_PUBLIC if n.version == ip.version):
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        return _ip_is_public(ip.ipv4_mapped)
    return ip.is_global and not ip.is_multicast


def _net_is_public(net) -> bool:
    """Public only if *no* part of the range is non-public."""
    if not (net.network_address.is_global and net.broadcast_address.is_global):
        return False
    for bad in _EXTRA_NON_PUBLIC:
        if bad.version == net.version and net.overlaps(bad):
            return False
    non_global = [ipaddress.ip_network(n) for n in (
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
         "0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
         "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
        if net.version == 4 else
        ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "::/128", "64:ff9b:1::/48"))]
    return not any(net.overlaps(n) for n in non_global)


Resolver = Callable[[str], list[str]]


def default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({i[4][0] for i in infos})


def classify_exposure(etype: str, data: str, resolver: Resolver = default_resolver) -> tuple[str, str]:
    """Return (verdict, reason): verdict is 'public', 'internal' or 'unknown'."""
    if etype == "ip":
        ip = ipaddress.ip_address(data)
        return ("public", "") if _ip_is_public(ip) else ("internal", f"{ip} is a private/reserved address")
    if etype == "cidr":
        net = ipaddress.ip_network(data, strict=False)
        return ("public", "") if _net_is_public(net) else ("internal", f"{net} includes private/reserved addresses")
    host = host_of(etype, data) or ""
    ip = _parse_ip(host.strip("[]"))
    if ip is not None:
        return ("public", "") if _ip_is_public(ip) else ("internal", f"host {ip} is a private/reserved address")
    if "." not in host or host == "localhost" or any(host.endswith(s) or host == s[1:] for s in _INTERNAL_SUFFIXES):
        return ("internal", f"{host!r} is an internal-only name")
    addrs = resolver(host)
    if not addrs:
        return ("unknown", f"{host!r} does not resolve right now — it will be re-checked at scan time")
    private = [a for a in addrs if not _ip_is_public(ipaddress.ip_address(a.split("%")[0]))]
    if private:
        return ("internal", f"{host!r} resolves to private address {private[0]}")
    return ("public", "")


# ------------------------------------------------------------ project checks
def _coerce_list(raw) -> list:
    return raw if isinstance(raw, list) else []


def check_endpoints(in_scope: list, out_of_scope: list) -> list[dict]:
    """Format + duplicate checks within and across both lists."""
    issues: list[dict] = []
    seen: dict[str, tuple[str, int]] = {}
    for lst_name, items in (("in_scope", in_scope), ("out_of_scope", out_of_scope)):
        for i, e in enumerate(items):
            if not isinstance(e, dict):
                issues.append(issue("error", lst_name, i, "data", "entry must be {type, data}"))
                continue
            etype, data = e.get("type"), e.get("data")
            reason = validate_endpoint(etype, data)
            if reason:
                issues.append(issue("error", lst_name, i, "data" if etype in TYPES else "type", reason))
                continue
            if etype == "hostname" and "." not in data:
                issues.append(issue("warning", lst_name, i, "data",
                                    f"single-label hostname {data!r} — did you mean a URL path?"))
            key = norm_key(etype, data)
            if key in seen:
                o_lst, o_i = seen[key]
                where = ("already listed in " + LISTS[o_lst]) if o_lst != lst_name else f"duplicate of row {o_i + 1}"
                issues.append(issue("error", lst_name, i, "data", f"{data} — {where}"))
            else:
                seen[key] = (lst_name, i)
    # overlap notices: an in-scope IP inside an out-of-scope range (or vice versa)
    nets = {ln: [(i, ipaddress.ip_network(e["data"], strict=False)) for i, e in enumerate(items)
                 if isinstance(e, dict) and e.get("type") in ("ip", "cidr")
                 and validate_endpoint(e["type"], e.get("data")) is None]
            for ln, items in (("in_scope", in_scope), ("out_of_scope", out_of_scope))}
    for i, n in nets["in_scope"]:
        for j, m in nets["out_of_scope"]:
            if n != m and n.version == m.version and n.subnet_of(m):
                issues.append(issue("warning", "in_scope", i, "data",
                                    f"{n} sits inside out-of-scope {m} — out of scope wins, it will not be tested"))
            elif n != m and n.version == m.version and m.subnet_of(n):
                issues.append(issue("warning", "out_of_scope", j, "data",
                                    f"{m} is excluded from in-scope range {n}"))
    return issues


SECRET_FIELDS = ("password", "api_key")
CRED_FIELDS = ("id", "label", "login_url", "username", "password", "domain", "api_key",
               "otp_ref", "role", "notes")


def check_credentials(keysafe: list, in_scope: list) -> list[dict]:
    issues: list[dict] = []
    for i, c in enumerate(keysafe):
        if not isinstance(c, dict):
            issues.append(issue("error", "keysafe", i, "label", "credential must be an object"))
            continue
        if not (c.get("username") or c.get("api_key")):
            issues.append(issue("error", "keysafe", i, "username", "a login needs a username (or an API key)"))
        if c.get("username") and not c.get("password") and not c.get("otp_ref"):
            issues.append(issue("warning", "keysafe", i, "password", "username has no password or OTP"))
        url = c.get("login_url") or ""
        if url:
            r = validate_endpoint("url", url)
            if r:
                issues.append(issue("error", "keysafe", i, "login_url", r))
    return issues


def _cred_matches_scope(login_url: str, in_scope: list) -> bool:
    host = (urlsplit(login_url).hostname or "").lower().rstrip(".")
    ip = _parse_ip(host)
    for e in in_scope:
        t, d = e.get("type"), e.get("data")
        if validate_endpoint(t, d):
            continue
        if t == "cidr" and ip is not None:
            if ip in ipaddress.ip_network(d, strict=False):
                return True
        elif t == "url":
            if norm_key("url", login_url).startswith(norm_key("url", d)) or host_of(t, d) == host:
                return True
        elif host_of(t, d) == host or (t == "hostname" and host.endswith("." + d.lower().rstrip("."))):
            return True
    return False


def position_violation(position: str, etype: str, data: str,
                       resolver: Resolver = default_resolver) -> tuple[str, str] | None:
    """(severity, message) when an in-scope entry does not fit the test position, else None."""
    if position == "both":
        return None
    verdict, why = classify_exposure(etype, data, resolver)
    if verdict == "unknown":
        return ("warning", why)
    if position == "external" and verdict == "internal":
        return ("error", f"External test position allows internet-facing endpoints only: {why} "
                         "(choose Internal or External + Internal to test it)")
    if position == "internal" and verdict == "public":
        return ("error", f"Internal test position allows internal endpoints only: {data} is internet-facing "
                         "(choose External or External + Internal to test it)")
    return None


def check_position(position: str, in_scope: list, resolver: Resolver = default_resolver) -> list[dict]:
    """Test-position gating (external / internal / both). Independent of the hat."""
    if position not in POSITIONS:
        return [issue("error", "position", None, "position",
                      f"test position must be one of {', '.join(POSITIONS)}")]
    issues: list[dict] = []
    for i, e in enumerate(in_scope):
        if not isinstance(e, dict) or validate_endpoint(e.get("type"), e.get("data")):
            continue  # format errors are reported by check_endpoints
        v = position_violation(position, e["type"], e["data"], resolver)
        if v:
            issues.append(issue(v[0], "in_scope", i, "data", v[1]))
    return issues


def check_hat(hat: str, in_scope: list, keysafe: list, resolver: Resolver = default_resolver) -> list[dict]:
    """Hat = knowledge level only (credentials / white-box). Network position is check_position.
    Out-of-scope is never relaxed by any setting."""
    issues: list[dict] = []
    if hat not in HATS:
        return [issue("error", "hat", None, "hat", f"hat must be one of {', '.join(HATS)}")]
    if hat == "white":
        return issues
    if hat == "black" and keysafe:
        issues.append(issue("error", "keysafe", None, "keysafe",
                            f"Black hat tests carry no credentials — remove the {len(keysafe)} keysafe "
                            "entr{} or choose Grey/White hat".format("y" if len(keysafe) == 1 else "ies")))
    if hat == "grey":
        for i, c in enumerate(keysafe):
            if not isinstance(c, dict):
                continue
            url = c.get("login_url") or ""
            if not url:
                issues.append(issue("error", "keysafe", i, "login_url",
                                    "Grey hat credentials must name the in-scope login URL they belong to"))
            elif validate_endpoint("url", url) is None and not _cred_matches_scope(url, in_scope):
                issues.append(issue("error", "keysafe", i, "login_url",
                                    f"{url} is not covered by any in-scope endpoint"))
    return issues


def errors(issues: Iterable[dict]) -> list[dict]:
    return [i for i in issues if i["severity"] == "error"]
