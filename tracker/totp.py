"""RFC 6238 TOTP (stdlib) + otpauth:// parsing (T2.2).

Used to (a) parse/normalise the setup secret a site shows during MFA
enrolment and (b) independently cross-check the code KeePassXC produces
right after registration, so a mis-registered seed is caught immediately.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, quote, urlsplit

ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class OtpError(ValueError):
    pass


def hotp(key: bytes, counter: int, digits: int = 6, algo: str = "SHA1") -> str:
    h = hmac.new(key, struct.pack(">Q", counter), ALGOS[algo]).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(key: bytes, at: float | None = None, period: int = 30, digits: int = 6, algo: str = "SHA1") -> str:
    t = time.time() if at is None else at
    return hotp(key, int(t) // period, digits, algo)


def remaining(period: int = 30, at: float | None = None) -> int:
    t = time.time() if at is None else at
    return period - int(t) % period


def b32decode(secret: str) -> bytes:
    s = "".join(secret.split()).replace("-", "").upper().rstrip("=")
    if not s:
        raise OtpError("MFA secret is empty")
    try:
        key = base64.b32decode(s + "=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        raise OtpError("MFA secret is not valid base32 (letters A–Z and digits 2–7)") from None
    if len(key) < 10:
        raise OtpError("MFA secret is too short (under 80 bits) — check you copied all of it")
    return key


def parse_setup(value: str) -> dict:
    """Accept a bare base32 key or an otpauth://totp URI. Returns normalised params."""
    value = (value or "").strip()
    params = {"period": 30, "digits": 6, "algo": "SHA1", "issuer": "", "account": ""}
    if value.lower().startswith("otpauth://"):
        u = urlsplit(value)
        if u.netloc.lower() != "totp":
            raise OtpError("only time-based (otpauth://totp) MFA is supported")
        q = {k.lower(): v[0] for k, v in parse_qs(u.query).items()}
        secret = q.get("secret", "")
        try:
            params["period"] = int(q.get("period", 30))
            params["digits"] = int(q.get("digits", 6))
        except ValueError:
            raise OtpError("otpauth period/digits must be numbers") from None
        params["algo"] = q.get("algorithm", "SHA1").upper()
        params["issuer"] = q.get("issuer", "")
        params["account"] = u.path.lstrip("/")
    else:
        secret = value
    if params["algo"] not in ALGOS:
        raise OtpError(f"unsupported MFA algorithm {params['algo']}")
    if params["digits"] not in (6, 7, 8) or not (10 <= params["period"] <= 120):
        raise OtpError("unsupported MFA digits/period")
    key = b32decode(secret)
    params["key"] = key
    params["secret_b32"] = base64.b32encode(key).decode().rstrip("=")
    return params


def to_uri(p: dict, label: str) -> str:
    return (f"otpauth://totp/{quote(label)}?secret={p['secret_b32']}&period={p['period']}"
            f"&digits={p['digits']}&algorithm={p['algo']}" + (f"&issuer={quote(p['issuer'])}" if p["issuer"] else ""))
