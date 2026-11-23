"""Agent (Strix LLM) configuration: model providers and the selected model.

penenv keeps its own provider list in ~/.config/penenv/agent.json (mode 0600) and never
edits Strix's ~/.strix/cli-config.json. At scan launch, scanrun asks this module for a
per-scan Strix config file: the non-LLM settings of Strix's own file (sandbox image,
telemetry, ...) plus the selected provider's model / key / base URL. That file is passed
with `strix --config`, and the shell's LLM connection variables are removed from the
Strix process so nothing mixes two providers. With no model selected here, the scan uses
Strix's own config unchanged ("Strix default").

API keys are stored only in agent.json, masked on every API read, never logged, and never
put in the agent's instructions.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_PATH = Path(os.environ["PENENV_AGENT_CONFIG"]) if os.environ.get("PENENV_AGENT_CONFIG") \
    else Path.home() / ".config" / "penenv" / "agent.json"
STRIX_CONFIG = Path(os.environ["PENENV_STRIX_CONFIG"]) if os.environ.get("PENENV_STRIX_CONFIG") \
    else Path.home() / ".strix" / "cli-config.json"
MASK = "********"

# kind -> (label, LiteLLM model prefix, default base URL used for model listing, needs key)
KINDS = {
    "openai-compatible": ("OpenAI-compatible endpoint (Z.ai, vLLM, LM Studio, …)", "openai/", "", True),
    "openai": ("OpenAI", "openai/", "https://api.openai.com/v1", True),
    "anthropic": ("Anthropic", "anthropic/", "https://api.anthropic.com/v1", True),
    "openrouter": ("OpenRouter", "openrouter/", "https://openrouter.ai/api/v1", True),
    "deepseek": ("DeepSeek", "deepseek/", "https://api.deepseek.com", True),
    "gemini": ("Google Gemini", "gemini/", "https://generativelanguage.googleapis.com/v1beta", True),
    "ollama": ("Ollama (local)", "ollama/", "http://localhost:11434", False),
}
API_TYPES = ("", "chat_completions", "responses")
EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")

# Every Strix env alias that describes the LLM connection (strix/config/settings.py).
LLM_ALIASES = ("STRIX_LLM", "LLM_API_KEY", "OPENAI_API_KEY", "LLM_API_BASE", "OPENAI_API_BASE",
               "OPENAI_BASE_URL", "LITELLM_BASE_URL", "OLLAMA_API_BASE", "STRIX_API_TYPE",
               "STRIX_FORCE_API", "STRIX_REASONING_EFFORT")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


class AgentConfigError(ValueError):
    pass


# ---- storage ----------------------------------------------------------------
def load() -> dict:
    try:
        data = json.loads(CONFIG_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    provs = [p for p in data.get("providers") or [] if isinstance(p, dict) and p.get("id")]
    active = data.get("active") if isinstance(data.get("active"), dict) else {}
    return {"providers": provs, "active": {"provider_id": str(active.get("provider_id") or ""),
                                           "model": str(active.get("model") or ""),
                                           "reasoning_effort": str(active.get("reasoning_effort") or "high")}}


def save(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def _provider(cfg: dict, pid: str) -> dict | None:
    return next((p for p in cfg["providers"] if p["id"] == pid), None)


def _mask_key(v: str) -> str:
    return MASK if v else ""


def masked(cfg: dict) -> dict:
    return {"providers": [{**p, "api_key": _mask_key(p.get("api_key", ""))} for p in cfg["providers"]],
            "active": dict(cfg["active"])}


# ---- Strix's own config (read-only) ------------------------------------------
def strix_env_block() -> dict:
    try:
        data = json.loads(STRIX_CONFIG.read_text())
        env = data.get("env", {}) if isinstance(data, dict) else {}
        return {str(k).upper(): v for k, v in env.items()} if isinstance(env, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def strix_default() -> dict:
    """What Strix would use on its own — key presence only, never the value."""
    env = strix_env_block()
    first = lambda *ks: next((str(env[k]) for k in ks if env.get(k)), "")  # noqa: E731
    return {"path": str(STRIX_CONFIG), "exists": STRIX_CONFIG.exists(),
            "model": first("STRIX_LLM"),
            "api_base": first("LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL",
                              "LITELLM_BASE_URL", "OLLAMA_API_BASE"),
            "api_type": first("STRIX_API_TYPE", "STRIX_FORCE_API"),
            "reasoning_effort": first("STRIX_REASONING_EFFORT"),
            "has_key": bool(first("LLM_API_KEY", "OPENAI_API_KEY"))}


# ---- validation / mutation ---------------------------------------------------
def _clean_provider(body: dict, old: dict | None) -> dict:
    kind = str(body.get("kind") or "").strip()
    if kind not in KINDS:
        raise AgentConfigError(f"provider type must be one of: {', '.join(KINDS)}")
    name = str(body.get("name") or "").strip()
    if not name:
        raise AgentConfigError("provider name is required")
    base = str(body.get("api_base") or "").strip().rstrip("/")
    if base:
        u = urllib.parse.urlparse(base)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise AgentConfigError("base URL must be an http(s) URL, e.g. https://api.example.com/v1")
    elif kind == "openai-compatible":
        raise AgentConfigError("an OpenAI-compatible endpoint needs a base URL")
    key = str(body.get("api_key") or "").strip()
    if key == MASK:
        key = (old or {}).get("api_key", "")
    if key and any(c.isspace() for c in key):
        raise AgentConfigError("API key must be a single token with no spaces")
    if KINDS[kind][3] and not key:
        raise AgentConfigError(f"{KINDS[kind][0]} needs an API key")
    api_type = str(body.get("api_type") or "").strip()
    if api_type not in API_TYPES:
        raise AgentConfigError("API type must be blank (auto), chat_completions or responses")
    models = [str(m).strip() for m in (body.get("models") or []) if str(m).strip()] \
        if isinstance(body.get("models"), list) else (old or {}).get("models", [])
    return {"id": (old or {}).get("id") or "", "name": name, "kind": kind, "api_base": base,
            "api_key": key, "api_type": api_type, "models": models[:500]}


def save_provider(body: dict, pid: str | None = None) -> dict:
    cfg = load()
    old = _provider(cfg, pid) if pid else None
    if pid and not old:
        raise AgentConfigError(f"unknown provider {pid}")
    p = _clean_provider(body, old)
    if old:
        cfg["providers"] = [p if x["id"] == pid else x for x in cfg["providers"]]
    else:
        slug = re.sub(r"[^a-z0-9]+", "-", p["name"].lower()).strip("-")[:30] or "provider"
        p["id"] = slug if not _provider(cfg, slug) else f"{slug}-{secrets.token_hex(2)}"
        cfg["providers"].append(p)
    save(cfg)
    return p


def delete_provider(pid: str) -> None:
    cfg = load()
    if not _provider(cfg, pid):
        raise AgentConfigError(f"unknown provider {pid}")
    cfg["providers"] = [p for p in cfg["providers"] if p["id"] != pid]
    if cfg["active"]["provider_id"] == pid:  # never leave a dangling selection
        cfg["active"] = {"provider_id": "", "model": "", "reasoning_effort": cfg["active"]["reasoning_effort"]}
    save(cfg)


def set_active(body: dict) -> dict:
    cfg = load()
    pid = str(body.get("provider_id") or "").strip()
    model = str(body.get("model") or "").strip()
    effort = str(body.get("reasoning_effort") or "high").strip().lower()
    if effort not in EFFORTS:
        raise AgentConfigError(f"reasoning effort must be one of: {', '.join(EFFORTS)}")
    if pid:
        if not _provider(cfg, pid):
            raise AgentConfigError(f"unknown provider {pid}")
        if not model or any(c.isspace() for c in model):
            raise AgentConfigError("choose a model (a single model id, no spaces)")
    else:
        model = ""  # "Strix default": use ~/.strix/cli-config.json unchanged
    cfg["active"] = {"provider_id": pid, "model": model, "reasoning_effort": effort}
    save(cfg)
    return cfg["active"]


def import_strix_default() -> dict:
    """Create a provider from Strix's current config (so the existing setup is one click away)."""
    env = strix_env_block()
    d = strix_default()
    if not d["model"]:
        raise AgentConfigError(f"no STRIX_LLM in {STRIX_CONFIG}")
    prefix, _, model = d["model"].partition("/")
    kind = next((k for k, v in KINDS.items() if v[1] == prefix + "/" and k != "openai-compatible"), None)
    if kind == "openai" and d["api_base"] and "api.openai.com" not in d["api_base"]:
        kind = "openai-compatible"
    if not kind or not model:
        kind, model = "openai-compatible", d["model"]
    host = urllib.parse.urlparse(d["api_base"]).hostname if d["api_base"] else ""
    p = save_provider({"name": f"Imported from Strix ({host or kind})", "kind": kind,
                       "api_base": d["api_base"], "api_type": d["api_type"],
                       "api_key": str(env.get("LLM_API_KEY") or env.get("OPENAI_API_KEY") or ""),
                       "models": [model]})
    return {"provider": {**p, "api_key": _mask_key(p["api_key"])}, "model": model,
            "reasoning_effort": d["reasoning_effort"] or "high"}


def seed_from_strix() -> dict | None:
    """First use only (no agent.json yet): adopt Strix's existing setup as a real, selected
    provider so its endpoint is configured here (model listing works) and scans keep using
    the same model. Never re-runs once agent.json exists, so deletions are respected."""
    if CONFIG_PATH.exists() or not strix_default()["model"]:
        return None
    try:
        r = import_strix_default()
    except AgentConfigError:
        return None
    set_active({"provider_id": r["provider"]["id"], "model": r["model"],
                "reasoning_effort": r["reasoning_effort"]})
    return r


# ---- resolution for a scan ---------------------------------------------------
def strix_model(p: dict, model: str) -> str:
    prefix = KINDS[p["kind"]][1]
    return model if model.startswith(prefix) else prefix + model


def effective() -> dict:
    """The model a scan launched now would use (no secrets)."""
    cfg = load()
    a = cfg["active"]
    p = _provider(cfg, a["provider_id"]) if a["provider_id"] else None
    if p and a["model"]:
        return {"source": "penenv", "provider_id": p["id"], "provider": p["name"],
                "model": strix_model(p, a["model"]), "api_base": p["api_base"],
                "api_type": p["api_type"], "reasoning_effort": a["reasoning_effort"],
                "has_key": bool(p["api_key"])}
    d = strix_default()
    return {"source": "strix", "provider_id": "", "provider": "Strix default", "model": d["model"],
            "api_base": d["api_base"], "api_type": d["api_type"],
            "reasoning_effort": d["reasoning_effort"] or "high", "has_key": d["has_key"]}


def scan_config(dest_dir: Path) -> tuple[Path | None, dict]:
    """Write the per-scan Strix config (0600) into dest_dir, or None for "Strix default".

    Returns (path, effective-description). The caller must pass `--config path` to Strix
    and strip LLM_ALIASES from the Strix process environment.
    """
    eff = effective()
    if eff["source"] != "penenv":
        return None, eff
    cfg = load()
    p = _provider(cfg, eff["provider_id"])
    env = {k: v for k, v in strix_env_block().items() if k not in LLM_ALIASES}
    env.update({"STRIX_LLM": eff["model"], "STRIX_REASONING_EFFORT": eff["reasoning_effort"]})
    if p["api_key"]:
        env["LLM_API_KEY"] = p["api_key"]
    if p["api_base"]:
        env["LLM_API_BASE"] = p["api_base"]
    if p["api_type"]:
        env["STRIX_API_TYPE"] = p["api_type"]
    path = Path(dest_dir) / "strix-config.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"env": env}, f)
    return path, eff


def scrub_env(env: dict) -> dict:
    return {k: v for k, v in env.items() if k.upper() not in LLM_ALIASES}


# ---- model discovery (host-side, user-initiated) -----------------------------
def _get(url: str, headers: dict, timeout: float = 12) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "penenv-agentcfg/1.0", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (user-configured URL)
        return json.loads(r.read() or b"{}")


def list_models(pid: str, opener=_get) -> dict:
    """Ask the provider which models it offers. Errors are returned, not raised, so the UI can
    fall back to typing a model id."""
    cfg = load()
    p = _provider(cfg, pid)
    if not p:
        raise AgentConfigError(f"unknown provider {pid}")
    base = (p["api_base"] or KINDS[p["kind"]][2]).rstrip("/")
    key = p["api_key"]
    try:
        if p["kind"] == "ollama":
            data = opener(base + "/api/tags", {})
            ids = [m.get("name") for m in data.get("models", [])]
        elif p["kind"] == "anthropic":
            data = opener(base + "/models?limit=1000", {"x-api-key": key, "anthropic-version": "2023-06-01"})
            ids = [m.get("id") for m in data.get("data", [])]
        elif p["kind"] == "gemini":
            data = opener(base + "/models?pageSize=1000", {"x-goog-api-key": key})
            ids = [str(m.get("name", "")).removeprefix("models/") for m in data.get("models", [])]
        else:
            data = opener(base + "/models", {"Authorization": f"Bearer {key}"} if key else {})
            ids = [m.get("id") for m in data.get("data", [])]
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"{base}: HTTP {e.code} {e.reason} — type the model id instead",
                "models": p.get("models", [])}
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        return {"ok": False, "error": f"{base}: {reason} — type the model id instead",
                "models": p.get("models", [])}
    ids = sorted({str(i) for i in ids if i})
    p["models"] = ids[:500]
    cfg["providers"] = [p if x["id"] == pid else x for x in cfg["providers"]]
    save(cfg)
    return {"ok": True, "models": p["models"]}


def kinds() -> list[dict]:
    return [{"kind": k, "label": v[0], "prefix": v[1], "default_base": v[2], "needs_key": v[3]}
            for k, v in KINDS.items()]
