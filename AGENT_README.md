# AGENT_README — installing penenv with Strix

This guide is for an **AI agent** installing this repository on a machine for a human
operator. Follow the steps in order and run every **Verify** check. If one fails, stop and
report it; don't skip ahead. The human README is `README.md`, and the model-selection design
is in `docs/agent-config.md`.

## 0. What you are installing

This repository (penenv) is **the harness only**. It doesn't include Strix and doesn't list
it as a package dependency. Three things come from outside the repo:

| Piece | Where it comes from | Where it lives |
|---|---|---|
| Strix agent (`strix-agent` **1.7.x**) | PyPI, installed as a uv tool | `~/.local/share/uv/tools/strix-agent/` |
| Strix sandbox image | `ghcr.io/usestrix/strix-sandbox:1.4.1` | Docker |
| Strix's model settings | written by you in step 4 | `~/.strix/cli-config.json` |

penenv builds one image itself (the egress gateway, step 3). It stores its own state in
`tracker/penenv.db` and `~/.config/penenv/agent.json`. Neither is committed.

Hard rules while installing:
- **Never commit or print secrets.** API keys go only in `~/.strix/cli-config.json` or
  `~/.config/penenv/agent.json`, both mode `0600`. Don't echo them into logs or chat.
- **Don't invent credentials.** If you don't have an API key you're authorised to use, ask
  the operator for one.
- **Don't scan anything except the local demo target** while installing. Real targets need
  an operator-created Project with scope (and an authorisation record for research mode).

## 1. Host prerequisites

Linux, with:
- `git`, `curl`, `python3` ≥ 3.11 (the tracker uses only the standard library)
- `uv` (https://docs.astral.sh/uv/). Strix's uv venv brings its own Python 3.13.
- Docker Engine with the compose plugin. The operator's user must be in the `docker` group.
  `bin/penenv` falls back to `sg docker` / `newgrp docker` when the current shell hasn't
  picked up the group yet. If neither `docker info` nor `sg` works, ask the operator to add
  the group and log in again. Don't use `sudo docker` as a workaround: scans run as the user.
- Optional: `chromium` (PDF reports and the agent's browser tool), LibreOffice `soffice`
  (Word reports), `keepassxc-cli` (MFA logins).

**Verify:**
```bash
python3 --version && uv --version && docker compose version && docker info >/dev/null && echo docker-ok
```

## 2. Install Strix

The launcher (`bin/penenv-launch.py`) hooks Strix internals and **refuses to scan** on any
version other than 1.7.x (`SUPPORTED_STRIX`). Pin it:

```bash
uv tool install 'strix-agent==1.7.*'
docker pull ghcr.io/usestrix/strix-sandbox:1.4.1
```

penenv expects Strix's interpreter at exactly
`~/.local/share/uv/tools/strix-agent/bin/python` (`STRIX_PY` in `tracker/scanrun.py`). That's
uv's default tool location. If `UV_TOOL_DIR` is set to something else, unset it for this
install, or stop and report the mismatch.

**Verify:**
```bash
uv tool list | grep -A1 strix-agent                         # strix-agent v1.7.x
~/.local/share/uv/tools/strix-agent/bin/python -c \
  "import importlib.metadata as m; print(m.version('strix-agent'))"   # 1.7.x
command -v strix                                             # ~/.local/bin/strix
docker image inspect ghcr.io/usestrix/strix-sandbox:1.4.1 >/dev/null && echo image-ok
```

Don't upgrade Strix past 1.7.x without first updating `SUPPORTED_STRIX` and re-running the
test suite. The launcher's fail-closed checks exist because Strix internals change between
versions.

## 3. Clone and build the harness

```bash
git clone https://github.com/JasonAiassist/pen-test-agent.git penenv
cd penenv
docker build -t penenv-egress-gw:2 docker/egress-gw      # every project scan needs this image
```

The tag must be exactly `penenv-egress-gw:2` (`GW_IMAGE` in `tracker/scanrun.py`).
Optionally put `bin/` on the `PATH` so the operator can type `penenv`.

**Verify:**
```bash
docker image inspect penenv-egress-gw:2 >/dev/null && echo gw-ok
python3 -m unittest discover -s tests 2>&1 | tail -2      # OK (skipped=1); tests use temp files only
```

## 4. Make your model the default Strix agent

Strix needs an LLM. To "link yourself" means configuring Strix to run on **the same
provider and model you, the installing agent, run on**, so the operator gets the model they
already chose. This only works when you have an API key for that provider that the operator
has authorised for this use:

1. **Identify your provider and model.** Use your own runtime facts (model id, API endpoint).
   Don't guess. If you run on a subscription or other login that has no API key Strix can
   use, tell the operator and ask which provider and key Strix should use instead.
2. **Get the key from the operator,** or from an environment variable they point you to.
   Don't copy keys out of other applications' config files without asking.
3. **Write `~/.strix/cli-config.json`** (mode `0600`). Strix reads an `env` object of its
   own variables. There is one key field, `LLM_API_KEY` (alias `OPENAI_API_KEY`), and one
   base-URL field, `LLM_API_BASE` (aliases `OPENAI_BASE_URL`, `OPENAI_API_BASE`,
   `OLLAMA_API_BASE`). Those are also the names penenv writes for each scan. Format the
   model id as `<prefix><model>`:

| Provider | `STRIX_LLM` example | `LLM_API_KEY` | `LLM_API_BASE` |
|---|---|---|---|
| Anthropic | `anthropic/claude-…` | required | — |
| OpenAI | `openai/gpt-…` | required | — |
| OpenAI-compatible (Z.ai, vLLM, LM Studio…) | `openai/glm-5.3` | required | required, e.g. `https://api.z.ai/api/coding/paas/v4` |
| OpenRouter | `openrouter/<vendor>/<model>` | required | — |
| DeepSeek | `deepseek/deepseek-…` | required | — |
| Gemini | `gemini/gemini-…` | required | — |
| Ollama (local) | `ollama/<model>` | — | `http://localhost:11434` |

Example (OpenAI-compatible endpoint). Write it without putting the key on a command line
that gets logged:

```bash
mkdir -p ~/.strix && chmod 700 ~/.strix
umask 077 && cat > ~/.strix/cli-config.json <<'EOF'
{
  "env": {
    "STRIX_LLM": "openai/glm-5.3",
    "STRIX_API_TYPE": "chat_completions",
    "STRIX_REASONING_EFFORT": "high",
    "LLM_API_BASE": "https://api.z.ai/api/coding/paas/v4",
    "LLM_API_KEY": "<KEY FROM OPERATOR>",
    "STRIX_IMAGE": "ghcr.io/usestrix/strix-sandbox:1.4.1",
    "STRIX_TELEMETRY": "0"
  }
}
EOF
chmod 600 ~/.strix/cli-config.json
```

Keep `STRIX_IMAGE` pinned to `1.4.1`: Strix 1.7's built-in default is an older image.
`STRIX_API_TYPE` (`chat_completions` or `responses`) is only needed for OpenAI-compatible
endpoints that don't support the default API. Variables in your shell override this file
when Strix runs by hand, but penenv clears them for its own scans (see step 5).

**Verify** (prints the model id; the key is never printed):
```bash
python3 -c "import json,pathlib;e=json.load(open(pathlib.Path.home()/'.strix/cli-config.json'))['env'];print(e['STRIX_LLM'])"
stat -c %a ~/.strix/cli-config.json     # 600
```

## 5. Integrate Strix with the harness (Agent config)

penenv doesn't edit `~/.strix/cli-config.json`. For each scan it writes a temporary Strix
config from the dashboard's **Agent config** selection, passes it with `--config`, clears the
shell's model variables, and deletes the file when the scan ends.

```bash
bin/penenv tracker start                 # http://127.0.0.1:8766 (localhost only)
curl -s http://127.0.0.1:8766/api/agent | python3 -c \
  "import json,sys;d=json.load(sys.stdin);print(d['effective']);print([p['id'] for p in d['providers']])"
```

The first time `/api/agent` is read and `~/.config/penenv/agent.json` doesn't exist yet,
penenv imports the step 4 config as a provider (`imported-from-strix-<host>`) and selects it.
That's why a fresh install already shows `"source": "penenv"` with your model. This happens
only once; after that, providers are managed on the dashboard's **Agent config** tab or
through the API:

```bash
# list the provider's models (works for providers saved in penenv)
curl -s -X POST -H 'Content-Type: application/json' -d '{}' \
  http://127.0.0.1:8766/api/agent/providers/<provider_id>/models
# choose the model scans use
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"provider_id":"<provider_id>","model":"<model>","reasoning_effort":"high"}' \
  http://127.0.0.1:8766/api/agent/active
```

API responses always mask keys as `********`. If they ever show a real key, stop and report
it.

**Verify:**
```bash
bin/penenv status                                        # tracker: running
stat -c %a ~/.config/penenv/agent.json                   # 600
```

## 6. End-to-end check against the demo target

```bash
bin/penenv up                       # Juice Shop on 127.0.0.1:3000 (local only)
```

Then, on the dashboard, create a Project for `http://127.0.0.1:3000` (White hat, Internal
position, low aggression), or ask the operator to. Then:

```bash
bin/penenv scan --project <name> --dry-run | grep "agent model"
# -> agent model: <your model> · provider Imported from Strix (...) · <base url> · reasoning high
```

The dry run starts nothing. A real scan uses model tokens (the demo took about an hour), so
**run one only if the operator agrees**:
`bin/penenv scan --project <name>`, or `bin/penenv demo` for the quick legacy path. Results
land in `strix_runs/<run>/` and are filed as findings in the tracker automatically.

## 7. Report back to the operator

Report each of these with its exact result. Write "not run" where you skipped one:
- Strix version, sandbox image, gateway image: present / missing
- the model Strix will use (`effective.model`) and its provider, never the key
- the test suite result
- the dry-run "agent model" line
- whether a real scan was run, and its run id if so

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `REFUSING TO SCAN: strix-agent X is not a version…` | Wrong Strix version. Run `uv tool install --force 'strix-agent==1.7.*'` |
| `docker is not accessible` | User isn't in the `docker` group, or the session predates it. Log in again. Run scans through `bin/penenv`, not `tracker/scanrun.py` |
| Gateway container fails to create | `penenv-egress-gw:2` isn't built (step 3) |
| Agent config shows "Strix default" and no provider | `agent.json` already existed before step 4. Use **Import from Strix config** on the tab, then **Use this model** |
| Fetch models returns an error | The provider doesn't publish a model list. Pick **Other…** and type the model id |
| Scan uses an unexpected model | Check `effective` in `/api/agent`. The Agent config selection overrides `~/.strix/cli-config.json` |
