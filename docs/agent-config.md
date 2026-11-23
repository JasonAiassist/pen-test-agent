# Agent config — model provider and model for Strix

The **Agent config** tab on the dashboard (http://127.0.0.1:8766/) chooses which AI model
the Strix agent runs on. There is no chat with the agent yet; this only picks the model.

## Using it

1. **Model providers** panel → fill in a provider and **Save provider**:
   - *Provider type* — OpenAI-compatible endpoint (Z.ai, vLLM, LM Studio, …), OpenAI,
     Anthropic, OpenRouter, DeepSeek, Google Gemini or Ollama (local).
   - *Base URL* — required for an OpenAI-compatible endpoint, optional otherwise (the
     provider's public API is the default).
   - *API key* — required for every type except Ollama. After saving it is shown only as
     `********`; leave the mask in place to keep the stored key when editing.
   - *API type* — `auto`, `chat_completions` or `responses` (Strix's `STRIX_API_TYPE`).
   - **Import from Strix config** creates a provider from the model, endpoint and key
     Strix is set up with now (`~/.strix/cli-config.json`).
2. **Model used by scans** panel → pick the provider, press **Fetch models** to ask the
   provider for its model list (or type a model id if the provider doesn't publish one),
   pick a reasoning effort, then **Use this model**.
3. The banner at the top, the New scan tab and every scan plan (`penenv scan --project X
   --dry-run`) show the model the next scan will use. Choose **Strix default** to go back
   to Strix's own config.

A change applies to the next scan; a running scan keeps the model it started with.

## How it reaches Strix

- penenv stores providers and the selection in `~/.config/penenv/agent.json` (mode 0600;
  override the path with `PENENV_AGENT_CONFIG`). It never edits `~/.strix/cli-config.json`.
- At launch (`tracker/scanrun.py`), `agentcfg.scan_config()` writes a per-scan Strix config
  into the scan's private work directory (mode 0600, deleted when the scan ends): Strix's
  own non-LLM settings (sandbox image, telemetry, …) plus `STRIX_LLM`, `LLM_API_KEY`,
  `LLM_API_BASE`, `STRIX_API_TYPE` and `STRIX_REASONING_EFFORT` for the chosen provider.
  It is passed with `strix --config`.
- The shell's LLM connection variables (`STRIX_LLM`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`,
  `LLM_API_*`, …) are removed from the Strix process for that scan, so two providers are
  never mixed.
- The model prefix is added for you (`openai/`, `anthropic/`, `openrouter/`, `deepseek/`,
  `gemini/`, `ollama/`), so you enter the provider's own model id, e.g. `glm-5.3`.
- The scan's audit trail records `agent model … via <provider> <base URL>` — never the key.

## Security notes

- Keys are masked on every API read, are not logged, and are not written into the agent's
  instructions. As before, the Strix process itself holds the key to call the model.
- **Fetch models** is the only network call this feature makes: a single read-only request
  from the tracker host to the provider's `/models` endpoint (Ollama: `/api/tags`), made
  only when you press the button. The scan sandbox's network is not changed.

## API

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/agent` | providers (keys masked), `active`, `effective`, `strix_default`, `kinds` |
| POST | `/api/agent/providers` | create `{name, kind, api_base, api_key, api_type}` |
| POST | `/api/agent/providers/{id}` | update (send `********` to keep the stored key) |
| DELETE | `/api/agent/providers/{id}` | remove; if it was selected, scans fall back to Strix default |
| POST | `/api/agent/providers/{id}/models` | `{ok, models, error?}` |
| POST | `/api/agent/active` | `{provider_id, model, reasoning_effort}`; `provider_id: ""` = Strix default |
| POST | `/api/agent/import-strix` | provider created from `~/.strix/cli-config.json` |

Tests: `tests/test_agentcfg.py`.
