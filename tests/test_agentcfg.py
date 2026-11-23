"""Agent config (tracker/agentcfg.py + /api/agent): provider CRUD, key masking/round-trip,
selection, Strix-default fallback, per-scan Strix config and env scrubbing, model listing."""
import json
import os
import stat
import tempfile
import unittest
import urllib.error
from pathlib import Path

import helpers
import agentcfg

KEY = "sk-test-SECRET-123"


def reset(strix_env=None):
    for p in (agentcfg.CONFIG_PATH, agentcfg.STRIX_CONFIG):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    if strix_env is not None:
        agentcfg.STRIX_CONFIG.write_text(json.dumps({"env": strix_env}))


STRIX_ENV = {"STRIX_LLM": "openai/glm-5.3", "STRIX_API_TYPE": "chat_completions",
             "STRIX_REASONING_EFFORT": "high", "STRIX_IMAGE": "ghcr.io/usestrix/strix-sandbox:1.4.1",
             "OPENAI_API_KEY": "zai-KEY", "OPENAI_BASE_URL": "https://api.z.ai/api/coding/paas/v4",
             "STRIX_TELEMETRY": "0"}


class TestAgentCfg(unittest.TestCase):
    def setUp(self):
        reset(STRIX_ENV)

    def test_paths_are_test_isolated(self):
        self.assertTrue(str(agentcfg.CONFIG_PATH).startswith(str(helpers.TMP)))
        self.assertTrue(str(agentcfg.STRIX_CONFIG).startswith(str(helpers.TMP)))

    def test_default_falls_back_to_strix_without_exposing_key(self):
        e = agentcfg.effective()
        self.assertEqual((e["source"], e["model"]), ("strix", "openai/glm-5.3"))
        self.assertTrue(e["has_key"])
        self.assertNotIn("zai-KEY", json.dumps(e) + json.dumps(agentcfg.strix_default()))
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(agentcfg.scan_config(Path(d))[0], None)  # Strix's own file is used

    def test_provider_validation(self):
        bad = [{"name": "x", "kind": "nope", "api_key": KEY},
               {"name": "", "kind": "openai", "api_key": KEY},
               {"name": "x", "kind": "openai-compatible", "api_key": KEY},          # no base URL
               {"name": "x", "kind": "openai", "api_key": ""},                       # key required
               {"name": "x", "kind": "openai", "api_key": "a b"},
               {"name": "x", "kind": "openai", "api_key": KEY, "api_base": "ftp://h"},
               {"name": "x", "kind": "openai", "api_key": KEY, "api_type": "grpc"}]
        for b in bad:
            with self.assertRaises(agentcfg.AgentConfigError, msg=b):
                agentcfg.save_provider(b)
        agentcfg.save_provider({"name": "local", "kind": "ollama"})  # ollama needs no key

    def test_file_mode_and_mask_round_trip(self):
        p = agentcfg.save_provider({"name": "Z.ai", "kind": "openai-compatible",
                                    "api_base": "https://api.z.ai/api/coding/paas/v4/", "api_key": KEY})
        self.assertEqual(stat.S_IMODE(os.stat(agentcfg.CONFIG_PATH).st_mode), 0o600)
        self.assertEqual(p["api_base"], "https://api.z.ai/api/coding/paas/v4")  # trailing / trimmed
        m = agentcfg.masked(agentcfg.load())
        self.assertEqual(m["providers"][0]["api_key"], agentcfg.MASK)
        agentcfg.save_provider({"name": "Z.ai renamed", "kind": "openai-compatible",
                                "api_base": p["api_base"], "api_key": agentcfg.MASK}, p["id"])
        self.assertEqual(agentcfg.load()["providers"][0]["api_key"], KEY)  # mask kept the stored key

    def test_selection_writes_scan_config_and_scrubs_env(self):
        p = agentcfg.save_provider({"name": "Anth", "kind": "anthropic", "api_key": KEY})
        with self.assertRaises(agentcfg.AgentConfigError):
            agentcfg.set_active({"provider_id": p["id"], "model": ""})
        with self.assertRaises(agentcfg.AgentConfigError):
            agentcfg.set_active({"provider_id": "ghost", "model": "m"})
        with self.assertRaises(agentcfg.AgentConfigError):
            agentcfg.set_active({"provider_id": p["id"], "model": "m", "reasoning_effort": "ludicrous"})
        agentcfg.set_active({"provider_id": p["id"], "model": "claude-sonnet-5", "reasoning_effort": "medium"})
        e = agentcfg.effective()
        self.assertEqual((e["source"], e["model"]), ("penenv", "anthropic/claude-sonnet-5"))
        with tempfile.TemporaryDirectory() as d:
            path, eff = agentcfg.scan_config(Path(d))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            env = json.loads(path.read_text())["env"]
        # non-LLM Strix settings survive; the old provider's connection does not leak in
        self.assertEqual(env["STRIX_IMAGE"], STRIX_ENV["STRIX_IMAGE"])
        self.assertEqual(env["STRIX_TELEMETRY"], "0")
        self.assertEqual((env["STRIX_LLM"], env["LLM_API_KEY"], env["STRIX_REASONING_EFFORT"]),
                         ("anthropic/claude-sonnet-5", KEY, "medium"))
        for gone in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "STRIX_API_TYPE", "LLM_API_BASE"):
            self.assertNotIn(gone, env)
        self.assertNotIn(KEY, json.dumps(eff))
        scrubbed = agentcfg.scrub_env({"OPENAI_BASE_URL": "x", "openai_api_key": "y", "PATH": "/bin"})
        self.assertEqual(scrubbed, {"PATH": "/bin"})

    def test_prefix_not_doubled_and_delete_clears_selection(self):
        p = agentcfg.save_provider({"name": "OR", "kind": "openrouter", "api_key": KEY})
        self.assertEqual(agentcfg.strix_model(p, "z-ai/glm-5.3"), "openrouter/z-ai/glm-5.3")
        self.assertEqual(agentcfg.strix_model(p, "openrouter/x/y"), "openrouter/x/y")
        agentcfg.set_active({"provider_id": p["id"], "model": "z-ai/glm-5.3"})
        agentcfg.delete_provider(p["id"])
        self.assertEqual(agentcfg.effective()["source"], "strix")

    def test_import_strix_default(self):
        r = agentcfg.import_strix_default()
        p = agentcfg.load()["providers"][0]
        self.assertEqual((p["kind"], p["api_base"], p["api_key"], r["model"]),
                         ("openai-compatible", STRIX_ENV["OPENAI_BASE_URL"], "zai-KEY", "glm-5.3"))
        self.assertEqual(r["provider"]["api_key"], agentcfg.MASK)
        self.assertEqual(agentcfg.strix_model(p, r["model"]), "openai/glm-5.3")  # same model as before
        reset({})
        with self.assertRaises(agentcfg.AgentConfigError):
            agentcfg.import_strix_default()

    def test_list_models_success_and_failure(self):
        p = agentcfg.save_provider({"name": "OAI", "kind": "openai", "api_key": KEY})
        seen = {}

        def ok(url, headers):
            seen.update(url=url, headers=headers)
            return {"data": [{"id": "gpt-b"}, {"id": "gpt-a"}, {"id": "gpt-a"}]}
        r = agentcfg.list_models(p["id"], opener=ok)
        self.assertEqual(r, {"ok": True, "models": ["gpt-a", "gpt-b"]})
        self.assertEqual(seen["url"], "https://api.openai.com/v1/models")
        self.assertEqual(seen["headers"]["Authorization"], f"Bearer {KEY}")
        self.assertEqual(agentcfg.load()["providers"][0]["models"], ["gpt-a", "gpt-b"])  # cached

        def fail(url, headers):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        r = agentcfg.list_models(p["id"], opener=fail)
        self.assertFalse(r["ok"])
        self.assertIn("type the model id", r["error"])
        self.assertNotIn(KEY, r["error"])
        self.assertEqual(r["models"], ["gpt-a", "gpt-b"])  # previous list still offered


class TestAgentApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = helpers.LiveServer()

    @classmethod
    def tearDownClass(cls):
        cls.s.stop()

    def setUp(self):
        reset(STRIX_ENV)

    def test_api_flow_never_returns_key(self):
        st, d = self.s.call("GET", "/api/agent")
        self.assertEqual((st, d["effective"]["source"]), (200, "strix"))
        st, d = self.s.call("POST", "/api/agent/providers", {"name": "OAI", "kind": "openai", "api_key": KEY})
        self.assertEqual((st, d["api_key"]), (200, agentcfg.MASK))
        pid = d["id"]
        st, d = self.s.call("POST", "/api/agent/providers", {"name": "bad", "kind": "openai"})
        self.assertEqual(st, 400)
        st, d = self.s.call("POST", "/api/agent/active", {"provider_id": pid, "model": "gpt-5"})
        self.assertEqual((st, d["effective"]["model"]), (200, "openai/gpt-5"))
        st, d = self.s.call("GET", "/api/agent")
        self.assertNotIn(KEY, json.dumps(d))
        self.assertNotIn("zai-KEY", json.dumps(d))
        st, d = self.s.call("POST", "/api/agent/active", {"provider_id": "", "model": "ignored"})
        self.assertEqual((st, d["effective"]["source"]), (200, "strix"))
        st, _ = self.s.call("DELETE", f"/api/agent/providers/{pid}")
        self.assertEqual(st, 200)
        st, _ = self.s.call("DELETE", f"/api/agent/providers/{pid}")
        self.assertEqual(st, 404)
        st, d = self.s.call("POST", "/api/agent/import-strix", {})
        self.assertEqual((st, d["model"]), (200, "glm-5.3"))


if __name__ == "__main__":
    unittest.main()
