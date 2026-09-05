"""
Tests for agent.llm_client — the provider-agnostic chat client.

The OpenRouter path is exercised with a mocked HTTP layer so no network
or API key is ever needed.
"""

import json
import os
import sys
import unittest
from unittest import mock

AGENT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"
)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

import llm_client  # noqa: E402


class ResolveProviderTest(unittest.TestCase):
    def test_config_setting_wins_over_env(self):
        with mock.patch.object(
            llm_client, "_read_config", return_value={"llm_provider": "gemini"}
        ), mock.patch.dict(
            os.environ, {"OPENROUTER_API_KEY": "sk-or-x"}, clear=False
        ):
            self.assertEqual(llm_client.resolve_provider(), "gemini")

    def test_auto_detects_openrouter_when_only_or_key_present(self):
        # The deployed cloud app has only OPENROUTER_API_KEY configured
        # (no llm_provider in config.json) — must pick openrouter.
        with mock.patch.object(
            llm_client, "_read_config", return_value={}
        ), mock.patch.dict(
            os.environ, {"OPENROUTER_API_KEY": "sk-or-x"}, clear=True
        ):
            self.assertEqual(llm_client.resolve_provider(), "openrouter")

    def test_defaults_to_gemini_when_no_key(self):
        with mock.patch.object(
            llm_client, "_read_config", return_value={}
        ), mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(llm_client.resolve_provider(), "gemini")


class ResolveModelTest(unittest.TestCase):
    def test_gemini_default_when_no_config(self):
        with mock.patch.object(llm_client, "_read_config", return_value={}):
            self.assertEqual(
                llm_client.resolve_model("gemini"),
                llm_client.DEFAULT_GEMINI_MODEL,
            )

    def test_gemini_uses_configured_model(self):
        with mock.patch.object(
            llm_client, "_read_config", return_value={"model": "gemini-3.6-flash"}
        ):
            self.assertEqual(
                llm_client.resolve_model("gemini"),
                "gemini-3.6-flash",
            )

    def test_openrouter_falls_back_when_model_is_gemini_name(self):
        # Settings starts from the old gemini model when the user switches
        # provider; we must not send a gemini slug to OpenRouter.
        with mock.patch.object(
            llm_client,
            "_read_config",
            return_value={"model": "gemini-3.5-flash-lite"},
        ):
            self.assertEqual(
                llm_client.resolve_model("openrouter"),
                llm_client.DEFAULT_OPENROUTER_MODEL,
            )

    def test_openrouter_uses_configured_slug(self):
        with mock.patch.object(
            llm_client,
            "_read_config",
            return_value={"model": "deepseek/deepseek-chat:free"},
        ):
            self.assertEqual(
                llm_client.resolve_model("openrouter"),
                "deepseek/deepseek-chat:free",
            )


class OpenAIToolsTest(unittest.TestCase):
    def test_schema_converts_to_function_tool(self):
        tools = [{
            "name": "get_merchant_history",
            "description": "Get merchant history",
            "parameters": {
                "type": "object",
                "properties": {"merchant_id": {"type": "string"}},
                "required": ["merchant_id"],
            },
        }]
        converted = llm_client._openai_tools(tools)
        self.assertEqual(converted[0]["type"], "function")
        fn = converted[0]["function"]
        self.assertEqual(fn["name"], "get_merchant_history")
        self.assertEqual(fn["parameters"]["required"], ["merchant_id"])


class OpenRouterChatTest(unittest.TestCase):
    def _chat(self):
        return llm_client.OpenRouterChat(
            base="https://fake.openrouter.ai/api/v1",
            model="test/model:free",
            system="be careful",
            tools=None,
            temperature=0.1,
            api_key="sk-test",
        )

    def _fake_roundtrip(self, responses):
        bodies = []

        def fake_post(url, api_key, body, timeout=180):
            # Deep-copy so later mutations of the live messages list
            # (the assistant reply appended after this request) don't
            # leak into the captured snapshot.
            bodies.append(json.loads(json.dumps(body)))
            return responses.pop(0)

        return bodies, fake_post

    def test_send_returns_text_and_tracks_messages(self):
        chat = self._chat()
        bodies, fake_post = self._fake_roundtrip([{
            "choices": [{"message": {"content": "  plain answer  "}}]
        }])
        with mock.patch.object(llm_client, "_post_json", side_effect=fake_post):
            resp = chat.send("investigate this")

        self.assertEqual(resp.text, "plain answer")
        self.assertEqual(resp.tool_calls, [])
        self.assertEqual(bodies[0]["model"], "test/model:free")
        self.assertEqual(bodies[0]["messages"][0]["role"], "system")
        self.assertEqual(bodies[0]["messages"][1], {
            "role": "user",
            "content": "investigate this",
        })

    def test_tool_call_roundtrip_pairs_tool_results_to_call_ids(self):
        chat = self._chat()
        bodies, fake_post = self._fake_roundtrip([
            {
                "choices": [{"message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "get_merchant_history",
                            "arguments": '{"merchant_id": "MER-1"}',
                        },
                    }],
                }}]
            },
            {
                "choices": [{"message": {
                    "content": '{"fraud_type_guess": "unclear"}'
                }}]
            },
        ])
        with mock.patch.object(llm_client, "_post_json", side_effect=fake_post):
            first = chat.send("investigate")
            second = chat.send_tool_results([{
                "name": "get_merchant_history",
                "response": {"found": False},
            }])

        self.assertEqual(first.tool_calls, [{
            "name": "get_merchant_history",
            "args": {"merchant_id": "MER-1"},
        }])
        self.assertIn("unclear", second.text)

        # The assistant tool-call message and the paired tool result must
        # both be present, with matching tool_call_id.
        roles = [m["role"] for m in bodies[1]["messages"]]
        self.assertEqual(roles, ["system", "user", "assistant", "tool"])
        tool_msg = bodies[1]["messages"][-1]
        self.assertEqual(tool_msg["tool_call_id"], "call_abc")
        self.assertEqual(
            json.loads(tool_msg["content"]),
            {"result": {"found": False}},
        )

    def test_bad_arguments_json_degrades_to_empty_args(self):
        chat = self._chat()
        _, fake_post = self._fake_roundtrip([{
            "choices": [{"message": {
                "content": None,
                "tool_calls": [{
                    "id": "call_x",
                    "type": "function",
                    "function": {"name": "check_geo_ip_consistency",
                                 "arguments": "not json"},
                }],
            }}]
        }])
        with mock.patch.object(llm_client, "_post_json", side_effect=fake_post):
            resp = chat.send("investigate")
        self.assertEqual(resp.tool_calls[0]["args"], {})


if __name__ == "__main__":
    unittest.main()