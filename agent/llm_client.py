"""
Provider-agnostic LLM chat client for the fraud investigation agent.

Two providers are supported:

- ``gemini`` (default): Google's Gemini API via the google-genai SDK.
  Model names look like ``gemini-3.5-flash-lite``.
- ``openrouter``: OpenAI-compatible API at ``openrouter.ai/api/v1``,
  implemented with stdlib ``urllib`` so no new dependency is required.
  Model names are OpenRouter slugs like ``google/gemini-2.5-flash-lite:free``.

Both expose the same interface so ``agent_loop.py`` stays provider-agnostic:

    client = build_client(api_key)          # provider read from config.json
    chat = client.start_chat(system=..., tools=[...], temperature=0.1)
    resp = chat.send(prompt)                # -> LLMResponse
    resp = chat.send_tool_results([...])    # -> LLMResponse

``LLMResponse`` carries ``text`` (str | None) and ``tool_calls``
(a list of ``{"name": str, "args": dict}``).

The active provider and model are read from ``config.json`` (written by
the dashboard's Settings tab); the API key comes from the matching
environment variable (``OPENROUTER_API_KEY`` / ``GEMINI_API_KEY``).
"""

import json
import os
import urllib.error
import urllib.request

from google import genai
from google.genai import types

DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"
DEFAULT_OPENROUTER_MODEL = "google/gemini-2.5-flash-lite:free"
OPENROUTER_BASE = "https://openrouter.ai/api/v1"


class LLMResponse:
    """Normalized response shared by every provider."""

    __slots__ = ("text", "tool_calls")

    def __init__(self, text=None, tool_calls=None):
        self.text = text
        self.tool_calls = tool_calls or []


def _read_config() -> dict:
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = json.load(f)
        if isinstance(cfg, dict):
            return cfg
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def resolve_provider() -> str:
    """Active provider ('gemini' or 'openrouter').

    Explicit config.json setting wins. Otherwise auto-detect from the
    key that is present (an OPENROUTER_API_KEY in the environment means
    openrouter) so a Streamlit Cloud app that only has the OpenRouter
    secret configured just works without touching config.json."""
    provider = _read_config().get("llm_provider")
    if provider in ("gemini", "openrouter"):
        return provider
    if os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter"
    return "gemini"


def resolve_model(provider: str = None) -> str:
    """Model for the provider from config.json, with sane defaults.

    For OpenRouter we fall back to a free model slug whenever the
    configured model is missing or still a Gemini name (the Settings tab
    starts from the old config, so the switch would otherwise break).
    Symmetrically, for Gemini we never send an OpenRouter-style slug
    (contains '/') — the Settings tab can leave one behind after a
    provider switch back to gemini, and the Gemini API would reject it
    as an unknown model."""
    provider = provider or resolve_provider()
    model = str(_read_config().get("model", "") or "").strip()

    if provider == "openrouter":
        if not model or "gemini" in model.lower():
            return DEFAULT_OPENROUTER_MODEL
        return model

    if not model or "/" in model:
        return DEFAULT_GEMINI_MODEL
    return model


def build_client(api_key: str = None, provider: str = None):
    """Create a client for the active provider.

    ``api_key`` defaults to the provider's environment variable. The
    provider defaults to config.json's ``llm_provider``."""
    provider = provider or resolve_provider()
    if provider == "openrouter":
        return OpenRouterClient(
            api_key or os.environ.get("OPENROUTER_API_KEY", "")
        )
    return GeminiClient(
        api_key or os.environ.get("GEMINI_API_KEY", "")
    )


# ---------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------

class GeminiClient:
    def __init__(self, api_key: str, model: str = None):
        self._api_key = api_key
        self._model = model or resolve_model("gemini")
        # Hold the underlying genai.Client for the lifetime of this
        # wrapper. google-genai's Client closes its HTTP transport when
        # it is garbage-collected; creating the client inline inside
        # start_chat() let it be collected immediately, and the returned
        # Chat then failed on the next send with "Cannot send a request,
        # as the client has been closed."
        self._genai_client = None

    def start_chat(self, system: str, tools: list = None, temperature: float = 0.1):
        tool = None
        if tools:
            tool = types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name=t["name"],
                        description=t["description"],
                        parameters=t["parameters"],
                    )
                    for t in tools
                ]
            )
        if self._genai_client is None:
            self._genai_client = genai.Client(api_key=self._api_key)
        chat = self._genai_client.chats.create(
            model=self._model,
            config=types.GenerateContentConfig(
                system_instruction=system,
                tools=[tool] if tool else None,
                temperature=temperature,
            ),
        )
        return GeminiChat(chat, self._genai_client)


class GeminiChat:
    def __init__(self, chat, client=None):
        self._chat = chat
        # Keep a reference to the genai.Client so it stays alive (and
        # un-closed) for the whole conversation, even if the wrapper
        # GeminiClient is dropped.
        self._client = client

    def send(self, content) -> LLMResponse:
        return self._to_response(self._chat.send_message(content))

    def send_tool_results(self, tool_results: list) -> LLMResponse:
        parts = [
            types.Part.from_function_response(
                name=r["name"],
                response={"result": r["response"]},
            )
            for r in tool_results
        ]
        return self._to_response(self._chat.send_message(parts))

    @staticmethod
    def _to_response(resp) -> LLMResponse:
        if not resp.candidates:
            return LLMResponse(text=None, tool_calls=[])
        parts = resp.candidates[0].content.parts
        calls = []
        for part in parts:
            fc = getattr(part, "function_call", None)
            if fc is not None:
                calls.append({
                    "name": fc.name,
                    "args": dict(fc.args or {}),
                })
        text = resp.text.strip() if resp.text else None
        return LLMResponse(text=text, tool_calls=calls)


# ---------------------------------------------------------------------
# OpenRouter (OpenAI-compatible, stdlib-only)
# ---------------------------------------------------------------------

def _post_json(url: str, api_key: str, body: dict, timeout: int = 180):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            detail = ""
        # Keep the status code visible so the retry layer in
        # agent_loop.py can recognize 429/503 rate limits.
        raise RuntimeError(f"OpenRouter HTTP {exc.code}: {detail}") from exc


def _openai_tools(tools: list) -> list:
    """Convert the project's tool schema to OpenAI function-calling tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for t in tools
    ]


class OpenRouterClient:
    def __init__(self, api_key: str, model: str = None, base: str = None):
        self._api_key = api_key
        self._model = model or resolve_model("openrouter")
        self._base = (base or os.environ.get(
            "OPENROUTER_BASE", OPENROUTER_BASE
        )).rstrip("/")

    def start_chat(self, system: str, tools: list = None, temperature: float = 0.1):
        return OpenRouterChat(
            base=self._base,
            model=self._model,
            system=system,
            tools=tools,
            temperature=temperature,
            api_key=self._api_key,
        )


class OpenRouterChat:
    def __init__(self, base: str, model: str, system: str, tools: list,
                 temperature: float, api_key: str):
        self._url = f"{base}/chat/completions"
        self._model = model
        self._api_key = api_key
        self._temperature = temperature
        self._tools = _openai_tools(tools) if tools else None
        self._messages = [{"role": "system", "content": system}]
        self._pending_tool_calls = []

    def send(self, content) -> LLMResponse:
        self._messages.append({"role": "user", "content": content})
        return self._roundtrip()

    def send_tool_results(self, tool_results: list) -> LLMResponse:
        for call, result in zip(self._pending_tool_calls, tool_results):
            self._messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": json.dumps(
                    {"result": result["response"]},
                    default=str,
                ),
            })
        self._pending_tool_calls = []
        return self._roundtrip()

    def _roundtrip(self) -> LLMResponse:
        body = {
            "model": self._model,
            "messages": self._messages,
            "temperature": self._temperature,
        }
        if self._tools:
            body["tools"] = self._tools

        data = _post_json(self._url, self._api_key, body)
        message = data["choices"][0]["message"]

        text = message.get("content") or None
        if isinstance(text, str):
            text = text.strip() or None

        raw_tool_calls = message.get("tool_calls") or []
        calls = []
        assistant_tool_calls = []
        for tc in raw_tool_calls:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
                if not isinstance(args, dict):
                    args = {}
            except json.JSONDecodeError:
                args = {}
            calls.append({
                "name": fn.get("name", ""),
                "args": args,
            })
            assistant_tool_calls.append({
                "id": tc.get("id", ""),
                "type": "function",
                "function": {
                    "name": fn.get("name", ""),
                    "arguments": fn.get("arguments", ""),
                },
            })
            self._pending_tool_calls.append({
                "id": tc.get("id", ""),
                "name": fn.get("name", ""),
            })

        assistant_msg = {"role": "assistant", "content": text}
        if assistant_tool_calls:
            assistant_msg["tool_calls"] = assistant_tool_calls
        self._messages.append(assistant_msg)

        return LLMResponse(text=text, tool_calls=calls)