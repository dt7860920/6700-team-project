"""The one model client every agent shares (OpenAI-compatible ``/chat/completions``).

Agents are *definitions*, not services: the planner and the analyst both go through
this client to the single pinned model. Two things live here that the agents must not
re-implement:

* **Tool transport.** With ``protocol="native"`` the request carries OpenAI
  ``tools`` and the reply's ``message.tool_calls`` are returned as :class:`ToolCall`
  objects. With ``protocol="text"`` no ``tools`` field is sent and the model is expected
  to answer with one JSON action in its content (parsed by :mod:`ono.agents.protocol`).
  ``"auto"`` starts native and flips to text *for the rest of the process* the first time
  the endpoint rejects the ``tools`` field (Ollama answers ``400 ... does not support
  tools`` for such models), so one bad first request never costs more than one retry.
* **The call budget.** :class:`CallBudget` is a hard counter the orchestrator creates per
  scan; a call past the budget raises :class:`BudgetExhaustedError` *before* any HTTP
  request is made.

Transport errors propagate as :class:`ModelError` so a scan is reported *failed*, never
silently "clean".
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from ono.config import AgentToolProtocol, Settings

__all__ = [
    "BudgetExhaustedError",
    "CallBudget",
    "ChatModel",
    "ModelClient",
    "ModelError",
    "ModelReply",
    "ToolCall",
]

log = logging.getLogger(__name__)

MODEL_TIMEOUT_S = 120.0
MAX_REPLY_CHARS = 20_000  # anything longer is not a tool call or a verdict; cut it


class ModelError(RuntimeError):
    """The endpoint could not be used (unreachable, non-2xx, malformed body)."""


class BudgetExhaustedError(ModelError):
    """The scan-wide model-call budget is spent; no request was made."""


@dataclass(slots=True)
class ToolCall:
    """One tool invocation the model asked for (native or text protocol, same shape)."""

    name: str
    args: dict[str, Any]
    call_id: str = ""  # native tool_call id to echo back; "" under the text protocol


@dataclass(slots=True)
class ModelReply:
    """One assistant turn: free text, native tool calls, and the raw message to echo."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    protocol: AgentToolProtocol = "text"
    raw_message: dict[str, Any] = field(default_factory=dict)
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(slots=True)
class CallBudget:
    """A hard cap on model calls; shared by every agent step of one scan."""

    limit: int
    used: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def take(self) -> None:
        if self.used >= self.limit:
            msg = f"model-call budget exhausted ({self.used}/{self.limit})"
            raise BudgetExhaustedError(msg)
        self.used += 1


class ChatModel(Protocol):
    """What the agents need from a model. Tests substitute a scripted fake."""

    @property
    def protocol(self) -> AgentToolProtocol: ...

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        budget: CallBudget | None = None,
    ) -> ModelReply: ...


class ModelClient:
    """Thin, typed client for an OpenAI-compatible chat endpoint (Ollama, vLLM, ...)."""

    def __init__(
        self,
        settings: Settings,
        *,
        timeout_s: float = MODEL_TIMEOUT_S,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not settings.model_service_url:
            msg = "ModelClient requires settings.model_service_url"
            raise ValueError(msg)
        self.base_url = settings.model_service_url.rstrip("/")
        self.model_name = settings.model_name
        self._api_key = settings.model_service_api_key
        self._lock = threading.Lock()
        self._protocol: AgentToolProtocol = settings.agent_tool_protocol
        self._http = httpx.Client(timeout=timeout_s, transport=transport)

    @property
    def protocol(self) -> AgentToolProtocol:
        """``native`` or ``text`` once decided; ``auto`` until the first tool-bearing call."""
        return self._protocol

    def close(self) -> None:
        self._http.close()

    # -- one round-trip -----------------------------------------------------------
    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        budget: CallBudget | None = None,
    ) -> ModelReply:
        """One ``/chat/completions`` call. ``tools`` are sent only under the native protocol."""
        if budget is not None:
            budget.take()
        send_tools = bool(tools) and self._protocol != "text"
        try:
            reply = self._post(messages, tools if send_tools else None, temperature)
        except ModelError as exc:
            if send_tools and self._protocol == "auto" and _rejects_tools(exc):
                with self._lock:
                    self._protocol = "text"
                log.warning(
                    "agents: endpoint rejected native tool calling (%s); using the text "
                    "protocol from now on",
                    exc,
                )
                reply = self._post(messages, None, temperature)
            else:
                raise
        if send_tools and self._protocol == "auto":
            with self._lock:
                self._protocol = "native"
        reply.protocol = "native" if send_tools and self._protocol == "native" else "text"
        return reply

    def _post(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        temperature: float,
    ) -> ModelReply:
        payload: dict[str, object] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        headers: dict[str, str] = {}
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key.get_secret_value()}"
        try:
            response = self._http.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
        except httpx.HTTPError as exc:
            raise ModelError(f"model endpoint unreachable at {self.base_url}: {exc}") from exc
        if not response.is_success:
            raise ModelError(
                f"model endpoint returned {response.status_code}: {response.text[:300]}"
            )
        try:
            body = response.json()
            message = body["choices"][0]["message"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelError("model endpoint returned an unexpected chat-completions body") from exc
        if not isinstance(message, dict):
            raise ModelError("model endpoint returned a non-object message")
        return _reply_from_message(message, body.get("usage"))


def _rejects_tools(exc: ModelError) -> bool:
    text = str(exc).lower()
    return "returned 4" in text and "tool" in text


def _reply_from_message(message: dict[str, Any], usage: object) -> ModelReply:
    content = message.get("content")
    text = content if isinstance(content, str) else ""
    if len(text) > MAX_REPLY_CHARS:
        text = text[:MAX_REPLY_CHARS]
    calls: list[ToolCall] = []
    raw_calls = message.get("tool_calls")
    if isinstance(raw_calls, list):
        for item in raw_calls:
            call = _tool_call_from(item)
            if call is not None:
                calls.append(call)
    prompt_tokens = completion_tokens = None
    if isinstance(usage, dict):
        prompt_tokens = _opt_int(usage.get("prompt_tokens"))
        completion_tokens = _opt_int(usage.get("completion_tokens"))
    return ModelReply(
        text=text,
        tool_calls=calls,
        raw_message=message,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )


def _tool_call_from(item: object) -> ToolCall | None:
    """OpenAI ``{"id", "function": {"name", "arguments": "<json>"}}``; Ollama may send a dict."""
    if not isinstance(item, dict):
        return None
    function = item.get("function")
    if not isinstance(function, dict):
        return None
    name = str(function.get("name") or "").strip()
    if not name:
        return None
    arguments = function.get("arguments")
    args: dict[str, Any] = {}
    if isinstance(arguments, dict):
        args = arguments
    elif isinstance(arguments, str) and arguments.strip():
        try:
            parsed = json.loads(arguments)
        except ValueError:
            parsed = {"__malformed__": arguments[:500]}
        args = parsed if isinstance(parsed, dict) else {"value": parsed}
    return ToolCall(name=name, args=args, call_id=str(item.get("id") or ""))


def _opt_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
