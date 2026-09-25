"""Target interface for communicating with the LLM under test."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from typing import Any

import httpx
from pydantic import BaseModel, Field, model_validator

from infiltr.exceptions import TargetConnectionError, TargetResponseError
from infiltr.logging import get_logger
from infiltr.models import Conversation

logger = get_logger("infiltr.target")

# Upper bound on the TCP/TLS connect phase.  An unreachable or black-holed
# endpoint should fail fast even when a generous response timeout is
# configured for slow LLM generations.
_CONNECT_TIMEOUT_CAP_S = 10.0

# How long an idle pooled connection is kept for reuse.  httpx's default
# (5 s) is shorter than a typical attack-model generation, which runs between
# consecutive probes, so the target connection would otherwise be dropped and
# re-established (TCP + TLS handshake) for nearly every probe of a scan.
_KEEPALIVE_EXPIRY_S = 30.0


class ProbeTimeoutResult(BaseModel):
    """Structured result returned when a probe times out."""

    timed_out: bool = True
    timeout_seconds: float
    endpoint: str
    error_message: str


class TargetConfig(BaseModel):
    """Configuration for the target LLM endpoint."""

    endpoint: str = Field(description="HTTP endpoint URL for the target LLM")
    auth: dict[str, str] = Field(
        default_factory=dict,
        description="Authentication headers (e.g., Authorization: Bearer ...)",
    )
    system_prompt_known: bool = Field(
        default=False,
        description="Whether the system prompt is known to the attacker",
    )
    system_prompt: str | None = Field(
        default=None,
        description="Known system prompt, if available",
    )
    request_template: dict[str, Any] = Field(
        default_factory=lambda: {
            "model": "gpt-4",
            "messages": [],
        },
        description="Template for API requests. Messages will be injected.",
    )
    response_path: str = Field(
        default="choices.0.message.content",
        description="Dot-separated path to extract response text from JSON.",
    )
    timeout_seconds: float = Field(
        default=30.0,
        description=(
            "Deadline in seconds for each HTTP attempt (connect, send and "
            "receive combined)"
        ),
    )
    max_retries: int = Field(default=3, ge=0, le=10)
    max_concurrency: int = Field(
        default=20,
        ge=1,
        le=256,
        description=(
            "Maximum number of requests in flight to the target at once. "
            "Also sizes the connection pool, so callers that fan out never "
            "queue inside the pool (where waiting would count against the "
            "request timeout and inflate measured latency)."
        ),
    )

    @model_validator(mode="after")
    def validate_prompt_consistency(self) -> TargetConfig:
        """Ensure system_prompt is set when system_prompt_known is True."""
        if self.system_prompt_known and not self.system_prompt:
            msg = "system_prompt must be provided when system_prompt_known is True"
            raise ValueError(msg)
        return self


class Target:
    """Interface for sending probes to and receiving responses from a target LLM.

    Handles HTTP communication, retry logic, response parsing, and
    conversation state management for multi-turn interactions.

    Args:
        endpoint: HTTP endpoint URL for the target LLM.
        auth: Authentication headers.
        system_prompt_known: Whether the system prompt is known.
        system_prompt: Known system prompt, if available.
        request_template: Template for API requests.
        response_path: Dot-separated path to extract response text.
        timeout_seconds: HTTP request timeout.
        max_retries: Maximum number of retry attempts on failure.
        max_concurrency: Maximum number of requests in flight at once.
        config: Optional TargetConfig to use instead of individual params.
    """

    def __init__(
        self,
        endpoint: str = "",
        auth: dict[str, str] | None = None,
        system_prompt_known: bool = False,
        system_prompt: str | None = None,
        request_template: dict[str, Any] | None = None,
        response_path: str = "choices.0.message.content",
        timeout_seconds: float = 30.0,
        timeout: float | None = None,
        max_retries: int = 3,
        config: TargetConfig | None = None,
        max_concurrency: int = 20,
    ) -> None:
        effective_timeout = timeout if timeout is not None else timeout_seconds
        if config is not None:
            self._config = config
        else:
            self._config = TargetConfig(
                endpoint=endpoint,
                auth=auth or {},
                system_prompt_known=system_prompt_known,
                system_prompt=system_prompt,
                request_template=request_template or {"model": "gpt-4", "messages": []},
                response_path=response_path,
                timeout_seconds=effective_timeout,
                max_retries=max_retries,
                max_concurrency=max_concurrency,
            )
        self._client: httpx.AsyncClient | None = None
        self._slots: asyncio.Semaphore | None = None
        self._probe_count: int = 0

    @property
    def config(self) -> TargetConfig:
        """Return the target configuration."""
        return self._config

    @property
    def endpoint(self) -> str:
        """Return the target endpoint URL."""
        return self._config.endpoint

    @property
    def probe_count(self) -> int:
        """Return the number of probes sent via this target instance."""
        return self._probe_count

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create a pooled HTTP client.

        The client is created once and reused across all probes,
        providing connection pooling for multi-turn and batched
        strategies.  The pool holds up to ``max_concurrency``
        connections and keeps every one of them alive between
        requests, so a burst of concurrent probes does not churn
        connections.

        Returns:
            An httpx AsyncClient instance.
        """
        if self._client is None or self._client.is_closed:
            size = self._config.max_concurrency
            pool_limits = httpx.Limits(
                max_connections=size,
                max_keepalive_connections=size,
                keepalive_expiry=_KEEPALIVE_EXPIRY_S,
            )
            timeout_s = self._config.timeout_seconds
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    timeout_s,
                    connect=min(timeout_s, _CONNECT_TIMEOUT_CAP_S),
                ),
                headers=self._config.auth,
                limits=pool_limits,
            )
            self._slots = asyncio.Semaphore(size)
        return self._client

    async def _post(
        self,
        client: httpx.AsyncClient,
        body: dict[str, Any],
    ) -> tuple[httpx.Response, float]:
        """POST one request, bounded by the concurrency limit and deadline.

        The concurrency slot is acquired *before* the clock starts, so time
        spent waiting behind other in-flight probes neither counts against
        ``timeout_seconds`` nor inflates the reported latency.  The deadline
        covers the whole attempt: httpx's own timeouts apply per network
        operation, so a server that trickles its response slowly would
        otherwise never time out.

        Returns:
            The response and the attempt's latency in milliseconds.

        Raises:
            TimeoutError: If the attempt exceeds ``timeout_seconds``.
            httpx.HTTPError: On transport-level failures.
        """
        slots = self._slots
        if slots is None:  # client injected directly rather than via _get_client
            slots = self._slots = asyncio.Semaphore(self._config.max_concurrency)
        async with slots:
            start_time = time.monotonic()
            async with asyncio.timeout(self._config.timeout_seconds):
                response = await client.post(self._config.endpoint, json=body)
            return response, (time.monotonic() - start_time) * 1000

    def _build_request_body(
        self,
        prompt: str,
        conversation: Conversation | None = None,
    ) -> dict[str, Any]:
        """Build the request body for the target API.

        Args:
            prompt: The attack prompt to send.
            conversation: Optional conversation history for multi-turn.

        Returns:
            A dictionary representing the request body.
        """
        body = dict(self._config.request_template)
        messages: list[dict[str, str]] = []

        if self._config.system_prompt:
            messages.append({"role": "system", "content": self._config.system_prompt})

        if conversation:
            for turn in conversation.turns:
                role = "user" if turn.role == "attacker" else "assistant"
                messages.append({"role": role, "content": turn.content})

            if not (
                conversation.turns
                and conversation.turns[-1].role == "attacker"
                and conversation.turns[-1].content == prompt
            ):
                messages.append({"role": "user", "content": prompt})
        else:
            messages.append({"role": "user", "content": prompt})
        body["messages"] = messages
        return body

    def _extract_response(self, data: dict[str, Any]) -> str:
        """Extract the response text from the API response JSON.

        Args:
            data: The parsed JSON response from the target.

        Returns:
            The extracted response text.

        Raises:
            TargetResponseError: If the response path doesn't resolve.
        """
        parts = self._config.response_path.split(".")
        current: Any = data

        for part in parts:
            if isinstance(current, dict):
                if part not in current:
                    raise TargetResponseError(
                        200,
                        f"Response path '{self._config.response_path}' "
                        f"not found at key '{part}' in {list(current.keys())}",
                    )
                current = current[part]
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx]
                except (ValueError, IndexError) as exc:
                    raise TargetResponseError(
                        200,
                        f"Response path '{self._config.response_path}' "
                        f"failed at index '{part}'",
                    ) from exc
            else:
                raise TargetResponseError(
                    200,
                    f"Cannot traverse '{part}' on type {type(current).__name__}",
                )

        if not isinstance(current, str):
            return str(current)

        return current

    async def send_probe(
        self,
        prompt: str,
        conversation: Conversation | None = None,
    ) -> tuple[str, float]:
        """Send an attack probe to the target and return the response.

        Args:
            prompt: The attack prompt to send.
            conversation: Optional conversation context for multi-turn attacks.

        Returns:
            A tuple of (response_text, latency_ms).

        Raises:
            TargetConnectionError: If the target cannot be reached.
            TargetResponseError: If the target returns an error response.
        """
        client = await self._get_client()
        body = self._build_request_body(prompt, conversation)

        last_error: Exception | None = None
        for attempt in range(self._config.max_retries + 1):
            try:
                response, latency_ms = await self._post(client, body)

                if response.status_code >= 500:
                    last_error = TargetResponseError(
                        response.status_code, response.text
                    )
                    logger.warning(
                        "target_server_error",
                        status=response.status_code,
                        attempt=attempt + 1,
                    )
                    continue

                if response.status_code >= 400:
                    raise TargetResponseError(response.status_code, response.text)

                data = response.json()
                text = self._extract_response(data)

                self._probe_count += 1
                logger.debug(
                    "probe_sent",
                    probe_number=self._probe_count,
                    prompt_len=len(prompt),
                    response_len=len(text),
                    latency_ms=round(latency_ms, 1),
                )

                return text, latency_ms

            except (httpx.TimeoutException, TimeoutError) as exc:
                last_error = exc
                logger.warning(
                    "target_timeout",
                    attempt=attempt + 1,
                    timeout_s=self._config.timeout_seconds,
                )
                continue
            except httpx.RequestError as exc:
                last_error = exc
                logger.warning(
                    "target_transport_error",
                    attempt=attempt + 1,
                    error=str(exc),
                )
                continue

        raise TargetConnectionError(
            self._config.endpoint,
            f"Exhausted {self._config.max_retries + 1} attempts: {last_error}",
        )

    async def send_probe_safe(
        self,
        prompt: str,
        conversation: Conversation | None = None,
    ) -> tuple[str, float] | ProbeTimeoutResult:
        """Send an attack probe, returning a structured result on timeout.

        Unlike :meth:`send_probe`, this method never raises on timeout
        or connection errors.  Instead it returns a
        :class:`ProbeTimeoutResult` so callers can handle the failure
        without a ``try / except`` block.

        Args:
            prompt: The attack prompt to send.
            conversation: Optional conversation context.

        Returns:
            ``(response_text, latency_ms)`` on success, or a
            :class:`ProbeTimeoutResult` on timeout / connection failure.
        """
        try:
            return await self.send_probe(prompt, conversation)
        except TargetConnectionError as exc:
            logger.warning(
                "probe_timeout_safe",
                endpoint=self._config.endpoint,
                error=str(exc),
            )
            return ProbeTimeoutResult(
                timeout_seconds=self._config.timeout_seconds,
                endpoint=self._config.endpoint,
                error_message=str(exc),
            )

    async def send_probes(
        self,
        prompts: Sequence[str],
        *,
        concurrency: int | None = None,
    ) -> list[tuple[str, float] | ProbeTimeoutResult]:
        """Send independent single-turn probes concurrently.

        At most ``concurrency`` probes (capped at ``max_concurrency``) are in
        flight at any time, using a fixed set of workers rather than one task
        per prompt.  Each probe behaves exactly like :meth:`send_probe_safe`;
        results are returned in the same order as ``prompts``.

        Args:
            prompts: The attack prompts to send.
            concurrency: Optional lower limit on in-flight probes.

        Returns:
            One ``(response_text, latency_ms)`` tuple or
            :class:`ProbeTimeoutResult` per prompt.

        Raises:
            ValueError: If ``concurrency`` is less than 1.
            TargetResponseError: If the target rejects a probe (4xx) or
                returns an unparseable response; remaining probes are
                cancelled.
        """
        limit = self._config.max_concurrency
        if concurrency is not None:
            if concurrency < 1:
                raise ValueError("concurrency must be at least 1")
            limit = min(limit, concurrency)

        results: dict[int, tuple[str, float] | ProbeTimeoutResult] = {}
        indices = iter(range(len(prompts)))

        async def worker() -> None:
            for index in indices:
                results[index] = await self.send_probe_safe(prompts[index])

        tasks = [asyncio.create_task(worker()) for _ in range(min(limit, len(prompts)))]
        try:
            await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        return [results[index] for index in range(len(prompts))]

    async def send_conversation_turn(
        self,
        prompt: str,
        conversation: Conversation,
    ) -> tuple[str, float]:
        """Send a prompt as part of a multi-turn conversation.

        Adds the attacker turn to the conversation, sends the probe,
        then adds the target response to the conversation.

        Args:
            prompt: The attack prompt for this turn.
            conversation: The conversation to continue.

        Returns:
            A tuple of (response_text, latency_ms).
        """
        conversation.add_turn("attacker", prompt)
        response_text, latency_ms = await self.send_probe(prompt, conversation)
        conversation.add_turn("target", response_text)
        return response_text, latency_ms

    async def health_check(self) -> bool:
        """Verify connectivity to the target endpoint.

        Returns:
            True if the target responds, False otherwise.
        """
        try:
            client = await self._get_client()
            response, _ = await self._post(client, self._build_request_body("Hello"))
            return response.status_code < 500
        except (httpx.HTTPError, Exception):
            return False

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            self._slots = None
