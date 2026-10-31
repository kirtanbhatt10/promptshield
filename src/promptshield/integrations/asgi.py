"""ASGI middleware that blocks prompt-injection before it reaches your LLM route.

Works with FastAPI, Starlette and any ASGI app::

    app.add_middleware(PromptShieldMiddleware, scanner=Scanner(), paths=("/chat",), field="message")
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from ..scanner import Scanner

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class PromptShieldMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        scanner: Scanner | None = None,
        paths: Iterable[str] = ("/",),
        field: str = "prompt",
        max_body: int = 1_000_000,
    ) -> None:
        self.app = app
        self.scanner = scanner or Scanner()
        self.paths = tuple(paths)
        self.field = field
        self.max_body = max_body

    def _watched(self, scope: Scope) -> bool:
        return (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and any(scope.get("path", "").startswith(p) for p in self.paths)
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self._watched(scope):
            await self.app(scope, receive, send)
            return

        chunks, size = [], 0
        while True:
            message = await receive()
            body = message.get("body", b"")
            size += len(body)
            if size > self.max_body:
                await _respond(send, 413, {"error": "request body too large"})
                return
            chunks.append(body)
            if not message.get("more_body"):
                break
        raw = b"".join(chunks)

        text = _extract(raw, self.field)
        if text is not None:
            result = self.scanner.scan_input(text)
            if result.blocked:
                await _respond(send, 400, {"error": "prompt rejected by promptshield", "scan": result.to_dict()})
                return

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def _extract(raw: bytes, field: str) -> str | None:
    try:
        data = json.loads(raw or b"null")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    value = data.get(field) if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


async def _respond(send: Send, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
