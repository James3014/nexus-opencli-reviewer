"""Local risk-model fake server fixture for H1 transport testing.

Spins up a lightweight, ephemeral HTTP server strictly bound to 127.0.0.1
or ::1. Runs in a background thread and automatically tears down when the
context manager exits.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import socket
import threading
import time
from typing import Any, Callable


class FakeHTTPServer(HTTPServer):
    """Subclass of HTTPServer that holds a reference to the fake server controller."""

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        controller: "LocalRiskModelFakeServer",
    ) -> None:
        self.controller = controller
        super().__init__(server_address, RequestHandlerClass)


class FakeServerHandler(BaseHTTPRequestHandler):
    """Configurable handler for fake server test conditions."""

    server: FakeHTTPServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy console logging during test runs
        pass

    def do_POST(self) -> None:
        controller = self.server.controller

        # Check custom behavior hook if provided
        if controller.custom_handler is not None:
            controller.custom_handler(self)
            return

        # Delay simulation
        if controller.delay_seconds > 0:
            time.sleep(controller.delay_seconds)

        # Connection truncation simulation
        if controller.truncate_connection:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"probability":')
            self.wfile.flush()
            # Close connection abruptly
            self.close_connection = True
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        controller.received_requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            }
        )

        # Return configured status / body
        self.send_response(controller.response_code)
        for key, val in controller.response_headers.items():
            self.send_header(key, val)
        self.end_headers()

        if controller.response_body is not None:
            self.wfile.write(controller.response_body)


class LocalRiskModelFakeServer:
    """Ephemeral, localhost-only HTTP fake server for testing."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        response_code: int = 200,
        response_body: bytes | None = None,
        delay_seconds: float = 0.0,
        truncate_connection: bool = False,
        custom_handler: Callable[[BaseHTTPRequestHandler], None] | None = None,
    ) -> None:
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(f"Fake server must only bind to loopback, got {host!r}")

        self.host = host
        self.port = port
        self.response_code = response_code
        self.response_body = response_body if response_body is not None else b'{"probability": 0.5}'
        self.response_headers: dict[str, str] = {"Content-Type": "application/json"}
        self.delay_seconds = delay_seconds
        self.truncate_connection = truncate_connection
        self.custom_handler = custom_handler
        self.received_requests: list[dict[str, Any]] = []

        self._httpd: FakeHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        self._httpd = FakeHTTPServer((self.host, self.port), FakeServerHandler, self)
        assigned_port = self._httpd.server_port
        self.port = assigned_port

        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.endpoint

    @property
    def endpoint(self) -> str:
        if self.host == "::1":
            return f"http://[{self.host}]:{self.port}"
        return f"http://{self.host}:{self.port}"

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> "LocalRiskModelFakeServer":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
