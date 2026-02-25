"""MCP session handling: SSE and HTTP transport detection."""

import json
import queue
import threading
import time
from urllib.parse import urljoin, urlparse

import httpx

from mcp_attack.core.constants import MCP_INIT_PARAMS, SSE_PATHS, POST_PATHS


def _jrpc(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params or {},
    }


def _probe_sse_path(base: str, path: str, timeout: float = 6.0) -> bool:
    url = base + path
    result: list[bool] = [False]
    done = threading.Event()

    def _try():
        try:
            with httpx.Client(
                verify=False, timeout=httpx.Timeout(timeout, connect=4.0)
            ) as c:
                with c.stream(
                    "GET", url, headers={"Accept": "text/event-stream"}
                ) as resp:
                    ct = resp.headers.get("content-type", "")
                    if resp.status_code == 200 and "text/event-stream" in ct:
                        result[0] = True
                    done.set()
                    for _ in zip(resp.iter_bytes(chunk_size=64), range(3)):
                        pass
        except Exception:
            pass
        finally:
            done.set()

    t = threading.Thread(target=_try, daemon=True)
    t.start()
    done.wait(timeout=timeout + 1)
    return result[0]


class MCPSession:
    """SSE-based MCP session."""

    def __init__(self, base: str, sse_path: str, timeout: float = 25.0):
        self.base = base
        self.sse_url = base + sse_path
        self.post_url: str = ""
        self.timeout = timeout
        self._req_id = 0
        self._q: queue.Queue[dict] = queue.Queue()
        self._stop = threading.Event()
        self._endpoint_ready = threading.Event()
        self._client = httpx.Client(
            verify=False, timeout=timeout, follow_redirects=True
        )
        self._listener = threading.Thread(
            target=self._listen, daemon=True, name=f"sse-{base}"
        )
        self._listener.start()

    def _listen(self):
        try:
            with self._client.stream(
                "GET",
                self.sse_url,
                headers={"Accept": "text/event-stream"},
            ) as resp:
                event_type = "message"
                for raw in resp.iter_lines():
                    if self._stop.is_set():
                        break
                    line = raw.strip()
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        if event_type == "endpoint" and data:
                            self.post_url = (
                                data
                                if data.startswith("http")
                                else self.base + data
                            )
                            self._endpoint_ready.set()
                        elif event_type != "endpoint" and data:
                            try:
                                msg = json.loads(data)
                                self._q.put(msg)
                            except json.JSONDecodeError:
                                pass
                        event_type = "message"
        except Exception:
            pass
        finally:
            self._endpoint_ready.set()

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return self._endpoint_ready.wait(timeout=timeout)

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        wait = timeout or self.timeout
        for attempt in range(retries + 1):
            self._req_id += 1
            payload = _jrpc(method, params, self._req_id)
            try:
                r = self._client.post(
                    self.post_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                if r.status_code not in (200, 202, 204):
                    if attempt < retries:
                        time.sleep(0.5)
                        continue
                    return None
            except Exception:
                if attempt < retries:
                    time.sleep(0.5)
                    continue
                return None

            deadline = time.time() + wait
            pending: list[dict] = []
            while time.time() < deadline:
                try:
                    msg = self._q.get(timeout=0.3)
                    if isinstance(msg, dict) and msg.get("id") == self._req_id:
                        for m in pending:
                            self._q.put(m)
                        return msg
                    pending.append(msg)
                except queue.Empty:
                    pass
            for m in pending:
                self._q.put(m)
            if attempt < retries:
                time.sleep(1.0)
        return None

    def notify(self, method: str, params: dict | None = None):
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        try:
            self._client.post(
                self.post_url,
                json=payload,
                headers=self._headers,
                timeout=5,
            )
        except Exception:
            pass

    def close(self):
        self._stop.set()
        try:
            self._client.close()
        except Exception:
            pass


def _parse_sse_json(text: str, req_id: int | None = None) -> dict | None:
    """Extract JSON-RPC response from SSE body (event: message / data: {...})."""
    for line in text.splitlines():
        if line.startswith("data:"):
            data = line[5:].strip()
            if data:
                try:
                    msg = json.loads(data)
                    if req_id is None or msg.get("id") == req_id:
                        return msg
                except json.JSONDecodeError:
                    pass
    return None


class HTTPSession:
    """Plain HTTP POST fallback (no SSE). Handles both application/json and text/event-stream responses."""

    def __init__(self, base: str, post_url: str, timeout: float = 25.0, headers: dict | None = None):
        self.base = base
        self.sse_url = ""
        self.post_url = post_url
        self.timeout = timeout
        self._req_id = 0
        self._stop = threading.Event()
        self._headers = headers or {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        self._client = httpx.Client(
            verify=False, timeout=timeout, follow_redirects=True
        )

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        for attempt in range(retries + 1):
            self._req_id += 1
            try:
                r = self._client.post(
                    self.post_url,
                    json=_jrpc(method, params, self._req_id),
                    headers=self._headers,
                    timeout=timeout or self.timeout,
                )
                if r.status_code in (200, 202):
                    ct = r.headers.get("content-type", "")
                    if "application/json" in ct:
                        return r.json()
                    # Streamable HTTP: response in SSE format (event: message / data: {...})
                    if "text/event-stream" in ct or "jsonrpc" in r.text:
                        parsed = _parse_sse_json(r.text, self._req_id)
                        if parsed:
                            return parsed
                        # Fallback: try raw JSON
                        try:
                            return r.json()
                        except Exception:
                            pass
            except Exception:
                if attempt < retries:
                    time.sleep(0.5)
        return None

    def notify(self, method: str, params: dict | None = None):
        try:
            self._client.post(
                self.post_url,
                json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params or {},
                },
                timeout=5,
            )
        except Exception:
            pass

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


def detect_transport(
    url: str, connect_timeout: float = 25.0, verbose: bool = False
) -> MCPSession | HTTPSession | None:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    hint = parsed.path.rstrip("/") or None

    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    for p in ([hint] if hint else []) + SSE_PATHS:
        if p is not None and p not in seen_paths:
            seen_paths.add(p)
            ordered_paths.append(p)

    for sse_path in ordered_paths:
        if not _probe_sse_path(base, sse_path, timeout=6.0):
            continue

        session = MCPSession(base, sse_path, timeout=connect_timeout)

        if session.wait_ready(timeout=12.0) and session.post_url:
            return session

        session.close()

    client = httpx.Client(verify=False, timeout=8, follow_redirects=True)

    seen_post: set[str] = set()
    ordered_post: list[str] = []
    for p in ([hint] if hint else []) + POST_PATHS:
        if p is not None and p not in seen_post:
            seen_post.add(p)
            ordered_post.append(p)

    mcp_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    for path in ordered_post:
        post_url = base + path
        try:
            r = client.post(
                post_url,
                json=_jrpc("initialize", MCP_INIT_PARAMS),
                headers=mcp_headers,
                timeout=5,
            )
            is_jsonrpc_body = "jsonrpc" in r.text or "JSON-RPC" in r.text
            is_jsonrpc_error = r.status_code in (400, 422) and (
                is_jsonrpc_body
                or "method" in r.text
                or "error" in r.text.lower()
            )
            # 200 with JSON or SSE body; 202 Accepted (Streamable HTTP)
            if (
                (r.status_code in (200, 202) and is_jsonrpc_body)
                or (r.status_code == 200 and "text/event-stream" in r.headers.get("content-type", ""))
                or is_jsonrpc_error
            ):
                client.close()
                return HTTPSession(base, post_url, timeout=connect_timeout, headers=mcp_headers)
        except Exception:
            pass

    for sse_path in ["/sse", ""]:
        for post_path in ["/messages", "/mcp"]:
            post_url = base + post_path
            try:
                r = client.post(
                    post_url,
                    json=_jrpc("initialize", MCP_INIT_PARAMS),
                    headers=mcp_headers,
                    timeout=4,
                )
                if r.status_code in (400, 404, 422):
                    session = MCPSession(
                        base, sse_path, timeout=connect_timeout
                    )
                    if session.wait_ready(timeout=10.0) and session.post_url:
                        client.close()
                        return session
                    session.close()
            except Exception:
                pass

    client.close()
    return None
