"""Upstream ttyd proxy helpers for HTTP, WebSocket, and HTML injection."""
import gzip
import http.client
import select
import socket
import sys

from ttydproxy.assets import TAB_FIX_SCRIPT


TTYD_PROXY_HTML_CSP = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'self'; "
    "object-src 'none'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'"
)

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
    "content-length", "authorization",
}

TUNNEL_RECV_SIZE = 8192
TUNNEL_MAX_PENDING = 1048576  # 1 MiB per direction before backpressure kicks in
TUNNEL_SELECT_TIMEOUT = 60

# Largest request body forwarded to ttyd. A client body above this is rejected
# with 413 rather than silently dropped (B4).
TTYD_MAX_BODY = 10485760  # 10 MiB


def is_websocket_request(handler):
    """Check if the current request is a WebSocket upgrade request."""
    return handler.headers.get("Upgrade", "").lower() == "websocket"


def build_ttyd_headers(handler, port):
    """Build headers for proxying a request to ttyd."""
    headers = {}
    for key, value in handler.headers.items():
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        headers[key] = value
    headers["Host"] = f"127.0.0.1:{port}"
    headers["X-Forwarded-For"] = handler.client_address[0]
    return headers


def inject_tab_fix_script(data):
    """Inject the Tab fix script into ttyd HTML responses.

    On any failure the ORIGINAL input bytes are returned unchanged, so a caller
    forwarding Content-Encoding: gzip stays consistent even when the
    decompressed payload can't be decoded (B3).
    """
    original = data
    try:
        is_gzipped = False
        if len(data) >= 2 and data[0:2] == b"\x1f\x8b":
            try:
                data = gzip.decompress(data)
                is_gzipped = True
            except Exception:
                return original

        html = data.decode("utf-8")
        script = TAB_FIX_SCRIPT

        if "<head>" in html:
            html = html.replace("<head>", "<head>" + script, 1)
        elif "<head " in html:
            idx = html.find("<head ")
            end_idx = html.find(">", idx)
            if end_idx != -1:
                html = html[:end_idx + 1] + script + html[end_idx + 1:]
        elif "<html>" in html:
            html = html.replace("<html>", "<html>" + script, 1)
        elif html.strip():
            html = script + html

        result = html.encode("utf-8")
        if is_gzipped:
            result = gzip.compress(result)
        return result
    except Exception:
        return original


def tunnel_sockets(handler, upstream):
    """Bidirectional socket tunneling with write buffering and backpressure.

    Non-blocking sockets require partial-send accounting: sendall() would
    raise BlockingIOError on a full kernel buffer after possibly sending
    only part of the data, silently dropping bytes and killing the tunnel.
    """
    client = handler.connection
    client.setblocking(False)
    upstream.setblocking(False)
    peer = {client: upstream, upstream: client}
    pending = {client: bytearray(), upstream: bytearray()}
    eof = {client: False, upstream: False}
    try:
        while True:
            # Once either side EOFs, the tunnel is logically done: stop
            # ingesting new data, drain BOTH pending buffers, then close.
            # Returning before pending[client] is flushed would drop ttyd
            # output that the (possibly half-closed) client can still read.
            draining = eof[client] or eof[upstream]
            if draining and not pending[client] and not pending[upstream]:
                return

            if draining:
                read_set = []
            else:
                # Stop reading a side whose peer's outbound buffer is full;
                # may overshoot the cap by at most one recv chunk.
                read_set = [
                    sock for sock in (client, upstream)
                    if len(pending[peer[sock]]) < TUNNEL_MAX_PENDING
                ]
            write_set = [sock for sock in (client, upstream) if pending[sock]]
            if not read_set and not write_set:
                return

            readable, writable, _ = select.select(
                read_set, write_set, [], TUNNEL_SELECT_TIMEOUT
            )
            if not readable and not writable:
                if write_set:
                    # A peer with pending data was unwritable for the whole
                    # timeout: it vanished without a FIN (crashed client,
                    # network partition). Bail out instead of spinning until
                    # the OS TCP keepalive notices, hours later.
                    return
                continue

            for sock in writable:
                buf = pending[sock]
                try:
                    sent = sock.send(buf)
                except (BlockingIOError, InterruptedError):
                    continue
                except (OSError, ConnectionError):
                    return
                if sent:
                    del buf[:sent]

            for sock in readable:
                try:
                    data = sock.recv(TUNNEL_RECV_SIZE)
                except (BlockingIOError, InterruptedError):
                    continue
                except (OSError, ConnectionError):
                    return
                if not data:
                    eof[sock] = True
                    continue
                target = peer[sock]
                buf = pending[target]
                if not buf:
                    try:
                        sent = target.send(data)
                    except (BlockingIOError, InterruptedError):
                        sent = 0
                    except (OSError, ConnectionError):
                        return
                    data = data[sent:]
                if data:
                    buf.extend(data)
    except Exception:
        return


def proxy_ttyd_websocket(handler, upstream_path, port):
    """Proxy WebSocket traffic to ttyd."""
    upstream = None
    try:
        upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
    except OSError as exc:
        print(f"TTYD proxy error: {exc}", file=sys.stderr, flush=True)
        handler.send_json(502, {"error": "TTYD unavailable"})
        return

    try:
        headers = build_ttyd_headers(handler, port)
        headers["Connection"] = "Upgrade"
        headers["Upgrade"] = "websocket"

        request_lines = [f"{handler.command} {upstream_path} {handler.request_version}"]
        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")
        request_lines.append("")
        request_lines.append("")
        upstream.sendall("\r\n".join(request_lines).encode("utf-8"))

        handler.close_connection = True
        tunnel_sockets(handler, upstream)
    except Exception:
        pass
    finally:
        if upstream:
            try:
                upstream.shutdown(socket.SHUT_RDWR)
            except (OSError, ConnectionError):
                pass
            upstream.close()


def proxy_ttyd_http(handler, upstream_path, port):
    """Proxy an HTTP request to ttyd."""
    body = None
    content_length = handler.headers.get("Content-Length")
    if content_length is not None:
        # A malformed/oversized body must be rejected with an explicit 4xx, not
        # silently dropped while the request is forwarded body-less (B4).
        try:
            length = int(content_length)
        except ValueError:
            handler.send_json(400, {"error": "Invalid Content-Length"})
            return
        if length < 0 or length > TTYD_MAX_BODY:
            handler.send_json(413, {"error": "Request too large"})
            return
        if length > 0:
            body = handler.rfile.read(length)
    elif handler.headers.get("Transfer-Encoding"):
        # No Content-Length but the client framed a body (e.g. chunked). We do
        # not de-chunk; forwarding an empty body would silently lose it (B4).
        handler.send_json(411, {"error": "Length required"})
        return

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        headers = build_ttyd_headers(handler, port)
        conn.request(handler.command, upstream_path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()

        content_type = ""
        for key, value in resp.getheaders():
            if key.lower() == "content-type":
                content_type = value
                break
        # Normalize the value so injection + CSP hardening fire regardless of
        # upstream header casing (e.g. 'Text/HTML') (B6).
        content_type = content_type.lower()

        if "text/html" in content_type and data:
            data = inject_tab_fix_script(data)

        handler.send_response(resp.status, resp.reason)

        if "text/html" in content_type:
            handler.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            handler.send_header("Pragma", "no-cache")
            handler.send_header("Expires", "0")

        skip_headers = set(HOP_BY_HOP_HEADERS)
        if "text/html" in content_type:
            skip_headers.add("content-security-policy")

        for key, value in resp.getheaders():
            if key.lower() in skip_headers:
                continue
            handler.send_header(key, value)

        if "text/html" in content_type:
            handler.send_header("Content-Security-Policy", TTYD_PROXY_HTML_CSP)

        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        if data:
            handler.wfile.write(data)
    except OSError as exc:
        print(f"TTYD proxy error: {exc}", file=sys.stderr, flush=True)
        handler.send_json(502, {"error": "TTYD unavailable"})
    finally:
        try:
            conn.close()
        except Exception:
            pass
