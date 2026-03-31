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


def inject_tab_fix_script(data, is_gzipped=False):
    """Inject the Tab fix script into ttyd HTML responses."""
    try:
        if is_gzipped or (len(data) >= 2 and data[0:2] == b"\x1f\x8b"):
            try:
                data = gzip.decompress(data)
                is_gzipped = True
            except Exception:
                return data

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
        return data


def tunnel_sockets(handler, upstream):
    """Bidirectional socket tunneling."""
    client = handler.connection
    client.setblocking(False)
    upstream.setblocking(False)
    sockets = [client, upstream]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 60)
            if not readable:
                continue
            for sock in readable:
                try:
                    data = sock.recv(8192)
                except BlockingIOError:
                    continue
                except (OSError, ConnectionError):
                    return
                if not data:
                    return
                target = upstream if sock is client else client
                try:
                    target.sendall(data)
                except (OSError, ConnectionError):
                    return
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
    if content_length:
        try:
            length = int(content_length)
        except ValueError:
            length = 0
        if 0 < length <= 10485760:
            body = handler.rfile.read(length)

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
