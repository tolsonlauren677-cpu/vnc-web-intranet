#!/usr/bin/env python3
"""
WebSocket <-> VNC TCP proxy for noVNC.

The browser speaks RFB over WebSocket. This proxy turns that WebSocket stream
into a plain TCP connection to the target VNC server.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import threading
import urllib.parse
from typing import Any

from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed

try:
    from Crypto.Cipher import DES
except ImportError:  # pragma: no cover - optional import during test only
    DES = None


logger = logging.getLogger("vnc_web_client.proxy")

SECURITY_TYPES = {
    1: "None",
    2: "VNC Authentication",
    5: "TLS",
    13: "VeNCrypt",
    16: "Tight",
    17: "Ultra",
    18: "TLS (VeNCrypt)",
    19: "VeNCrypt",
    128: "UltraVNC MS Logon II",
    129: "UltraVNC MS Logon II AD",
    130: "UltraVNC SCP",
    131: "UltraVNC MS Logon III",
    132: "UltraVNC DSM",
    133: "UltraVNC MS Logon IV",
    192: "UltraVNC MS Logon V",
}
VENDOR_SECURITY_TYPES = set(range(128, 256))
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]+$")


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        data = sock.recv(size - len(chunks))
        if not data:
            raise ConnectionError(f"Expected {size} bytes, got {len(chunks)} bytes before EOF")
        chunks.extend(data)
    return bytes(chunks)


def parse_rfb_version(version_bytes: bytes) -> tuple[int, int]:
    try:
        text = version_bytes.decode("ascii")
        major = int(text[4:7])
        minor = int(text[8:11])
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise ValueError(f"Invalid RFB version banner: {version_bytes!r}") from exc
    return major, minor


def choose_client_version(server_version: bytes) -> bytes:
    major, minor = parse_rfb_version(server_version)
    if (major, minor) >= (3, 8):
        return b"RFB 003.008\n"
    if (major, minor) >= (3, 7):
        return b"RFB 003.007\n"
    return b"RFB 003.003\n"


def reverse_bits(value: int) -> int:
    result = 0
    for _ in range(8):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def encrypt_vnc_password(password: str, challenge: bytes) -> bytes:
    if DES is None:
        raise RuntimeError("pycryptodome is required for password validation.")

    key = password.encode("latin-1", errors="ignore")[:8].ljust(8, b"\x00")
    reversed_key = bytes(reverse_bits(byte) for byte in key)
    cipher = DES.new(reversed_key, DES.MODE_ECB)
    return cipher.encrypt(challenge[:8]) + cipher.encrypt(challenge[8:16])


def describe_security_types(security_types: list[int]) -> list[str]:
    return [SECURITY_TYPES.get(value, f"Unknown({value})") for value in security_types]


def security_failure_reason(sock: socket.socket) -> str:
    try:
        reason_length = struct.unpack("!I", recv_exact(sock, 4))[0]
        if reason_length == 0:
            return "认证失败，服务端没有返回详细原因。"
        return recv_exact(sock, reason_length).decode("utf-8", errors="replace")
    except Exception:
        return "认证失败，未能读取服务端错误信息。"


def test_vnc_connection(
    host: str,
    port: int,
    password: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """
    Validate that the target speaks RFB and optionally verify VNC password auth.

    TightVNC commonly offers security types 2 (classic VNC auth) and 16 (Tight).
    UltraVNC offers types 128-192 for various MS Logon variants.
    For diagnostics, this function prefers type 2 when a password is provided,
    then type 1, then falls back to standard auth methods.
    """

    def choose_security(security_types: list[int], has_password: bool) -> int | None:
        """Choose the best security type to attempt."""
        if has_password and 2 in security_types:
            return 2
        if 1 in security_types:
            return 1
        if 2 in security_types:
            return 2
        # For vendor-specific types (128-255), try None auth as fallback
        if any(t in VENDOR_SECURITY_TYPES for t in security_types) and 1 in security_types:
            return 1
        return None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            server_version = recv_exact(sock, 12)
            client_version = choose_client_version(server_version)
            server_major, server_minor = parse_rfb_version(server_version)
            sock.sendall(client_version)

            security_types: list[int]
            selected_security: int | None = None

            if (server_major, server_minor) >= (3, 7):
                count = recv_exact(sock, 1)[0]
                if count == 0:
                    return {
                        "success": False,
                        "message": security_failure_reason(sock),
                        "version": server_version.decode("ascii", errors="replace").strip(),
                    }

                security_types = list(recv_exact(sock, count))
                selected_security = choose_security(security_types, bool(password))

                if selected_security is None:
                    has_vendor_types = any(t in VENDOR_SECURITY_TYPES for t in security_types)
                    if has_vendor_types:
                        # Server is reachable but only offers vendor-specific types.
                        # Return partial success so the web client can attempt connection.
                        return {
                            "success": True,
                            "partial": True,
                            "message": f"服务器可达，但仅提供厂商自定义安全类型: {describe_security_types(security_types)}。测试器无法验证认证，但 noVNC 客户端可能支持。请尝试连接。",
                            "version": server_version.decode("ascii", errors="replace").strip(),
                            "security_types": describe_security_types(security_types),
                            "vendor_types": True,
                        }
                    return {
                        "success": False,
                        "message": f"当前测试器不支持服务端提供的安全类型: {describe_security_types(security_types)}",
                        "version": server_version.decode("ascii", errors="replace").strip(),
                        "security_types": describe_security_types(security_types),
                    }

                sock.sendall(bytes([selected_security]))

                if selected_security == 2:
                    challenge = recv_exact(sock, 16)
                    sock.sendall(encrypt_vnc_password(password or "", challenge))

                if selected_security != 1 or (server_major, server_minor) >= (3, 8):
                    result = struct.unpack("!I", recv_exact(sock, 4))[0]
                    if result != 0:
                        return {
                            "success": False,
                            "message": security_failure_reason(sock),
                            "version": server_version.decode("ascii", errors="replace").strip(),
                            "security_types": describe_security_types(security_types),
                        }
            else:
                selected_security = struct.unpack("!I", recv_exact(sock, 4))[0]
                security_types = [selected_security]
                if selected_security == 0:
                    return {
                        "success": False,
                        "message": security_failure_reason(sock),
                        "version": server_version.decode("ascii", errors="replace").strip(),
                    }
                if selected_security == 2:
                    if not password:
                        return {
                            "success": False,
                            "message": "服务端要求 VNC 密码认证，但当前没有提供密码。",
                            "version": server_version.decode("ascii", errors="replace").strip(),
                            "security_types": describe_security_types(security_types),
                        }
                    challenge = recv_exact(sock, 16)
                    sock.sendall(encrypt_vnc_password(password, challenge))
                    result = struct.unpack("!I", recv_exact(sock, 4))[0]
                    if result != 0:
                        return {
                            "success": False,
                            "message": security_failure_reason(sock),
                            "version": server_version.decode("ascii", errors="replace").strip(),
                            "security_types": describe_security_types(security_types),
                        }
                elif selected_security != 1:
                    return {
                        "success": False,
                        "message": f"当前测试器不支持服务端提供的安全类型: {describe_security_types(security_types)}",
                        "version": server_version.decode("ascii", errors="replace").strip(),
                        "security_types": describe_security_types(security_types),
                    }

            sock.sendall(b"\x01")
            server_init = recv_exact(sock, 24)
            width, height = struct.unpack("!HH", server_init[:4])
            name_length = struct.unpack("!I", server_init[20:24])[0]
            desktop_name = recv_exact(sock, name_length).decode("utf-8", errors="replace")

            security_label = SECURITY_TYPES.get(selected_security or -1, "Unknown")
            auth_text = "密码认证通过" if selected_security == 2 else "无需密码认证"

            return {
                "success": True,
                "message": f"连接成功，{auth_text}，桌面 {desktop_name} ({width}x{height})。",
                "version": server_version.decode("ascii", errors="replace").strip(),
                "security_types": describe_security_types(security_types),
                "selected_security": security_label,
                "desktop_name": desktop_name,
                "width": width,
                "height": height,
            }

    except socket.timeout:
        return {"success": False, "message": "连接超时。"}
    except ConnectionRefusedError:
        return {"success": False, "message": "连接被拒绝。"}
    except OSError as exc:
        return {"success": False, "message": str(exc)}
    except Exception as exc:
        logger.exception("Unexpected VNC test failure: %s", exc)
        return {"success": False, "message": str(exc)}


class VNCProxyServer:
    """
    Dedicated WebSocket-to-TCP bridge for noVNC.

    The browser connects to:
        ws://<proxy-host>:<proxy-port>/websockify?host=192.168.1.3&port=5900
    """

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 6080,
        connect_timeout: float = 10.0,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.connect_timeout = connect_timeout

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stop_event: asyncio.Event | None = None
        self._started = threading.Event()
        self._startup_error: Exception | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._started.clear()
        self._startup_error = None
        self._thread = threading.Thread(
            target=self._run_server_loop,
            name="vnc-websocket-proxy",
            daemon=True,
        )
        self._thread.start()
        self._started.wait(timeout=10)

        if self._startup_error is not None:
            raise RuntimeError("Failed to start WebSocket proxy") from self._startup_error

        if not self._thread.is_alive():
            raise RuntimeError("WebSocket proxy terminated during startup.")

    def stop(self) -> None:
        if self._loop and self._stop_event:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run_server_loop(self) -> None:
        try:
            asyncio.run(self._serve_forever())
        except Exception as exc:  # pragma: no cover - surfaced through start()
            logger.exception("WebSocket proxy crashed: %s", exc)
            self._startup_error = exc
            self._started.set()

    async def _serve_forever(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()

        async with serve(
            self._handle_websocket,
            self.listen_host,
            self.listen_port,
            compression=None,
            max_size=None,
            max_queue=None,
            ping_interval=20,
            ping_timeout=20,
            open_timeout=self.connect_timeout,
        ):
            logger.info(
                "WebSocket proxy listening on ws://%s:%s/websockify",
                self.listen_host,
                self.listen_port,
            )
            self._started.set()
            await self._stop_event.wait()

    def _extract_target(self, websocket: ServerConnection) -> tuple[str, int]:
        if websocket.request is None:
            raise ValueError("Missing WebSocket request metadata.")

        parsed = urllib.parse.urlparse(websocket.request.path)
        if parsed.path != "/websockify":
            raise ValueError(f"Unsupported path: {parsed.path}")

        params = urllib.parse.parse_qs(parsed.query)
        host = (params.get("host", [""])[0] or "").strip()
        port_text = (params.get("port", ["5900"])[0] or "").strip()

        if not host:
            raise ValueError("Missing host query parameter.")
        if len(host) > 255 or not HOST_RE.fullmatch(host):
            raise ValueError("Host contains unsupported characters.")

        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError("Port must be an integer.") from exc

        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        return host, port

    async def _handle_websocket(self, websocket: ServerConnection) -> None:
        try:
            host, port = self._extract_target(websocket)
        except ValueError as exc:
            logger.warning("Rejecting invalid proxy request: %s", exc)
            await websocket.close(code=1008, reason=str(exc))
            return

        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.connect_timeout,
            )
            logger.info("Proxy connected %s -> %s:%s", websocket.remote_address, host, port)

            to_tcp = asyncio.create_task(self._pipe_websocket_to_tcp(websocket, writer))
            to_ws = asyncio.create_task(self._pipe_tcp_to_websocket(reader, websocket))

            done, pending = await asyncio.wait(
                {to_tcp, to_ws},
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (ConnectionClosed, OSError)):
                    raise exc

        except (ConnectionClosed, OSError, asyncio.TimeoutError) as exc:
            logger.info("Proxy connection ended for %s:%s: %s", host, port, exc)
        except Exception as exc:
            logger.exception("Unexpected proxy failure for %s:%s: %s", host, port, exc)
            await websocket.close(code=1011, reason="Proxy error")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

            await websocket.close()

    async def _pipe_websocket_to_tcp(
        self,
        websocket: ServerConnection,
        writer: asyncio.StreamWriter,
    ) -> None:
        while True:
            message = await websocket.recv(decode=False)
            if isinstance(message, str):
                payload = message.encode("utf-8")
            else:
                payload = bytes(message)

            writer.write(payload)
            await writer.drain()

    async def _pipe_tcp_to_websocket(
        self,
        reader: asyncio.StreamReader,
        websocket: ServerConnection,
    ) -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                return
            await websocket.send(data)
