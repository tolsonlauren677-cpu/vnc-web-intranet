#!/usr/bin/env python3
"""
VNC web client entrypoint.

This application serves a small management UI over HTTP and starts a
dedicated WebSocket-to-TCP proxy for noVNC on a separate port.
"""

from __future__ import annotations

import atexit
import base64
import logging
import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from websocket_proxy import VNCProxyServer, test_vnc_connection


BASE_DIR = Path(__file__).resolve().parent
PASSWORDS_FILE = BASE_DIR / "saved_passwords.json"
DEFAULT_VNC_PORT=5900
HTTP_PORT = int(os.environ.get("PORT", "5888"))
HTTP_THREADS = int(os.environ.get("HTTP_THREADS", "16"))
PROXY_HOST = os.environ.get("WS_PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.environ.get("WS_PROXY_PORT", "6080"))
PROXY_PATH = "/websockify"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("vnc_web_client")


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "vnc-web-client")

proxy_server = VNCProxyServer(listen_host=PROXY_HOST, listen_port=PROXY_PORT)
LEGACY_CLIPBOARD_ENCODINGS = ("utf-8", "gb18030", "gbk", "big5")
MAX_CLIPBOARD_TEXT_LENGTH = 200_000
MAX_CLIPBOARD_BYTES_LENGTH = 400_000


@app.after_request
def apply_permissions_policy(response):
    # Ensure clipboard APIs are explicitly allowed for this origin.
    response.headers.setdefault(
        "Permissions-Policy",
        "clipboard-read=(self), clipboard-write=(self)",
    )
    return response


def coerce_port(value: Any, default: int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default

    if 1 <= port <= 65535:
        return port
    return default


def truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def score_decoded_text(text: str) -> float:
    score = 0.0
    for char in text:
        codepoint = ord(char)
        if char == "\ufffd":
            score -= 6.0
        elif char in "\r\n\t":
            score += 0.05
        elif codepoint < 32:
            score -= 2.5
        elif 0x4E00 <= codepoint <= 0x9FFF:
            score += 2.2
        elif char.isalnum():
            score += 0.2
        elif char.isprintable():
            score += 0.05
        else:
            score -= 0.2

    if any(marker in text for marker in ("Ã", "Â", "Ð", "Ñ", "�")):
        score -= 2.0

    return score


def detect_legacy_clipboard_encoding(payload: bytes, preferred: str | None = None) -> tuple[str, str]:
    encodings = []
    if preferred in LEGACY_CLIPBOARD_ENCODINGS:
        encodings.append(preferred)
    encodings.extend(encoding for encoding in LEGACY_CLIPBOARD_ENCODINGS if encoding not in encodings)

    best_encoding = "utf-8"
    best_text = payload.decode("utf-8", errors="replace")
    best_score = score_decoded_text(best_text)

    for encoding in encodings:
        try:
            text = payload.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue

        score = score_decoded_text(text)
        if score > best_score:
            best_encoding = encoding
            best_text = text
            best_score = score

    return best_text, best_encoding


@app.get("/")
def index():
    requested_host = request.args.get("ip") or request.args.get("host")
    host = requested_host.strip() if requested_host else ""
    port = coerce_port(request.args.get("port"), 5900)
    auto_connect = truthy(request.args.get("autoconnect") or request.args.get("connect"))
    if requested_host:
        auto_connect = True

    return render_template(
        "index.html",
        default_ip=host,
        default_port=port,
        proxy_port=PROXY_PORT,
        proxy_path=PROXY_PATH,
        auto_connect=auto_connect,
    )





@app.post("/api/test_connection")
def test_connection():
    payload = request.get_json(silent=True) or {}
    host = str(payload.get("host", "")).strip()
    port = coerce_port(payload.get("port"), DEFAULT_VNC_PORT)
    password = str(payload.get("password", ""))

    if not host:
        return jsonify({"success": False, "message": "IP 或主机名不能为空。"}), 400

    result = test_vnc_connection(host=host, port=port, password=password or None)
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.post("/api/clipboard/legacy_encode")
def encode_legacy_clipboard():
    payload = request.get_json(silent=True) or {}
    text = str(payload.get("text", ""))
    preferred = str(payload.get("encoding", "")).strip().lower() or None

    if len(text) > MAX_CLIPBOARD_TEXT_LENGTH:
        return jsonify({"success": False, "message": "文本长度超过上限。"}), 400

    encodings = []
    if preferred in LEGACY_CLIPBOARD_ENCODINGS:
        encodings.append(preferred)
    # Chinese Windows VNC servers most commonly expect GB18030/GBK for legacy clipboard.
    for encoding in ("gb18030", "gbk", "utf-8", "big5"):
        if encoding not in encodings:
            encodings.append(encoding)

    for encoding in encodings:
        try:
            encoded = text.encode(encoding, errors="strict")
        except UnicodeEncodeError:
            continue

        return jsonify(
            {
                "success": True,
                "encoding": encoding,
                "lossy": False,
                "bytes_base64": base64.b64encode(encoded).decode("ascii"),
            }
        )

    fallback_encoding = encodings[0]
    encoded = text.encode(fallback_encoding, errors="replace")
    return jsonify(
        {
            "success": True,
            "encoding": fallback_encoding,
            "lossy": True,
            "bytes_base64": base64.b64encode(encoded).decode("ascii"),
        }
    )


@app.post("/api/clipboard/legacy_decode")
def decode_legacy_clipboard():
    payload = request.get_json(silent=True) or {}
    bytes_base64 = str(payload.get("bytes_base64", "")).strip()
    preferred = str(payload.get("encoding", "")).strip().lower() or None

    if not bytes_base64:
        return jsonify({"success": False, "message": "缺少 bytes_base64。"}), 400

    try:
        raw = base64.b64decode(bytes_base64, validate=True)
    except Exception:
        return jsonify({"success": False, "message": "bytes_base64 格式无效。"}), 400

    if len(raw) > MAX_CLIPBOARD_BYTES_LENGTH:
        return jsonify({"success": False, "message": "字节长度超过上限。"}), 400

    text, encoding = detect_legacy_clipboard_encoding(raw, preferred=preferred)
    return jsonify({"success": True, "text": text, "encoding": encoding})


def start_proxy() -> None:
    proxy_server.start()


def stop_proxy() -> None:
    proxy_server.stop()


atexit.register(stop_proxy)


if __name__ == "__main__":
    try:
        from waitress import serve as waitress_serve
    except ImportError as exc:
        raise RuntimeError(
            "生产启动需要 waitress，请先执行: pip install -r vnc-web-client/requirements.txt"
        ) from exc

    start_proxy()
    logger.info("HTTP UI listening on http://0.0.0.0:%s", HTTP_PORT)
    logger.info("WebSocket proxy listening on ws://0.0.0.0:%s%s", PROXY_PORT, PROXY_PATH)
    logger.info(
        "Direct connect example: http://127.0.0.1:%s/?ip=192.168.1.3&port=5900",
        HTTP_PORT,
    )
    # Waitress is a production WSGI server and keeps the HTTP UI independent
    # from the long-lived WebSocket proxy running on PROXY_PORT.
    waitress_serve(
        app,
        host="0.0.0.0",
        port=HTTP_PORT,
        threads=max(4, HTTP_THREADS),
        channel_timeout=30,
        asyncore_use_poll=True,
    )

