"""RealVNC RA2 (RSA/AES-128-EAX) authenticated record stream.

RA2 encrypts every byte after its key exchange, including SecurityResult and
the framebuffer stream. RA2ne differs by disabling encryption after auth.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA


def read_exact(sock, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("RA2 connection closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


class EAXRecords:
    """Length-authenticated records with a little-endian 128-bit nonce."""

    def __init__(self, key: bytes):
        self.key = key
        self.counter = 0

    def _cipher(self, header: bytes):
        cipher = AES.new(self.key, AES.MODE_EAX,
                         nonce=self.counter.to_bytes(16, "little"), mac_len=16)
        cipher.update(header)
        self.counter += 1
        return cipher

    def encrypt(self, data: bytes) -> bytes:
        header = struct.pack("!H", len(data))
        ciphertext, tag = self._cipher(header).encrypt_and_digest(data)
        return header + ciphertext + tag

    def decrypt(self, header: bytes, payload: bytes) -> bytes:
        return self._cipher(header).decrypt_and_verify(payload[:-16], payload[-16:])


class RA2Stream:
    def __init__(self, sock, outgoing: EAXRecords, incoming: EAXRecords):
        self.sock = sock
        self.outgoing = outgoing
        self.incoming = incoming
        self.pending = bytearray()

    def sendall(self, data: bytes) -> None:
        for start in range(0, len(data), 65535):
            self.sock.sendall(self.outgoing.encrypt(data[start:start + 65535]))

    def recv(self, size: int) -> bytes:
        while not self.pending:
            header = read_exact(self.sock, 2)
            length = struct.unpack("!H", header)[0]
            self.pending.extend(self.incoming.decrypt(
                header, read_exact(self.sock, length + 16)))
        data = bytes(self.pending[:size])
        del self.pending[:size]
        return data


def authenticate(sock, password: str, username: str = "") -> RA2Stream:
    """Complete RA2 key exchange and send credentials after type 5 selection.

    Returns the encrypted stream positioned at the RFB SecurityResult.
    Server key continuity/trust follows the existing VNC proxy policy.
    """
    key_header = read_exact(sock, 4)
    bits = struct.unpack("!I", key_header)[0]
    if not 1024 <= bits <= 8192:
        raise ValueError("Invalid RA2 RSA key size")
    key_bytes = (bits + 7) // 8
    server_key_data = read_exact(sock, key_bytes * 2)
    server_public = key_header + server_key_data
    server_key = RSA.construct((
        int.from_bytes(server_key_data[:key_bytes], "big"),
        int.from_bytes(server_key_data[key_bytes:], "big")))

    client_key = RSA.generate(2048)
    client_bytes = 256
    client_public = (struct.pack("!I", 2048)
                     + client_key.n.to_bytes(client_bytes, "big")
                     + client_key.e.to_bytes(client_bytes, "big"))
    sock.sendall(client_public)
    client_random = secrets.token_bytes(16)
    encrypted = PKCS1_v1_5.new(server_key).encrypt(client_random)
    sock.sendall(struct.pack("!H", len(encrypted)) + encrypted)
    encrypted_size = struct.unpack("!H", read_exact(sock, 2))[0]
    if encrypted_size != client_bytes:
        raise ValueError("Invalid RA2 encrypted random length")
    sentinel = secrets.token_bytes(16)
    server_random = PKCS1_v1_5.new(client_key).decrypt(
        read_exact(sock, encrypted_size), sentinel, expected_pt_len=16)
    if hmac.compare_digest(server_random, sentinel):
        raise ValueError("RA2 RSA key exchange failed")

    stream = RA2Stream(
        sock,
        EAXRecords(hashlib.sha1(server_random + client_random).digest()[:16]),
        EAXRecords(hashlib.sha1(client_random + server_random).digest()[:16]))
    stream.sendall(hashlib.sha1(client_public + server_public).digest())
    expected_hash = hashlib.sha1(server_public + client_public).digest()
    if not hmac.compare_digest(read_exact(stream, 20), expected_hash):
        raise ValueError("RA2 server key exchange hash mismatch")
    subtype = read_exact(stream, 1)[0]
    if subtype not in (1, 2):
        raise ValueError(f"Unsupported RA2 credential subtype {subtype}")
    if subtype == 1 and not username:
        raise ValueError("RA2 服务器要求用户名和密码，请填写用户名。")
    user = username.encode("utf-8") if subtype == 1 else b""
    secret = password.encode("utf-8")
    if len(user) > 255 or len(secret) > 255:
        raise ValueError("RA2 username/password exceeds 255 UTF-8 bytes")
    stream.sendall(bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    return stream
