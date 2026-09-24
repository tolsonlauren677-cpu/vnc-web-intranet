"""RA2 record integrity and ordinary VNC proxy regression tests.

Run with: python -m unittest -v test_ra2
No external VNC server or saved credentials are required.
"""

import asyncio
import hashlib
import json
import socket
import struct
import threading
import unittest

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from ra2 import EAXRecords, RA2Stream, authenticate, read_exact
from websocket_proxy import VNCProxyServer


KEY = bytes(range(16))


class FragmentedSocket:
    def __init__(self, data=b"", fragment_size=1):
        self.data = bytearray(data)
        self.sent = bytearray()
        self.fragment_size = fragment_size

    def recv(self, size):
        size = min(size, self.fragment_size)
        result = bytes(self.data[:size])
        del self.data[:size]
        return result

    def sendall(self, data):
        self.sent.extend(data)


class RecordTests(unittest.TestCase):
    def test_nonce_and_length_match_independent_eax(self):
        records = EAXRecords(KEY)
        for nonce in range(257):
            payload = b"framebuffer update"
            header = struct.pack("!H", len(payload))
            cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce.to_bytes(16, "little"))
            cipher.update(header)
            encrypted, tag = cipher.encrypt_and_digest(payload)
            self.assertEqual(records.encrypt(payload), header + encrypted + tag)

    def test_fragmented_records_form_continuous_stream(self):
        sender = EAXRecords(KEY)
        wire = b"".join(sender.encrypt(part) for part in (b"", b"hash", b"subtype", b"desktop"))
        stream = RA2Stream(FragmentedSocket(wire), EAXRecords(KEY), EAXRecords(KEY))
        self.assertEqual(read_exact(stream, 11), b"hashsubtype")
        self.assertEqual(read_exact(stream, 7), b"desktop")
        with self.assertRaises(ConnectionError):
            stream.recv(1)

    def test_corrupt_ciphertext_tag_and_length_rejected(self):
        record = EAXRecords(KEY).encrypt(b"protected desktop data")
        for position in (1, 2, len(record) - 1):
            with self.subTest(position=position):
                damaged = bytearray(record)
                damaged[position] ^= 1
                with self.assertRaises(ValueError):
                    EAXRecords(KEY).decrypt(bytes(damaged[:2]), bytes(damaged[2:]))

    def test_replayed_record_rejected(self):
        record = EAXRecords(KEY).encrypt(b"desktop")
        receiver = EAXRecords(KEY)
        self.assertEqual(receiver.decrypt(record[:2], record[2:]), b"desktop")
        with self.assertRaises(ValueError):
            receiver.decrypt(record[:2], record[2:])

    def test_large_writes_split_into_valid_records(self):
        payload = bytes(range(256)) * 600
        target = FragmentedSocket(fragment_size=101)
        RA2Stream(target, EAXRecords(KEY), EAXRecords(KEY)).sendall(payload)
        receiver = RA2Stream(FragmentedSocket(target.sent, 101), EAXRecords(KEY), EAXRecords(KEY))
        self.assertEqual(read_exact(receiver, len(payload)), payload)

    def test_truncated_record_rejected(self):
        record = EAXRecords(KEY).encrypt(b"desktop")
        stream = RA2Stream(FragmentedSocket(record[:-1]), EAXRecords(KEY), EAXRecords(KEY))
        with self.assertRaises(ConnectionError):
            stream.recv(1)


class WebSocketReader:
    def __init__(self, websocket):
        self.websocket = websocket
        self.pending = bytearray()

    async def read(self, size):
        while len(self.pending) < size:
            self.pending.extend(await self.websocket.recv())
        result = bytes(self.pending[:size])
        del self.pending[:size]
        return result


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_key = RSA.generate(1024)

    def exchange(self, subtype=2, password="test-password", username="", bad_hash=False):
        client, server = socket.socketpair()
        client.settimeout(5)
        server.settimeout(5)
        received = []
        failures = []

        def emulate_server():
            try:
                key = self.server_key
                public = struct.pack("!I", 1024) + key.n.to_bytes(128, "big") + key.e.to_bytes(128, "big")
                server.sendall(public)
                header = read_exact(server, 4)
                size = struct.unpack("!I", header)[0] // 8
                key_data = read_exact(server, size * 2)
                client_public = header + key_data
                peer_key = RSA.construct((int.from_bytes(key_data[:size], "big"),
                                          int.from_bytes(key_data[size:], "big")))
                encrypted_size = struct.unpack("!H", read_exact(server, 2))[0]
                client_random = PKCS1_v1_5.new(key).decrypt(read_exact(server, encrypted_size), b"error")
                server_random = bytes(range(16))
                encrypted = PKCS1_v1_5.new(peer_key).encrypt(server_random)
                server.sendall(struct.pack("!H", len(encrypted)))
                server.sendall(encrypted)
                stream = RA2Stream(server,
                    EAXRecords(hashlib.sha1(client_random + server_random).digest()[:16]),
                    EAXRecords(hashlib.sha1(server_random + client_random).digest()[:16]))
                self.assertEqual(read_exact(stream, 20), hashlib.sha1(client_public + public).digest())
                digest = bytes(20) if bad_hash else hashlib.sha1(public + client_public).digest()
                # Hash and subtype deliberately share a record, unlike a
                # handshake implementation that assumes one record per field.
                stream.sendall(digest + bytes([subtype]))
                if bad_hash or subtype not in (1, 2) or (subtype == 1 and not username):
                    return
                user_size = read_exact(stream, 1)[0]
                user = read_exact(stream, user_size)
                secret_size = read_exact(stream, 1)[0]
                secret = read_exact(stream, secret_size)
                received.append((user, secret))
                stream.sendall(bytes(4) + b"desktop")
            except Exception as exc:
                failures.append(exc)
            finally:
                server.close()

        thread = threading.Thread(target=emulate_server, daemon=True)
        thread.start()
        try:
            stream = authenticate(client, password, username)
            self.assertEqual(read_exact(stream, 4), bytes(4))
            self.assertEqual(read_exact(stream, 7), b"desktop")
            return received
        finally:
            client.close()
            thread.join(6)
            self.assertFalse(thread.is_alive(), "Synthetic RA2 server failed to terminate")
            if failures:
                raise failures[0]

    def test_password_auth_and_encrypted_session_continue(self):
        self.assertEqual(self.exchange(), [(b"", b"test-password")])

    def test_user_password_subtype(self):
        self.assertEqual(self.exchange(subtype=1, username="operator"),
                         [(b"operator", b"test-password")])

    def test_username_required_is_reported(self):
        with self.assertRaisesRegex(ValueError, "用户名"):
            self.exchange(subtype=1)

    def test_invalid_hash_and_subtype_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.exchange(bad_hash=True)
        with self.assertRaisesRegex(ValueError, "Unsupported RA2 credential subtype"):
            self.exchange(subtype=3)


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_ordinary_vnc_auth_stays_byte_for_byte(self):
        complete = asyncio.get_running_loop().create_future()
        banner = b"RFB 003.008\n"
        challenge = bytes(range(16))
        response = bytes(range(16, 32))
        desktop = struct.pack("!HH", 800, 600) + bytes(16) + struct.pack("!I", 4) + b"test"

        async def server(reader, writer):
            try:
                for fragment in (banner[:3], banner[3:]):
                    writer.write(fragment)
                    await writer.drain()
                self.assertEqual(await reader.readexactly(12), banner)
                writer.write(b"\x02\x02\x10")
                await writer.drain()
                self.assertEqual(await reader.readexactly(1), b"\x02")
                writer.write(challenge)
                await writer.drain()
                self.assertEqual(await reader.readexactly(16), response)
                writer.write(bytes(4))
                await writer.drain()
                self.assertEqual(await reader.readexactly(1), b"\x01")
                writer.write(desktop)
                await writer.drain()
                self.assertEqual(await reader.readexactly(4), b"ping")
                writer.write(b"pong")
                await writer.drain()
                complete.set_result(True)
                await reader.read()
            except Exception as exc:
                if not complete.done():
                    complete.set_exception(exc)
            finally:
                writer.close()
                await writer.wait_closed()

        tcp = await asyncio.start_server(server, "127.0.0.1", 0)
        proxy = VNCProxyServer()
        async with tcp, serve(proxy._handle_websocket, "127.0.0.1", 0) as websocket_server:
            port = websocket_server.sockets[0].getsockname()[1]
            target = tcp.sockets[0].getsockname()[1]
            async with connect(f"ws://127.0.0.1:{port}/websockify?host=127.0.0.1&port={target}&ra2=1") as ws:
                await ws.send(json.dumps({"type": "credentials", "password": "test-only"}))
                reader = WebSocketReader(ws)
                self.assertEqual(await reader.read(12), banner)
                await ws.send(banner)
                self.assertEqual(await reader.read(3), b"\x02\x02\x10")
                await ws.send(b"\x02")
                self.assertEqual(await reader.read(16), challenge)
                await ws.send(response)
                self.assertEqual(await reader.read(4), bytes(4))
                await ws.send(b"\x01")
                self.assertEqual(await reader.read(len(desktop)), desktop)
                await ws.send(b"ping")
                self.assertEqual(await reader.read(4), b"pong")
                await asyncio.wait_for(complete, 3)

    async def test_malformed_credentials_close_connection(self):
        proxy = VNCProxyServer(connect_timeout=0.5)
        async with serve(proxy._handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            for payload in ("not-json", "[]", '{"type":"unexpected"}'):
                with self.subTest(payload=payload):
                    async with connect(f"ws://127.0.0.1:{port}/websockify?host=127.0.0.1&port=1&ra2=1") as ws:
                        await ws.send(payload)
                        with self.assertRaises(ConnectionClosed):
                            await asyncio.wait_for(ws.recv(), 2)


if __name__ == "__main__":
    unittest.main()
