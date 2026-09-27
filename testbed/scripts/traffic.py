#!/usr/bin/env python3
"""Controlled traffic for the IPsec testbed (runs inside the containers, stdlib only).

  traffic.py serve                                   # responder: start all servers
  traffic.py client KIND --src IP --dst IP [--seconds N] [--seed N]

KIND is one of: ICMP, Web, File-Transfer, VoIP, Video, Chat, Email.
Patterns are shaped so packet size, rate and direction differ per class; a
fixed seed makes every run reproducible.
"""
import argparse
import http.client
import http.server
import ipaddress
import os
import random
import socket
import socketserver
import subprocess
import threading
import time

HTTP_PORT, EMAIL_PORT, CHAT_PORT, VOIP_PORT, VIDEO_PORT = 8080, 2525, 5222, 5004, 5006
WEB_ROOT = os.environ.get("TRAFFIC_WEB_ROOT", "/srv/www")


# --- servers (responder) ----------------------------------------------------

class DualStackTCP(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class LineHandler(socketserver.StreamRequestHandler):
    """SMTP-like (email) and chat-like line protocol: every line gets a short acknowledgement."""

    def handle(self):
        self.wfile.write(b"220 testbed ready\r\n")
        in_data = False
        for line in self.rfile:
            if in_data:
                if line.strip() == b".":
                    in_data = False
                    self.wfile.write(b"250 queued\r\n")
                continue
            command = line.strip().upper()
            if command == b"DATA":
                in_data = True
                self.wfile.write(b"354 go ahead\r\n")
            elif command == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class QuietHTTP(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def log_message(self, *args):
        pass


def udp_server(port: int, echo: bool) -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    while True:
        data, peer = sock.recvfrom(65535)
        if echo:
            sock.sendto(data, peer)


def serve() -> None:
    os.makedirs(WEB_ROOT, exist_ok=True)
    rng = random.Random(7)
    for index in range(5):
        with open(f"{WEB_ROOT}/page{index}.html", "wb") as handle:
            handle.write(rng.randbytes(rng.randint(4_000, 60_000)))
    with open(f"{WEB_ROOT}/dataset.bin", "wb") as handle:
        handle.write(rng.randbytes(4 * 1024 * 1024))
    for server in (DualStackTCP(("::", HTTP_PORT), QuietHTTP), DualStackTCP(("::", EMAIL_PORT), LineHandler), DualStackTCP(("::", CHAT_PORT), LineHandler)):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=udp_server, args=(VOIP_PORT, True), daemon=True).start()
    threading.Thread(target=udp_server, args=(VIDEO_PORT, False), daemon=True).start()
    print("traffic servers listening", flush=True)
    threading.Event().wait()


# --- clients (initiator) ----------------------------------------------------

def _family(address: str) -> int:
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET


def _http_host(address: str) -> str:
    return f"[{address}]" if ipaddress.ip_address(address).version == 6 else address


def _get(src: str, dst: str, path: str) -> int:
    connection = http.client.HTTPConnection(_http_host(dst), HTTP_PORT, timeout=30, source_address=(src, 0))
    connection.request("GET", path)
    size = len(connection.getresponse().read())
    connection.close()
    return size


def icmp(src: str, dst: str, seconds: int, rng: random.Random) -> None:
    count = max(5, int(seconds / 0.2))
    subprocess.run(["ping", "-q", "-c", str(count), "-i", "0.2", "-s", "56", "-I", src, dst], check=True)


def web(src: str, dst: str, seconds: int, rng: random.Random) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        _get(src, dst, f"/page{rng.randrange(5)}.html")
        time.sleep(rng.uniform(0.3, 1.5))  # user think time between page loads


def file_transfer(src: str, dst: str, seconds: int, rng: random.Random) -> None:
    _get(src, dst, "/dataset.bin")


def _udp_stream(src: str, dst: str, port: int, seconds: int, frame, interval: float, receive: bool) -> None:
    sock = socket.socket(_family(dst), socket.SOCK_DGRAM)
    sock.bind((src, 0))
    sock.setblocking(False)
    deadline = time.time() + seconds
    next_send = time.time()
    while time.time() < deadline:
        for payload in frame():
            sock.sendto(payload, (dst, port))
        if receive:
            try:
                while True:
                    sock.recv(65535)
            except BlockingIOError:
                pass
        next_send += interval
        time.sleep(max(0.0, next_send - time.time()))


def voip(src: str, dst: str, seconds: int, rng: random.Random) -> None:
    # G.711-like: 160-byte voice frame + 12-byte RTP header every 20 ms, echoed back (two-way call).
    _udp_stream(src, dst, VOIP_PORT, seconds, lambda: [rng.randbytes(172)], 0.02, receive=True)


def video(src: str, dst: str, seconds: int, rng: random.Random) -> None:
    # ~30 fps; each frame is a burst of near-MTU packets, with a larger keyframe every 30 frames.
    frame_number = [0]

    def frame():
        frame_number[0] += 1
        packets = rng.randint(14, 20) if frame_number[0] % 30 == 1 else rng.randint(3, 7)
        return [rng.randbytes(1200) for _ in range(packets)]

    _udp_stream(src, dst, VIDEO_PORT, seconds, frame, 1 / 30, receive=False)


def _line_session(src: str, dst: str, port: int):
    sock = socket.create_connection((dst, port), timeout=30, source_address=(src, 0))
    return sock, sock.makefile("rb")


def chat(src: str, dst: str, seconds: int, rng: random.Random) -> None:
    sock, reader = _line_session(src, dst, CHAT_PORT)
    reader.readline()
    deadline = time.time() + seconds
    while time.time() < deadline:
        message = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(rng.randint(10, 180)))
        sock.sendall(f"MSG {message}\r\n".encode())
        reader.readline()
        time.sleep(rng.uniform(0.4, 2.5))  # typing pauses
    sock.sendall(b"QUIT\r\n")
    sock.close()


def email(src: str, dst: str, seconds: int, rng: random.Random) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        sock, reader = _line_session(src, dst, EMAIL_PORT)
        reader.readline()
        body = "\r\n".join(rng.randbytes(57).hex() for _ in range(rng.randint(200, 800)))
        for command in ("EHLO moon.testbed", "MAIL FROM:<a@moon.testbed>", "RCPT TO:<b@sun.testbed>", "DATA"):
            sock.sendall(f"{command}\r\n".encode())
            reader.readline()
        sock.sendall(f"{body}\r\n.\r\n".encode())
        reader.readline()
        sock.sendall(b"QUIT\r\n")
        reader.readline()
        sock.close()
        time.sleep(rng.uniform(1.0, 3.0))


CLIENTS = {"ICMP": icmp, "Web": web, "File-Transfer": file_transfer, "VoIP": voip, "Video": video, "Chat": chat, "Email": email}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    client = sub.add_parser("client")
    client.add_argument("kind", choices=sorted(CLIENTS))
    client.add_argument("--src", required=True)
    client.add_argument("--dst", required=True)
    client.add_argument("--seconds", type=int, default=10)
    client.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    if args.command == "serve":
        serve()
    else:
        CLIENTS[args.kind](args.src, args.dst, args.seconds, random.Random(args.seed))


if __name__ == "__main__":
    main()
