#!/usr/bin/env python3
"""Record labelled ESP traffic sessions with Linux network namespaces (no Docker).

Two namespaces, `moon` and `sun`, are joined by a veth pair (MTU 1500). The
kernel's XFRM stack protects traffic between them with manually keyed ESP SAs,
so every captured packet is real kernel-generated ESP. No IKE runs: the traffic
classifier only uses the ESP data plane, and the SA parameters come from each
profile below.

Run as root inside WSL/Ubuntu (or any Linux):

    sudo python3 testbed/scripts/netns_sessions.py                 # all profiles, 3 repeats
    sudo python3 testbed/scripts/netns_sessions.py --profiles ns-gcm256-tunnel-v4 --repeats 1

Writes data/raw/traffic_sessions/<profile>_<class>_<nn>.pcap + .json. Requires
iproute2, tcpdump, iputils-ping and python3.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "data" / "raw" / "traffic_sessions"
TRAFFIC = Path(__file__).resolve().parent / "traffic.py"
CLASSES = ("Web", "Video", "VoIP", "Email", "Chat", "ICMP", "File-Transfer")

OUTER = {4: ("172.30.0.10", "172.30.0.20", 24), 6: ("fd00:30::10", "fd00:30::20", 64)}
INNER = {4: (("10.1.0.1", "10.1.0.0/24"), ("10.2.0.1", "10.2.0.0/24"), 24), 6: (("fd00:1::1", "fd00:1::/64"), ("fd00:2::1", "fd00:2::/64"), 64)}

# name: (cipher, mode, ip version, NAT-T)
PROFILES = {
    "ns-gcm256-tunnel-v4": ("aes256gcm", "tunnel", 4, False),
    "ns-gcm128-tunnel-v4": ("aes128gcm", "tunnel", 4, False),
    "ns-cbc256-sha256-tunnel-v4": ("aes256cbc-sha256", "tunnel", 4, False),
    "ns-cbc128-sha1-tunnel-v4": ("aes128cbc-sha1", "tunnel", 4, False),
    "ns-gcm256-transport-v4": ("aes256gcm", "transport", 4, False),
    "ns-gcm256-tunnel-natt-v4": ("aes256gcm", "tunnel", 4, True),
    "ns-gcm256-tunnel-v6": ("aes256gcm", "tunnel", 6, False),
    "ns-cbc256-sha256-transport-v6": ("aes256cbc-sha256", "transport", 6, False),
    # Added for AI mode / ESP-cipher inference: more transport-mode variety, a weak 64-bit block cipher, and ESP-NULL.
    "ns-gcm128-transport-v4": ("aes128gcm", "transport", 4, False),
    "ns-cbc128-sha1-transport-v4": ("aes128cbc-sha1", "transport", 4, False),
    "ns-cbc256-sha256-transport-v4": ("aes256cbc-sha256", "transport", 4, False),
    "ns-gcm256-transport-v6": ("aes256gcm", "transport", 6, False),
    "ns-cbc128-sha256-tunnel-v6": ("aes128cbc-sha256", "tunnel", 6, False),
    "ns-3des-sha1-tunnel-v4": ("3des-sha1", "tunnel", 4, False),
    "ns-3des-sha1-transport-v4": ("3des-sha1", "transport", 4, False),
    "ns-null-sha256-tunnel-v4": ("null-sha256", "tunnel", 4, False),
    "ns-null-sha256-transport-v4": ("null-sha256", "transport", 4, False),
}
CAPTURE_FILTER = "udp port 4500 or ip proto 50 or ip6 proto 50"


def sh(*args: str, check: bool = True, ns: str | None = None) -> subprocess.CompletedProcess:
    command = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    result = subprocess.run(command, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed: {result.stderr.strip()}")
    return result


def algorithm_args(cipher: str) -> list[str]:
    key = lambda n: "0x" + secrets.token_hex(n)
    if cipher.endswith("gcm"):
        bits = int(cipher[3:6])
        return ["aead", "rfc4106(gcm(aes))", key(bits // 8 + 4), "128"]  # key + 4-byte salt, 16-byte ICV
    if cipher == "3des-sha1":
        return ["enc", "cbc(des3_ede)", key(24), "auth-trunc", "hmac(sha1)", key(20), "96"]
    if cipher == "null-sha256":
        return ["enc", "ecb(cipher_null)", "", "auth-trunc", "hmac(sha256)", key(32), "128"]
    bits = int(cipher[3:6])
    if cipher.endswith("sha256"):
        return ["enc", "cbc(aes)", key(bits // 8), "auth-trunc", "hmac(sha256)", key(32), "128"]
    return ["enc", "cbc(aes)", key(bits // 8), "auth-trunc", "hmac(sha1)", key(20), "96"]


def teardown() -> None:
    for ns in ("moon", "sun"):
        pids = subprocess.run(["ip", "netns", "pids", ns], capture_output=True, text=True).stdout.split()
        for pid in pids:
            try:
                os.kill(int(pid), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)


def setup(profile: str) -> tuple[str, str, list[subprocess.Popen]]:
    cipher, mode, version, natt = PROFILES[profile]
    teardown()
    for ns in ("moon", "sun"):
        sh("ip", "netns", "add", ns)
    sh("ip", "link", "add", "veth-moon", "type", "veth", "peer", "name", "veth-sun")
    helpers: list[subprocess.Popen] = []
    for ns, index in (("moon", 0), ("sun", 1)):
        sh("ip", "link", "set", f"veth-{ns}", "netns", ns)
        sh("ip", "link", "set", "lo", "up", ns=ns)
        sh("ip", "link", "set", f"veth-{ns}", "up", ns=ns)
        sh("ip", "link", "add", "inner", "type", "dummy", ns=ns)
        sh("ip", "link", "set", "inner", "up", ns=ns)
        for v in (4, 6):
            family = ["-6"] if v == 6 else []
            sh("ip", *family, "addr", "add", f"{OUTER[v][index]}/{OUTER[v][2]}", "dev", f"veth-{ns}", *(["nodad"] if v == 6 else []), ns=ns)
            sh("ip", *family, "addr", "add", f"{INNER[v][index][0]}/{INNER[v][2]}", "dev", "inner", *(["nodad"] if v == 6 else []), ns=ns)

    local, remote = OUTER[version][0], OUTER[version][1]
    spi_out, spi_in = secrets.randbits(31) | 0x1000, secrets.randbits(31) | 0x1000
    algorithms = {spi: algorithm_args(cipher) for spi in (spi_out, spi_in)}
    encap = ["encap", "espinudp", "4500", "4500", "0.0.0.0"] if natt else []
    family = ["-6"] if version == 6 else []
    for ns, (src, dst) in (("moon", (local, remote)), ("sun", (remote, local))):
        # Both peers hold both SAs; each SA is identified by its destination and SPI.
        for sa_src, sa_dst, spi in ((local, remote, spi_out), (remote, local, spi_in)):
            sh("ip", "xfrm", "state", "add", "src", sa_src, "dst", sa_dst, "proto", "esp", "spi", hex(spi), "reqid", "1",
               "mode", mode, "replay-window", "32", *algorithms[spi], *encap, ns=ns)
        if mode == "tunnel":
            me, peer = (INNER[version][0], INNER[version][1]) if ns == "moon" else (INNER[version][1], INNER[version][0])
            sh("ip", *family, "route", "add", peer[1], "dev", f"veth-{ns}", "src", me[0], ns=ns)
            selectors = [(me[1], peer[1], "out", src, dst), (peer[1], me[1], "in", dst, src)]
        else:
            host = "/32" if version == 4 else "/128"
            selectors = [(src + host, dst + host, "out", src, dst), (dst + host, src + host, "in", dst, src)]
        for sel_src, sel_dst, direction, t_src, t_dst in selectors:
            sh("ip", "xfrm", "policy", "add", "src", sel_src, "dst", sel_dst, "dir", direction,
               "tmpl", "src", t_src, "dst", t_dst, "proto", "esp", "reqid", "1", "mode", mode, ns=ns)
        if natt:
            # Receiving UDP-encapsulated ESP needs a socket with UDP_ENCAP_ESPINUDP on port 4500.
            helpers.append(subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, "-c",
                "import socket,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('0.0.0.0',4500))\n"
                "s.setsockopt(socket.IPPROTO_UDP,100,2)\ntime.sleep(10**9)"]))

    if mode == "tunnel":
        return INNER[version][0][0], INNER[version][1][0], helpers
    return local, remote, helpers


def start_servers() -> subprocess.Popen:
    env = {**os.environ, "TRAFFIC_WEB_ROOT": "/tmp/ipsec-analyzer-www"}
    server = subprocess.Popen(["ip", "netns", "exec", "sun", sys.executable, str(TRAFFIC), "serve"], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    probe = "import socket\nfor p in (8080, 2525, 5222):\n    socket.create_connection(('127.0.0.1', p), 2).close()"
    for _ in range(60):
        if sh(sys.executable, "-c", probe, check=False, ns="sun").returncode == 0:
            return server
        time.sleep(0.5)
    server.kill()
    raise RuntimeError("traffic servers did not start")


def record(profile: str, repeats: int, seed_base: int) -> int:
    cipher, mode, version, natt = PROFILES[profile]
    src, dst, helpers = setup(profile)
    server = start_servers()
    check = sh("ping", "-c", "2", "-W", "2", "-I", src, dst, check=False, ns="moon")
    if check.returncode != 0:
        raise RuntimeError(f"no connectivity through the ESP SA: {check.stdout.strip()[-200:]}")
    rng = random.Random(seed_base)
    written = 0
    try:
        for repeat in range(repeats):
            for kind in CLASSES:
                seed = seed_base * 1000 + repeat * 10 + CLASSES.index(kind)
                seconds = rng.randint(8, 20)
                session_id = f"{profile}_{kind.lower()}_{repeat:02d}"
                pcap = OUTPUT / f"{session_id}.pcap"
                pcap.unlink(missing_ok=True)
                dump = subprocess.Popen(["ip", "netns", "exec", "moon", "tcpdump", "-i", "veth-moon", "-U", "-n", "-w", str(pcap), CAPTURE_FILTER],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1)
                client = sh(sys.executable, str(TRAFFIC), "client", kind, "--src", src, "--dst", dst,
                            "--seconds", str(seconds), "--seed", str(seed), check=False, ns="moon")
                time.sleep(0.5)
                dump.send_signal(signal.SIGINT)
                dump.wait(timeout=15)
                if client.returncode != 0:
                    print(f"    {session_id}: FAILED {client.stderr.strip()[-200:]}", file=sys.stderr, flush=True)
                    pcap.unlink(missing_ok=True)
                    continue
                label = {
                    "session_id": session_id, "pcap_filename": pcap.name, "traffic": kind, "group": profile, "scenario": profile,
                    "ike_version": None, "mode": mode.capitalize(), "ip_version": f"IPv{version}", "nat_traversal": natt,
                    "esp_proposal": cipher, "seconds": seconds, "seed": seed,
                    "dataset_origin": "linux_xfrm_netns_capture",
                    "note": "Kernel ESP with manually keyed SAs between network namespaces; no IKE in the capture.",
                }
                (OUTPUT / f"{session_id}.json").write_text(json.dumps(label, indent=2) + "\n", encoding="utf-8")
                written += 1
                print(f"    {session_id}: {pcap.stat().st_size:,} bytes", flush=True)
    finally:
        server.kill()
        for helper in helpers:
            helper.kill()
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profiles", nargs="+", choices=sorted(PROFILES), default=list(PROFILES))
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Run as root (sudo): network namespaces and XFRM states need CAP_NET_ADMIN.", file=sys.stderr)
        return 1
    missing = [tool for tool in ("ip", "tcpdump", "ping") if not shutil.which(tool)]
    if missing:
        print(f"Missing tools: {', '.join(missing)}. Install with: sudo apt install -y iproute2 tcpdump iputils-ping", file=sys.stderr)
        return 1
    OUTPUT.mkdir(parents=True, exist_ok=True)
    total = 0
    try:
        for index, profile in enumerate(args.profiles, start=100):
            print(f"\n=== {profile}", flush=True)
            try:
                total += record(profile, args.repeats, index)
            except Exception as exc:  # keep going with the next profile
                print(f"    FAILED: {exc}", file=sys.stderr, flush=True)
    finally:
        teardown()
    print(f"\n{total} labelled sessions in {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
