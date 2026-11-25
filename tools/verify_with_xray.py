#!/usr/bin/env python3
"""用真实 Xray 核心验证生成的 .dat：标签可加载、错误标签被拒绝、路由命中符合预期。

用法：python tools/verify_with_xray.py <xray 可执行文件>
只在 127.0.0.1 上启动临时核心与回显服务：命中规则的连接进入 blackhole，
未命中的连接由 freedom 重定向到本机回显服务，不访问外网。
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# 必须命中的核心目标，以及与规则无关、必须不命中的目标。
MUST_HIT = ["claude.ai", "api.anthropic.com"]
MUST_MISS = ["example.org", "www.example.com", "1.1.1.1", "2001:4860:4860::8888"]


def rule_lines(path: Path) -> list[str]:
    return [line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.split("#", 1)[0].strip()]


def build_cases() -> list[tuple[str, bool]]:
    """由源文件推出用例：每条规则至少一个应命中的目标，再加固定的必中 / 必不中目标。"""
    cases: list[tuple[str, bool]] = [(target, True) for target in MUST_HIT]
    for path in sorted((ROOT / "geosite").iterdir()):
        for line in rule_lines(path):
            kind, sep, value = line.partition(":")
            if not sep:
                kind, value = "domain", line
            if kind == "domain":
                cases += [(value, True), (f"probe.{value}", True)]
            elif kind == "full":
                cases.append((value, True))
            elif kind == "keyword":
                cases.append((f"x-{value}-probe.net", True))
    for path in sorted((ROOT / "geoip").iterdir()):
        for line in rule_lines(path):
            network = ipaddress.ip_network(line, strict=False)
            first = network.network_address + (1 if network.num_addresses > 1 else 0)
            cases += [(str(first), True), (str(network.broadcast_address), True)]
    cases += [(target, False) for target in MUST_MISS]
    return list(dict.fromkeys(cases))

def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_config(path: Path, rules: list[dict], socks: int, echo: int) -> None:
    path.write_text(json.dumps({
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": socks, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [
            {"tag": "echo", "protocol": "freedom", "settings": {"redirect": f"127.0.0.1:{echo}"}},
            {"tag": "hit", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }), encoding="utf-8")


def run_test(xray: Path, workdir: Path, config: Path) -> tuple[int, str]:
    done = subprocess.run([str(xray), "run", "-test", "-c", str(config)], cwd=workdir,
                          env={**os.environ, "XRAY_LOCATION_ASSET": str(workdir)}, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", creationflags=FLAGS)
    return done.returncode, (done.stdout + done.stderr).strip()


def echo_server(port: int, stop: threading.Event) -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", port))
    server.listen()
    server.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = server.accept()
        except OSError:
            continue
        with conn:
            conn.settimeout(2)
            try:
                data = conn.recv(64)
                conn.sendall(b"ECHO:" + data)
            except OSError:
                pass
    server.close()


def through_socks(socks: int, target: str) -> bool:
    """经 SOCKS5 连接 target:443 并发一个探测串；收到回显返回 True（未命中规则）。"""
    with socket.create_connection(("127.0.0.1", socks), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(b"\x05\x01\x00")
        sock.recv(2)
        try:
            address = ipaddress.ip_address(target)
            header = (b"\x01" if address.version == 4 else b"\x04") + address.packed
        except ValueError:
            header = b"\x03" + bytes([len(target)]) + target.encode()
        sock.sendall(b"\x05\x01\x00" + header + (443).to_bytes(2, "big"))
        reply = sock.recv(32)
        if len(reply) < 2 or reply[1] != 0:
            return False
        try:
            sock.sendall(b"probe")
            return sock.recv(64).startswith(b"ECHO:")
        except OSError:
            return False


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    xray = Path(sys.argv[1]).resolve()
    failures = 0
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        for name in ("geosite-rulesdd.dat", "geoip-rulesdd.dat"):
            shutil.copy2(DIST / name, work / name)
        socks, echo = free_port(), free_port()
        domain_tags = sorted(path.name for path in (ROOT / "geosite").iterdir())
        rules = [
            {"domain": [f"ext:geosite-rulesdd.dat:{tag}" for tag in domain_tags], "outboundTag": "hit"},
            {"ip": [f"ext:geoip-rulesdd.dat:{path.name}" for path in sorted((ROOT / "geoip").iterdir())], "outboundTag": "hit"},
        ]
        config = work / "config.json"
        write_config(config, rules + [{"domain": ["ext:geosite-rulesdd.dat:not-a-tag"], "outboundTag": "hit"}],
                     socks, echo)
        code, output = run_test(xray, work, config)
        print(f"不存在的标签被拒绝：{'是' if code != 0 else '否'}")
        failures += code == 0
        write_config(config, rules, socks, echo)
        code, output = run_test(xray, work, config)
        print(f"全部标签加载：{'OK' if code == 0 else output.splitlines()[-1:]}")
        failures += code != 0
        stop = threading.Event()
        threading.Thread(target=echo_server, args=(echo, stop), daemon=True).start()
        process = subprocess.Popen([str(xray), "run", "-c", str(config)], cwd=work,
                                   env={**os.environ, "XRAY_LOCATION_ASSET": str(work)},
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=FLAGS)
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", socks), timeout=0.3).close()
                    break
                except OSError:
                    time.sleep(0.1)
            if process.poll() is not None:
                print("Xray 未能启动：", process.stdout.read().decode("utf-8", "replace")[-400:])
                return 1
            for target, expect_hit in build_cases():
                hit = not through_socks(socks, target)
                ok = hit == expect_hit
                failures += not ok
                print(f"{'OK ' if ok else 'BAD'} {target:<36} {'命中' if hit else '未命中'}")
        finally:
            process.terminate()
            process.wait(5)
            stop.set()
    print("结果：" + ("全部通过" if not failures else f"{failures} 项不符合预期"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
