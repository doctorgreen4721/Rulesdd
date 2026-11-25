#!/usr/bin/env python3
"""把 geosite/ 与 geoip/ 下的文本规则编译成 Xray / V2Ray 可用的 .dat 规则库。

不依赖第三方库，直接按 Xray routercommon 的 protobuf 结构编码：
  GeoSiteList{ repeated GeoSite entry = 1 }
  GeoSite{ string country_code = 1; repeated Domain domain = 2 }
  Domain{ Type type = 1; string value = 2 }   Type: Plain=0(keyword) Regex=1 Domain=2 Full=3
  GeoIPList{ repeated GeoIP entry = 1 }
  GeoIP{ string country_code = 1; repeated CIDR cidr = 2 }
  CIDR{ bytes ip = 1; uint32 prefix = 2 }

源文件格式（与 v2fly/domain-list-community 一致，文件名即标签）：
  geosite/<tag>：每行 `domain:` / `full:` / `keyword:` / `regexp:` 加值，裸域名视为 `domain:`；
                 `include:<tag>` 引入同目录另一标签；`#` 开头为注释。
  geoip/<tag>  ：每行一个 IPv4/IPv6 地址或 CIDR；`#` 开头为注释。

用法：python tools/build_geodata.py [--out dist]
输出 geosite-rulesdd.dat、geoip-rulesdd.dat，在 Xray 中以
  "ext:geosite-rulesdd.dat:<tag>"  /  "ext:geoip-rulesdd.dat:<tag>"  引用。
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOMAIN_TYPES = {"keyword": 0, "regexp": 1, "domain": 2, "full": 3}
TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9!-]*$")
DOMAIN_PATTERN = re.compile(r"^[a-z0-9_.-]+$")


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field_bytes(number: int, payload: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(payload)) + payload


def field_varint(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value) if value else b""


def read_lines(path: Path) -> list[str]:
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def load_site(directory: Path, tag: str, stack: tuple[str, ...] = ()) -> list[tuple[int, str]]:
    if tag in stack:
        raise ValueError(f"geosite include 循环：{' -> '.join(stack + (tag,))}")
    path = directory / tag
    if not path.is_file():
        raise ValueError(f"geosite 标签不存在：{tag}")
    rules: list[tuple[int, str]] = []
    for line in read_lines(path):
        kind, sep, value = line.partition(":")
        if not sep:
            kind, value = "domain", line
        kind, value = kind.strip().lower(), value.strip()
        if kind == "include":
            rules.extend(load_site(directory, value, stack + (tag,)))
            continue
        if kind not in DOMAIN_TYPES:
            raise ValueError(f"{path.name}: 不支持的规则类型 {kind!r}")
        if kind == "regexp":
            re.compile(value)
        else:
            value = value.lower()
            if not DOMAIN_PATTERN.match(value):
                raise ValueError(f"{path.name}: 非法域名 {value!r}")
        rules.append((DOMAIN_TYPES[kind], value))
    return list(dict.fromkeys(rules))


def build_geosite(directory: Path) -> tuple[bytes, dict[str, int]]:
    entries, summary = b"", {}
    for path in sorted(p for p in directory.iterdir() if p.is_file()):
        tag = path.name
        if not TAG_PATTERN.match(tag):
            raise ValueError(f"标签名只能用小写字母、数字和连字符：{tag}")
        domains = b"".join(
            field_bytes(2, field_varint(1, kind) + field_bytes(2, value.encode("utf-8")))
            for kind, value in load_site(directory, tag)
        )
        # Xray 按大写标签查找（与官方 geosite.dat 一致）。
        entries += field_bytes(1, field_bytes(1, tag.upper().encode("ascii")) + domains)
        summary[tag] = len(load_site(directory, tag))
    return entries, summary


def build_geoip(directory: Path) -> tuple[bytes, dict[str, int]]:
    entries, summary = b"", {}
    for path in sorted(p for p in directory.iterdir() if p.is_file()):
        tag = path.name
        if not TAG_PATTERN.match(tag):
            raise ValueError(f"标签名只能用小写字母、数字和连字符：{tag}")
        networks = sorted(
            {ipaddress.ip_network(line, strict=False) for line in read_lines(path)},
            key=lambda net: (net.version, net.network_address, net.prefixlen),
        )
        cidrs = b"".join(
            field_bytes(2, field_bytes(1, net.network_address.packed) + field_varint(2, net.prefixlen))
            for net in networks
        )
        entries += field_bytes(1, field_bytes(1, tag.upper().encode("ascii")) + cidrs)
        summary[tag] = len(networks)
    return entries, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="dist", help="输出目录（相对仓库根）")
    args = parser.parse_args()
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    site, site_summary = build_geosite(ROOT / "geosite")
    ip, ip_summary = build_geoip(ROOT / "geoip")
    (out / "geosite-rulesdd.dat").write_bytes(site)
    (out / "geoip-rulesdd.dat").write_bytes(ip)
    for name, summary in (("geosite-rulesdd.dat", site_summary), ("geoip-rulesdd.dat", ip_summary)):
        print(name, ", ".join(f"{tag}={count}" for tag, count in summary.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
