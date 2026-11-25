#!/usr/bin/env python3
"""查看 geosite / geoip .dat 里的标签与条目，用于核对生成结果或官方库的分类。

用法：python tools/inspect_geodata.py <file.dat> [tag ...]
不给标签时只列出标签与条目数；给标签时打印该标签的全部规则。
"""
from __future__ import annotations

import ipaddress
import sys

KINDS = {0: "keyword", 1: "regexp", 2: "domain", 3: "full"}


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    shift = value = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def fields(data: bytes):
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 2:
            length, pos = read_varint(data, pos)
            value, pos = data[pos:pos + length], pos + length
        elif wire == 5:
            value, pos = data[pos:pos + 4], pos + 4
        elif wire == 1:
            value, pos = data[pos:pos + 8], pos + 8
        else:
            raise ValueError(f"unsupported wire type {wire}")
        yield number, value


def describe(entry: bytes) -> tuple[str, list[str]]:
    code, items = "", []
    for number, value in fields(entry):
        if number == 1:
            code = value.decode("utf-8", "replace")
        elif number == 2:
            parts = dict(fields(value))
            if isinstance(parts.get(1, 0), int) and 2 in parts and isinstance(parts[2], bytes) and len(parts) <= 3 and 1 not in parts or isinstance(parts.get(1), int):
                # Domain{type, value}
                kind = KINDS.get(parts.get(1, 0), str(parts.get(1)))
                items.append(f"{kind}:{parts.get(2, b'').decode('utf-8', 'replace')}")
            else:
                # CIDR{ip, prefix}
                ip = ipaddress.ip_address(parts[1])
                items.append(f"{ip}/{parts.get(2, 0)}")
    return code, items


def main() -> int:
    data = open(sys.argv[1], "rb").read()
    wanted = {tag.upper() for tag in sys.argv[2:]}
    for number, entry in fields(data):
        if number != 1:
            continue
        code, items = describe(entry)
        if not wanted:
            print(f"{code}\t{len(items)}")
        elif code.upper() in wanted:
            print(f"[{code}] {len(items)}")
            for item in items:
                print("  " + item)
    return 0


if __name__ == "__main__":
    sys.exit(main())
