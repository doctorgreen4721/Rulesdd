#!/usr/bin/env python3
"""从 Net.Coffee 页面同步 Claude 分流规则，重写本仓库的派生文件。

只读取页面“类型前缀文本”标签页（data-panel="prefix"）里的 <pre> 规则块，然后：
  - geosite/claude、geoip/claude：只替换 BEGIN/END 标记之间的自动生成区，其余手工内容保留；
  - anthropic_supple.lsr：页面规则原样 + 由 geosite/ip-check 生成的“检测网站”一节；
  - IP-ASN：查询 RIPEstat 当前宣告的前缀，未被现有 CIDR 覆盖的才补入 geoip/claude。

页面改版导致找不到规则块、规则过少或缺少核心域名时，以非零状态退出且不写任何文件。
用法：python tools/update_from_netcoffee.py [--html 本地文件]
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_URL = "https://ip.net.coffee/claude/site.html"
USER_AGENT = "Mozilla/5.0 (compatible; Rulesdd-updater; +https://github.com/doctorgreen4721/Rulesdd)"
BEGIN, END = "# BEGIN net.coffee（自动生成，勿手改）", "# END net.coffee"
RULE = re.compile(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|IP-CIDR6|IP-ASN),([^,\s]+)(?:,no-resolve)?$")
REQUIRED = {("DOMAIN-SUFFIX", "anthropic.com"), ("DOMAIN-SUFFIX", "claude.ai")}
MIN_RULES = 10


class UpdateError(RuntimeError):
    pass


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", "replace")


def extract_rules(page: str) -> list[str]:
    """返回规则块的行（含页面自带的 # 注释），并做结构校验。"""
    match = re.search(r'data-panel="prefix".*?<pre[^>]*>(.*?)</pre>', page, re.S)
    if not match:
        raise UpdateError("页面中找不到“类型前缀文本”规则块，可能已改版")
    text = html.unescape(re.sub(r"<[^>]+>", "", match.group(1)))
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    rules = [line for line in lines if not line.startswith("#")]
    bad = [line for line in rules if not RULE.match(line)]
    if bad:
        raise UpdateError(f"规则块里有无法识别的行：{bad[:3]}")
    parsed = {tuple(RULE.match(line).group(1, 2)) for line in rules}
    if len(rules) < MIN_RULES or not REQUIRED <= parsed:
        raise UpdateError(f"规则数异常（{len(rules)} 条）或缺少核心域名，拒绝更新")
    for kind, value in parsed:
        if kind.startswith("IP-CIDR"):
            ipaddress.ip_network(value, strict=False)
        elif kind == "IP-ASN" and not value.isdigit():
            raise UpdateError(f"无效的 ASN：{value}")
    return lines


def announced_prefixes(asn: str) -> list[ipaddress._BaseNetwork] | None:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    for attempt in range(1, 4):
        try:
            data = json.loads(fetch(url))
            return [ipaddress.ip_network(item["prefix"]) for item in data["data"]["prefixes"]]
        except Exception as exc:  # RIPEstat 不可用时不阻塞更新
            print(f"警告：查询 AS{asn} 第 {attempt} 次失败：{exc}", file=sys.stderr)
            time.sleep(5 * attempt)
    return None


def previous_asn_blocks(path: Path) -> dict[str, list[str]]:
    """读出自动生成区里上次成功的 ASN 展开结果（注释行及其后的前缀行）。"""
    text = path.read_text(encoding="utf-8")
    start, end = text.find(BEGIN), text.find(END)
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in text[start + len(BEGIN):end].splitlines():
        line = line.strip()
        match = re.match(r"^# AS(\d+)：RIPEstat 宣告", line)
        if match:
            current = match.group(1)
            blocks[current] = [line]
        elif line.startswith("#"):
            current = None
        elif line and current:
            blocks[current].append(line)
    return blocks


def replace_region(path: Path, body: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    start, end = text.find(BEGIN), text.find(END)
    if start < 0 or end < start:
        raise UpdateError(f"{path.relative_to(ROOT)} 缺少 BEGIN/END 标记")
    region = "\n".join([BEGIN, *body, END])
    path.write_text(text[:start] + region + text[end + len(END):], encoding="utf-8", newline="\n")


def site_lines(lines: list[str]) -> list[str]:
    mapping = {"DOMAIN-SUFFIX": "domain", "DOMAIN": "full", "DOMAIN-KEYWORD": "keyword"}
    out = []
    for line in lines:
        if line.startswith("#"):
            if "IP" not in line:
                out.append(line)
            continue
        kind, value = RULE.match(line).group(1, 2)
        if kind in mapping:
            out.append(f"{mapping[kind]}:{value.lower()}")
    return out


def ip_lines(lines: list[str], previous: dict[str, list[str]]) -> list[str]:
    networks, asns = [], []
    for line in lines:
        match = RULE.match(line)
        if not match:
            continue
        kind, value = match.group(1, 2)
        if kind.startswith("IP-CIDR"):
            networks.append(ipaddress.ip_network(value, strict=False))
        elif kind == "IP-ASN":
            asns.append(value)
    out = [str(net) for net in networks]
    for asn in asns:
        prefixes = announced_prefixes(asn)
        if prefixes is None:
            # 查询失败时沿用上次成功的展开，避免网络波动造成无意义的变更或丢失前缀。
            out.extend(previous.get(asn) or [f"# AS{asn}：RIPEstat 暂不可用，仅依赖上方 CIDR"])
            continue
        extra = [p for p in prefixes if not any(p.version == n.version and p.subnet_of(n) for n in networks)]
        covered = len(prefixes) - len(extra)
        out.append(f"# AS{asn}：RIPEstat 宣告 {len(prefixes)} 个前缀，{covered} 个已被上方 CIDR 覆盖")
        out.extend(str(p) for p in extra)
    return out


def lsr_text(lines: list[str]) -> str:
    out = list(lines)
    check = ROOT / "geosite" / "ip-check"
    reverse = {"domain": "DOMAIN-SUFFIX", "full": "DOMAIN", "keyword": "DOMAIN-KEYWORD"}
    out.append("# 检测网站（由 geosite/ip-check 生成）")
    for raw in check.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        kind, sep, value = line.partition(":")
        if not sep:
            kind, value = "domain", line
        if kind in reverse:
            out.append(f"{reverse[kind]},{value}")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--html", help="使用本地保存的页面代替联网抓取")
    args = parser.parse_args()
    try:
        page = Path(args.html).read_text(encoding="utf-8") if args.html else fetch(SOURCE_URL)
        lines = extract_rules(page)
        previous = previous_asn_blocks(ROOT / "geoip" / "claude")
        site, ips, lsr = site_lines(lines), ip_lines(lines, previous), lsr_text(lines)
    except Exception as exc:
        print(f"更新失败：{exc}", file=sys.stderr)
        return 1
    replace_region(ROOT / "geosite" / "claude", site)
    replace_region(ROOT / "geoip" / "claude", ips)
    (ROOT / "anthropic_supple.lsr").write_text(lsr, encoding="utf-8", newline="\n")
    rules = sum(1 for line in lines if not line.startswith("#"))
    print(f"已同步 {rules} 条规则：geosite/claude、geoip/claude、anthropic_supple.lsr")
    return 0


if __name__ == "__main__":
    sys.exit(main())
