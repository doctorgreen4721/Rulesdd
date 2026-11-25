# Rulesdd

自用分流规则。`geosite/`、`geoip/` 下的文本规则可编译为 Xray / V2Ray 的 `.dat` 规则库（geodata）。

## Xray 规则库

| 文件 | 标签 | 内容 |
|---|---|---|
| `dist/geosite-rulesdd.dat` | `claude` | Claude / Anthropic 核心、CDN、认证、监控遥测、客服 widget 域名，并补入 Loyalsoldier `geosite:anthropic` 中的其余域名（32 条） |
| | `claude-kyc` | 身份核验（KYC）相关域名，遇到 KYC 时再启用（含 Google 通用的 `maps.googleapis.com`） |
| | `ip-check` | IP / 泄露检测网站，让检测结果与 Claude 出口一致 |
| `dist/geoip-rulesdd.dat` | `claude` | Anthropic 自有 IP 段 `160.79.104.0/21`、`2607:6bc0::/32`（覆盖 AS399358 当前宣告的全部前缀） |

Claude 规则来源：[Net.Coffee · Claude Code 域名分流规则大全](https://ip.net.coffee/claude/site.html)（2026-11-25 抓取）。映射关系：`DOMAIN-SUFFIX` → `domain:`，`DOMAIN` → `full:`，`DOMAIN-KEYWORD` → `keyword:`，`IP-CIDR(6)` → geoip。Xray 不支持 ASN 匹配，`IP-ASN,399358` 以上述两段 CIDR 代替。

`keyword:datadog`、`keyword:sift`、`keyword:sentry` 会顺带匹配其他使用这些服务的网站，这是原规则为保持出口一致的有意取舍。

### 在 Xray 配置中使用

把两个 `.dat` 放到 Xray 资源目录（通常与 `xray` 可执行文件同目录，或 `XRAY_LOCATION_ASSET` 指定的目录），并放在通用规则之前：

```jsonc
{
  "routing": {
    "rules": [
      { "domain": ["ext:geosite-rulesdd.dat:claude", "ext:geosite-rulesdd.dat:ip-check", "geosite:category-ntp"], "outboundTag": "proxy" },
      { "ip": ["ext:geoip-rulesdd.dat:claude"], "outboundTag": "proxy" }
    ]
  }
}
```

- NTP 时区检测使用官方 geosite 的 `geosite:category-ntp`（Loyalsoldier 版含 116 条），无需复制到本库。NTP 走 UDP，需要代理支持 UDP。
- 需要 KYC 时再加 `ext:geosite-rulesdd.dat:claude-kyc`。
- 标签不存在时 Xray 会拒绝启动，可先用 `xray run -test -c config.json` 检查。

新版 Xray 也可以用 `geodata` 定时下载并热重载（下载失败或重载失败会回滚）：

```jsonc
{
  "geodata": {
    "cron": "0 4 * * *",
    "outbound": "proxy",
    "assets": [
      { "url": "https://raw.githubusercontent.com/doctorgreen4721/Rulesdd/main/dist/geosite-rulesdd.dat", "file": "geosite-rulesdd.dat" },
      { "url": "https://raw.githubusercontent.com/doctorgreen4721/Rulesdd/main/dist/geoip-rulesdd.dat", "file": "geoip-rulesdd.dat" }
    ]
  }
}
```

## 修改与构建

规则源文件与 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) 格式一致，文件名即标签：

- `geosite/<tag>`：每行 `domain:` / `full:` / `keyword:` / `regexp:`，裸域名视为 `domain:`，`include:<tag>` 引入其他标签，`#` 为注释。
- `geoip/<tag>`：每行一个 IP 或 CIDR。

```bash
python tools/build_geodata.py                       # 生成 dist/*.dat，无第三方依赖
python tools/inspect_geodata.py dist/geosite-rulesdd.dat claude
python tools/verify_with_xray.py /path/to/xray      # 用真实核心验证加载与路由命中
```

`verify_with_xray.py` 只在 127.0.0.1 上启动临时核心：命中规则的连接进入 blackhole，未命中的连接被重定向到本机回显服务，不访问外网。2026-11-25 用 Xray 26.11.9 验证 24 个用例全部符合预期。

## 其他文件

`*.list`、`*.yaml`、`*.lsr`、`anthropic_supple.json` 为既有的其他格式规则，未改动。
