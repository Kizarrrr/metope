#!/usr/bin/env python3

import os
import sys
import re
import base64
import json
import urllib.parse
from datetime import datetime, timezone, timedelta

try:
    import yaml
except ImportError:
    print("[!] Error: PyYAML is required. Run: pip install pyyaml")
    sys.exit(1)

OUT_DIR = "output"
PROXIES_PATH = f"{OUT_DIR}/proxies.yaml"
CLASH_PATH = f"{OUT_DIR}/clash.yaml"
HAPP_PATH = f"{OUT_DIR}/happ.txt"

TEST_URL = "http://www.gstatic.com/generate_204"
BALANCE_TOP = 12
FALLBACK_TOP = 15
PROFILE_TITLE = "Metope"
UPDATE_HOURS = 2

def format_host(server: str) -> str:
    s = str(server or '').strip()
    if ':' in s and not s.startswith('['):
        return f"[{s}]"
    return s

def parse_proxies_yaml(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}
    proxies = data.get('proxies', [])
    if isinstance(proxies, list):
        return [p for p in proxies if isinstance(p, dict)]
    return []

def _q(d):
    items = [(k, v) for k, v in d.items() if v not in (None, '')]
    return urllib.parse.urlencode(items, quote_via=urllib.parse.quote)

def _alpn(p):
    a = p.get('alpn')
    return ','.join(a) if isinstance(a, list) else (a or '')

def _ws_path(p):
    return (p.get('ws-opts') or {}).get('path') or '/'

def _ws_host(p):
    h = (p.get('ws-opts') or {}).get('headers') or {}
    return h.get('Host') or h.get('host') or p.get('servername') or p.get('sni') or ''

def _grpc_name(p):
    return (p.get('grpc-opts') or {}).get('grpc-service-name') or ''

def _frag(p):
    return urllib.parse.quote(p.get('name', ''))

def link_vless(p):
    ro = p.get('reality-opts') if isinstance(p.get('reality-opts'), dict) else None
    net = p.get('network') or 'tcp'
    sec = 'reality' if ro else ('tls' if p.get('tls') else 'none')
    server = format_host(p.get('server', ''))
    sni = p.get('servername') or p.get('sni')
    q = {
        'encryption': 'none',
        'type': net,
        'security': sec,
        'sni': sni,
        'fp': p.get('client-fingerprint') if sec != 'none' else None,
        'alpn': _alpn(p),
        'flow': p.get('flow') if net == 'tcp' else None,
    }
    if (sec == 'tls' or p.get('skip-cert-verify')) and p.get('skip-cert-verify'):
        q['allowInsecure'] = '1'
    if ro:
        q['pbk'] = ro.get('public-key')
        if ro.get('short-id'):
            q['sid'] = ro.get('short-id')
        if ro.get('spider-x'):
            q['spx'] = ro.get('spider-x')
    if net == 'ws':
        q['path'] = _ws_path(p)
        q['host'] = _ws_host(p) or sni
    elif net == 'grpc':
        q['serviceName'] = _grpc_name(p)
        q['mode'] = 'gun'
    elif net in ('h2', 'http'):
        h2o = p.get('h2-opts') or p.get('http-opts') or {}
        if h2o.get('path'):
            q['path'] = h2o.get('path')
        if h2o.get('host'):
            h_val = h2o.get('host')
            q['host'] = ','.join(h_val) if isinstance(h_val, list) else str(h_val)
    elif net == 'xhttp':
        xo = p.get('xhttp-opts') if isinstance(p.get('xhttp-opts'), dict) else {}
        if xo.get('path'):
            q['path'] = xo.get('path')
        if xo.get('host'):
            q['host'] = xo.get('host')
        if xo.get('mode'):
            q['mode'] = xo.get('mode')
    return f"vless://{p.get('uuid', '')}@{server}:{p.get('port', 443)}?{_q(q)}#{_frag(p)}"

def link_trojan(p):
    net = p.get('network') or 'tcp'
    server = format_host(p.get('server', ''))
    sni = p.get('sni') or p.get('servername')
    ro = p.get('reality-opts') if isinstance(p.get('reality-opts'), dict) else None
    sec = 'reality' if ro else 'tls'
    q = {
        'security': sec,
        'sni': sni,
        'peer': sni,
        'fp': p.get('client-fingerprint') or 'firefox',
        'alpn': _alpn(p),
        'type': net
    }
    if p.get('skip-cert-verify'):
        q['allowInsecure'] = '1'
    if ro:
        q['pbk'] = ro.get('public-key')
        if ro.get('short-id'):
            q['sid'] = ro.get('short-id')
        if ro.get('spider-x'):
            q['spx'] = ro.get('spider-x')
    if net == 'ws':
        q['path'] = _ws_path(p)
        q['host'] = _ws_host(p) or sni
    elif net == 'grpc':
        q['serviceName'] = _grpc_name(p)
        q['mode'] = 'gun'
    elif net in ('h2', 'http'):
        h2o = p.get('h2-opts') or p.get('http-opts') or {}
        if h2o.get('path'):
            q['path'] = h2o.get('path')
        if h2o.get('host'):
            h_val = h2o.get('host')
            q['host'] = ','.join(h_val) if isinstance(h_val, list) else str(h_val)
    pw = urllib.parse.quote(str(p.get('password', '')), safe='')
    return f"trojan://{pw}@{server}:{p.get('port', 443)}?{_q(q)}#{_frag(p)}"

def link_ss(p):
    server = format_host(p.get('server', ''))
    userinfo = f"{p.get('cipher', '')}:{p.get('password', '')}".encode('utf-8')
    b64 = base64.urlsafe_b64encode(userinfo).decode().rstrip('=')
    link = f"ss://{b64}@{server}:{p.get('port', 8388)}"
    plugin = p.get('plugin')
    if plugin:
        opts = p.get('plugin-opts', {})
        if plugin == 'obfs':
            m = opts.get('mode', 'http')
            h = opts.get('host', '')
            plugin_str = f"obfs-local;obfs={m}"
            if h:
                plugin_str += f";obfs-host={h}"
        else:
            plugin_str = plugin
            if opts:
                opt_parts = []
                for k, v in opts.items():
                    if v is True or str(v).lower() == 'true':
                        opt_parts.append(k)
                    elif v is not False and str(v).lower() != 'false':
                        opt_parts.append(f"{k}={v}")
                if opt_parts:
                    plugin_str += ";" + ";".join(opt_parts)
        link += f"?plugin={urllib.parse.quote(plugin_str)}"
    return f"{link}#{_frag(p)}"

def link_hy2(p):
    server = format_host(p.get('server', ''))
    sni = p.get('sni') or p.get('servername')
    q = {
        'sni': sni,
        'alpn': _alpn(p),
        'obfs': p.get('obfs'),
        'obfs-password': p.get('obfs-password')
    }
    if p.get('skip-cert-verify'):
        q['insecure'] = '1'
    pw = urllib.parse.quote(str(p.get('password', '')), safe='')
    qs = _q(q)
    return f"hysteria2://{pw}@{server}:{p.get('port', 443)}{'?' + qs if qs else ''}#{_frag(p)}"

def link_hy1(p):
    server = format_host(p.get('server', ''))
    sni = p.get('sni') or p.get('servername')
    q = {
        'protocol': p.get('protocol', 'udp'),
        'auth': p.get('auth-str', ''),
        'peer': sni,
        'upmbps': str(p.get('up', '50')).replace(' Mbps', ''),
        'downmbps': str(p.get('down', '100')).replace(' Mbps', ''),
        'alpn': _alpn(p)
    }
    if p.get('skip-cert-verify'):
        q['insecure'] = '1'
    qs = _q(q)
    return f"hysteria://{server}:{p.get('port', 443)}?{qs}#{_frag(p)}"

def link_tuic(p):
    server = format_host(p.get('server', ''))
    sni = p.get('sni') or p.get('servername')
    q = {
        'congestion_control': p.get('congestion-controller', 'bbr'),
        'alpn': _alpn(p),
        'sni': sni
    }
    if p.get('skip-cert-verify'):
        q['allowInsecure'] = '1'
    uuid_val = p.get('uuid', '')
    pw = urllib.parse.quote(str(p.get('password', '')), safe='')
    qs = _q(q)
    return f"tuic://{uuid_val}:{pw}@{server}:{p.get('port', 8443)}{'?' + qs if qs else ''}#{_frag(p)}"

def link_wireguard(p):
    server = format_host(p.get('server', ''))
    q = {
        'publickey': p.get('public-key', ''),
        'ip': p.get('ip', ''),
    }
    if p.get('preshared-key'):
        q['presharedkey'] = p.get('preshared-key')
    if p.get('mtu'):
        q['mtu'] = str(p.get('mtu'))
    qs = _q(q)
    pk = urllib.parse.quote(str(p.get('private-key', '')), safe='')
    return f"wireguard://{pk}@{server}:{p.get('port', 51820)}?{qs}#{_frag(p)}"

def link_vmess(p):
    net = p.get('network') or 'tcp'
    tls = bool(p.get('tls'))
    server = str(p.get('server', '')).strip()
    sni = p.get('servername') or p.get('sni') or ''
    data = {
        'v': '2', 'ps': p['name'], 'add': server, 'port': int(p['port']),
        'id': p.get('uuid', ''), 'aid': int(p.get('alterId', 0) or 0),
        'scy': p.get('cipher') or 'auto', 'net': net, 'type': 'none',
        'host': '', 'path': '',
        'tls': 'tls' if tls else '',
        'sni': sni if tls else '',
        'alpn': _alpn(p), 'fp': p.get('client-fingerprint') or '',
    }
    if net == 'ws':
        data['host'] = _ws_host(p) or sni
        data['path'] = _ws_path(p)
    elif net == 'grpc':
        data['path'] = _grpc_name(p)
        data['type'] = 'gun'
    elif net in ('h2', 'http'):
        h2o = p.get('h2-opts') or p.get('http-opts') or {}
        if h2o.get('path'):
            data['path'] = h2o.get('path')
        if h2o.get('host'):
            h_val = h2o.get('host')
            data['host'] = ','.join(h_val) if isinstance(h_val, list) else str(h_val)
    return 'vmess://' + base64.b64encode(json.dumps(data, ensure_ascii=False).encode('utf-8')).decode()

def node_to_link(p):
    t = str(p.get('type', '')).lower()
    fn = {
        'vless': link_vless,
        'trojan': link_trojan,
        'ss': link_ss,
        'shadowsocks': link_ss,
        'hysteria2': link_hy2,
        'hy2': link_hy2,
        'hysteria': link_hy1,
        'hy': link_hy1,
        'tuic': link_tuic,
        'wireguard': link_wireguard,
        'vmess': link_vmess
    }.get(t)
    return fn(p) if fn else None

def main():
    if not os.path.exists(PROXIES_PATH):
        print(f"[!] {PROXIES_PATH} not found")
        return

    proxies = parse_proxies_yaml(PROXIES_PATH)
    if not proxies:
        print("[!] Ошибка: Список proxies пуст. Генерация clash.yaml прервана.")
        sys.exit(1)
    proxy_names = [p['name'] for p in proxies]

    msk = timezone(timedelta(hours=3))
    now_msk = datetime.now(msk).strftime("%Y-%m-%d %H:%M:%S МСК")
    updated_str = f"# Обновлено: {now_msk}"

    out = []
    out.append("# ============================================================")
    out.append(f"# {PROFILE_TITLE} | Mihomo / Clash.Meta / FlClash / Clash Verge / Stash")
    out.append(updated_str)
    out.append(f"# Рабочих серверов: {len(proxy_names)}")
    out.append(f"# Автовыбор + Резерв (топ-{FALLBACK_TOP}) + Балансировка (топ-{BALANCE_TOP}, consistent-hashing)")
    out.append(f"# Интервал обновления: каждые {UPDATE_HOURS} часа, ночью (02:00-08:00 МСК) без обновлений")
    out.append("# ============================================================")
    out.append("")
    out.append("mixed-port: 7890")
    out.append("allow-lan: false")
    out.append("mode: rule")
    out.append("log-level: info")
    out.append("unified-delay: true")
    out.append("tcp-concurrent: true")
    out.append("")
    out.append("profile:")
    out.append("  store-selected: true")
    out.append("  store-fake-ip: true")
    out.append("")
    out.append("hosts:")
    out.append("  ntc.party: 130.255.77.28")
    out.append("")
    out.append("dns:")
    out.append("  enable: true")
    out.append("  listen: 127.0.0.1:7874")
    out.append("  ipv6: false")
    out.append("  enhanced-mode: fake-ip")
    out.append("  fake-ip-range: 198.18.0.1/16")
    out.append("  fake-ip-filter:")
    out.append("    - '*.lan'")
    out.append("    - '*.local'")
    out.append("    - '+.msftconnecttest.com'")
    out.append("    - '+.msftncsi.com'")
    out.append("    - 'time.*.com'")
    out.append("    - 'ntp.*.com'")
    out.append("    - '+.stun.*.*'")
    out.append("    - 'connectivitycheck.gstatic.com'")
    out.append("    - 'captive.apple.com'")
    out.append("  nameserver-policy:")
    out.append("    '+.polaris-iot.com': 'https://77.88.8.8/dns-query'")
    out.append("    'rule-set:gemini': 'https://dns.dns-ai.ru/dns-query'")
    out.append("    'rule-set:ai': 'https://dns.dns-ai.ru/dns-query'")
    out.append("  default-nameserver:")
    out.append("    - 77.88.8.8")
    out.append("    - 8.8.8.8")
    out.append("    - 1.1.1.1")
    out.append("  proxy-server-nameserver:")
    out.append("    - https://77.88.8.8/dns-query")
    out.append("    - https://8.8.8.8/dns-query")
    out.append("  direct-nameserver:")
    out.append("    - https://77.88.8.8/dns-query")
    out.append("    - https://77.88.8.1/dns-query")
    out.append("    - https://8.8.8.8/dns-query")
    out.append("  nameserver:")
    out.append("    - https://cloudflare-dns.com/dns-query")
    out.append("    - https://1.1.1.1/dns-query")
    out.append("    - https://8.8.8.8/dns-query")
    out.append("    - https://8.8.4.4/dns-query")
    out.append("    - https://77.88.8.8/dns-query")
    out.append("    - https://77.88.8.1/dns-query")
    out.append("")
    out.append("sniffer:")
    out.append("  enable: true")
    out.append("  force-dns-mapping: true")
    out.append("  parse-pure-ip: true")
    out.append("  override-destination: true")
    out.append("  sniff:")
    out.append("    TLS:")
    out.append("      ports: [443, 8443]")
    out.append("    HTTP:")
    out.append("      ports: [80, '8080-8880']")
    out.append("    QUIC:")
    out.append("      ports: [443, 8443]")
    out.append("  skip-domain:")
    out.append("    - 'Mijia Cloud'")
    out.append("    - '+.push.apple.com'")
    out.append("")
    out.append("tun:")
    out.append("  enable: false")
    out.append("  stack: system")
    out.append("  auto-route: true")
    out.append("  auto-detect-interface: true")
    out.append("  dns-hijack:")
    out.append("    - any:53")
    out.append("    - tcp://any:53")
    out.append("  strict-route: true")
    out.append("")
    out.append("proxy-groups:")
    out.append("  - name: PROXY")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - ⚡ Автовыбор (Лучший пинг)")
    out.append("      - 🛟 Резерв (Fallback)")
    out.append("      - ⚖️ Балансировка нагрузки")
    for p in proxy_names:
        safe_p = p.replace("'", "''")
        out.append(f"      - '{safe_p}'")
    out.append("      - DIRECT")
    out.append("")
    out.append("  - name: ⚡ Автовыбор (Лучший пинг)")
    out.append("    type: url-test")
    out.append(f"    url: {TEST_URL}")
    out.append("    interval: 300")
    out.append("    tolerance: 50")
    out.append("    lazy: true")
    out.append("    timeout: 4000")
    out.append("    max-failed-times: 3")
    out.append("    proxies:")
    for p in proxy_names:
        safe_p = p.replace("'", "''")
        out.append(f"      - '{safe_p}'")
    out.append("")
    out.append("  - name: 🛟 Резерв (Fallback)")
    out.append("    type: fallback")
    out.append(f"    url: {TEST_URL}")
    out.append("    interval: 120")
    out.append("    lazy: true")
    out.append("    timeout: 4000")
    out.append("    max-failed-times: 2")
    out.append("    proxies:")
    for p in proxy_names[:FALLBACK_TOP]:
        safe_p = p.replace("'", "''")
        out.append(f"      - '{safe_p}'")
    out.append("")
    out.append("  - name: ⚖️ Балансировка нагрузки")
    out.append("    type: load-balance")
    out.append("    strategy: consistent-hashing")
    out.append(f"    url: {TEST_URL}")
    out.append("    interval: 300")
    out.append("    lazy: true")
    out.append("    timeout: 4000")
    out.append("    proxies:")
    for p in proxy_names[:BALANCE_TOP]:
        safe_p = p.replace("'", "''")
        out.append(f"      - '{safe_p}'")
    non_ru_proxies = [
        p['name'] for p in proxies
        if p.get('country') and p.get('country') not in ('RU', 'BY', 'UN', 'UNKNOWN')
        and not any(ru in p['name'] for ru in ('Россия', 'Беларусь', 'Неизвестно', '🇷🇺', '🇧🇾', '🌐'))
    ]
    if not non_ru_proxies:
        print("[!] Внимание: Зарубежные узлы для группы ИИ не найдены! Установлен DIRECT.")
        ai_candidates = ['DIRECT']
    else:
        ai_candidates = non_ru_proxies
    out.append("")
    out.append("  - name: 🤖 Искусственный интеллект")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - 🤖 ИИ Авто (Зарубежные)")
    for p in ai_candidates:
        safe_p = p.replace("'", "''")
        out.append(f"      - '{safe_p}'")
    if 'DIRECT' not in ai_candidates:
        out.append("      - DIRECT")
    out.append("")
    out.append("  - name: 🤖 ИИ Авто (Зарубежные)")
    out.append("    type: url-test")
    out.append("    url: https://gemini.google.com")
    out.append("    interval: 300")
    out.append("    tolerance: 50")
    out.append("    lazy: true")
    out.append("    timeout: 4000")
    out.append("    proxies:")
    for p in ai_candidates:
        safe_p = p.replace("'", "''")
        out.append(f"      - '{safe_p}'")
    out.append("")
    out.append("rule-providers:")
    out.append("  private-domains:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/private.yaml'")
    out.append("    interval: 2592000")
    out.append("    path: ./ruleset/private-domains.yaml")
    out.append("")
    out.append("  private-ips:")
    out.append("    behavior: ipcidr")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/private.yaml'")
    out.append("    interval: 2592000")
    out.append("    path: ./ruleset/private-ips.yaml")
    out.append("")
    out.append("  apple:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/apple.yaml")
    out.append("")
    out.append("  adblock:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ads-all.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/adblock.yaml")
    out.append("")
    out.append("  win-office-spy:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: text")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/wildcard/native.winoffice-onlydomains.txt'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/win-office-spy.txt")
    out.append("")
    out.append("  xiaomi-spy:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: text")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/wildcard/native.xiaomi-onlydomains.txt'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/xiaomi-spy.txt")
    out.append("")
    out.append("  gemini:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/google-gemini.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/gemini.yaml")
    out.append("")
    out.append("  ai:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ai-!cn.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/ai.yaml")
    out.append("")
    out.append("  anthropic:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/anthropic.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/anthropic.yaml")
    out.append("")
    out.append("  youtube:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/youtube.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/youtube.yaml")
    out.append("")
    out.append("  twitter:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: text")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/itdoginfo/allow-domains@main/Services/twitter.lst'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/twitter.list")
    out.append("")
    out.append("  spotify:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/spotify.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/spotify.yaml")
    out.append("")
    out.append("  github:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/github.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/github.yaml")
    out.append("")
    out.append("  google-play:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/google-play.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/google-play.yaml")
    out.append("")
    out.append("  telegram:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/telegram.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/telegram.yaml")
    out.append("")
    out.append("  russia-inside:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: text")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/itdoginfo/allow-domains@main/Russia/inside-raw.lst'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/russia-inside.list")
    out.append("")
    out.append("  torrent-domains:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-public-tracker.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/torrent-domains.yaml")
    out.append("")
    out.append("  download:")
    out.append("    behavior: classical")
    out.append("    type: http")
    out.append("    format: text")
    out.append("    url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Download/Download.list'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/download.list")
    out.append("")
    out.append("  spb-tele2:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: text")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/chebur-net/russia-mobile-whitelist@main/spb-tele2/domains.txt'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/spb-tele2.txt")
    out.append("")
    out.append("  category-bank-ru:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-bank-ru.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/category-bank-ru.yaml")
    out.append("")
    out.append("  category-gov-ru:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-gov-ru.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/category-gov-ru.yaml")
    out.append("")
    out.append("  ru-app-list:")
    out.append("    behavior: classical")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/legiz-ru/mihomo-rule-sets@main/other/ru-app-list.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/ru-app-list.yaml")
    out.append("")
    out.append("  category-ru:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ru.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/category-ru.yaml")
    out.append("")
    out.append("  microsoft:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/microsoft.yaml")
    out.append("")
    out.append("  twitch:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/twitch.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/twitch.yaml")
    out.append("")
    out.append("  pinterest:")
    out.append("    behavior: domain")
    out.append("    type: http")
    out.append("    format: yaml")
    out.append("    url: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/pinterest.yaml'")
    out.append("    interval: 86400")
    out.append("    path: ./ruleset/pinterest.yaml")
    out.append("")
    out.append("rules:")
    out.append("  - RULE-SET,private-domains,DIRECT")
    out.append("  - RULE-SET,private-ips,DIRECT,no-resolve")
    out.append("  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
    out.append("  - DOMAIN-SUFFIX,ozon.ru,DIRECT")
    out.append("  - DOMAIN-SUFFIX,avito.ru,DIRECT")
    out.append("  - DOMAIN-SUFFIX,avito.st,DIRECT")
    out.append("  - DOMAIN-SUFFIX,ozone.ru,DIRECT")
    out.append("  - DOMAIN-SUFFIX,ozonusercontent.com,DIRECT")
    out.append("  - DOMAIN-SUFFIX,wildberries.ru,DIRECT")
    out.append("  - DOMAIN-SUFFIX,wb.ru,DIRECT")
    out.append("  - DOMAIN-SUFFIX,wbbasket.ru,DIRECT")
    out.append("  - DOMAIN-SUFFIX,geobasket.ru,DIRECT")
    out.append("  - DOMAIN-SUFFIX,paywb.com,DIRECT")
    out.append("  - DOMAIN-SUFFIX,apple.com,PROXY")
    out.append("  - DOMAIN-SUFFIX,icloud.com,PROXY")
    out.append("  - DOMAIN-SUFFIX,cdn-apple.com,PROXY")
    out.append("  - IP-CIDR,17.0.0.0/8,PROXY,no-resolve")
    out.append("  - RULE-SET,apple,PROXY")
    out.append("  - DOMAIN-SUFFIX,sberbank.ru,DIRECT")
    out.append("  - DOMAIN,subnebulaguard.mooo.com,PROXY")
    out.append("  - DOMAIN,my.vpn.lease,DIRECT")
    out.append("  - DOMAIN-SUFFIX,ntc.party,PROXY")
    out.append("  - DOMAIN-SUFFIX,rutracker.org,PROXY")
    out.append("  - DOMAIN-SUFFIX,rutracker.net,PROXY")
    out.append("  - DOMAIN-SUFFIX,t-ru.org,PROXY")
    out.append("  - DOMAIN-SUFFIX,gitlab.com,PROXY")
    out.append("  - DOMAIN-SUFFIX,sidestore.io,PROXY")
    out.append("  - DOMAIN-SUFFIX,right.com.cn,PROXY")
    out.append("  - DOMAIN-SUFFIX,xbox-dns.ru,PROXY")
    out.append("  - RULE-SET,adblock,REJECT")
    out.append("  - RULE-SET,win-office-spy,REJECT")
    out.append("  - RULE-SET,xiaomi-spy,REJECT")
    out.append("  - DOMAIN-SUFFIX,gemini.google.com,🤖 Искусственный интеллект")
    out.append("  - DOMAIN-SUFFIX,anthropic.com,🤖 Искусственный интеллект")
    out.append("  - DOMAIN-SUFFIX,claude.ai,🤖 Искусственный интеллект")
    out.append("  - RULE-SET,gemini,🤖 Искусственный интеллект")
    out.append("  - RULE-SET,ai,🤖 Искусственный интеллект")
    out.append("  - RULE-SET,anthropic,🤖 Искусственный интеллект")
    out.append("  - DOMAIN-SUFFIX,youtube.com,PROXY")
    out.append("  - DOMAIN-SUFFIX,googlevideo.com,PROXY")
    out.append("  - DOMAIN-SUFFIX,ytimg.com,PROXY")
    out.append("  - DOMAIN-SUFFIX,youtu.be,PROXY")
    out.append("  - RULE-SET,youtube,PROXY")
    out.append("  - RULE-SET,twitter,PROXY")
    out.append("  - RULE-SET,spotify,PROXY")
    out.append("  - RULE-SET,github,PROXY")
    out.append("  - RULE-SET,google-play,PROXY")
    out.append("  - DOMAIN-SUFFIX,telegram.org,PROXY")
    out.append("  - DOMAIN-SUFFIX,t.me,PROXY")
    out.append("  - RULE-SET,telegram,PROXY")
    out.append("  - IP-CIDR,91.108.4.0/22,PROXY,no-resolve")
    out.append("  - IP-CIDR,91.108.8.0/22,PROXY,no-resolve")
    out.append("  - IP-CIDR,91.108.12.0/22,PROXY,no-resolve")
    out.append("  - IP-CIDR,91.108.16.0/22,PROXY,no-resolve")
    out.append("  - IP-CIDR,91.108.56.0/22,PROXY,no-resolve")
    out.append("  - IP-CIDR,149.154.160.0/20,PROXY,no-resolve")
    out.append("  - IP-CIDR,149.154.164.0/22,PROXY,no-resolve")
    out.append("  - IP-CIDR,149.154.168.0/21,PROXY,no-resolve")
    out.append("  - IP-CIDR,149.154.172.0/22,PROXY,no-resolve")
    out.append("  - RULE-SET,russia-inside,PROXY")
    out.append("  - RULE-SET,torrent-domains,DIRECT")
    out.append("  - RULE-SET,download,DIRECT")
    out.append("  - RULE-SET,spb-tele2,DIRECT")
    out.append("  - IP-CIDR,109.207.1.0/24,DIRECT")
    out.append("  - IP-CIDR,109.207.9.0/24,DIRECT")
    out.append("  - IP-CIDR,109.238.88.0/24,DIRECT")
    out.append("  - IP-CIDR,109.238.90.0/24,DIRECT")
    out.append("  - IP-CIDR,155.212.192.0/20,DIRECT")
    out.append("  - IP-CIDR,158.160.0.0/16,DIRECT")
    out.append("  - IP-CIDR,176.114.120.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.232.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.233.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.234.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.235.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.236.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.237.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.238.0/24,DIRECT")
    out.append("  - IP-CIDR,178.248.239.0/24,DIRECT")
    out.append("  - IP-CIDR,185.12.152.0/24,DIRECT")
    out.append("  - IP-CIDR,185.129.100.0/24,DIRECT")
    out.append("  - IP-CIDR,185.163.159.0/24,DIRECT")
    out.append("  - IP-CIDR,185.165.123.0/24,DIRECT")
    out.append("  - IP-CIDR,185.169.155.0/24,DIRECT")
    out.append("  - IP-CIDR,185.178.208.0/24,DIRECT")
    out.append("  - IP-CIDR,185.178.210.0/24,DIRECT")
    out.append("  - IP-CIDR,185.180.200.0/22,DIRECT")
    out.append("  - IP-CIDR,185.215.4.0/24,DIRECT")
    out.append("  - IP-CIDR,185.253.20.0/24,DIRECT")
    out.append("  - IP-CIDR,185.6.47.0/24,DIRECT")
    out.append("  - IP-CIDR,185.62.202.0/24,DIRECT")
    out.append("  - IP-CIDR,185.65.148.0/24,DIRECT")
    out.append("  - IP-CIDR,185.65.149.0/24,DIRECT")
    out.append("  - IP-CIDR,185.71.64.0/24,DIRECT")
    out.append("  - IP-CIDR,185.71.67.0/24,DIRECT")
    out.append("  - IP-CIDR,185.73.193.0/24,DIRECT")
    out.append("  - IP-CIDR,188.162.32.0/19,DIRECT")
    out.append("  - RULE-SET,category-bank-ru,DIRECT")
    out.append("  - RULE-SET,category-gov-ru,DIRECT")
    out.append("  - RULE-SET,ru-app-list,DIRECT")
    out.append("  - RULE-SET,category-ru,DIRECT")
    out.append("  - RULE-SET,microsoft,DIRECT")
    out.append("  - RULE-SET,twitch,DIRECT")
    out.append("  - RULE-SET,pinterest,DIRECT")
    out.append("  - GEOIP,RU,DIRECT")
    out.append("  - IP-CIDR,::/0,REJECT,no-resolve")
    out.append("  - MATCH,PROXY")
    out.append("")
    clean_clash_proxies = []
    for p in proxies:
        cp = {k: v for k, v in p.items() if k != 'country'}
        for k in ('sni', 'servername'):
            if cp.get(k) in ('', "''", '""'):
                cp.pop(k, None)
        clean_clash_proxies.append(cp)

    out.append(yaml.dump({'proxies': clean_clash_proxies}, allow_unicode=True, sort_keys=False).rstrip())

    os.makedirs(OUT_DIR, exist_ok=True)
    tmp_clash = CLASH_PATH + ".tmp"
    with open(tmp_clash, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')
    os.replace(tmp_clash, CLASH_PATH)

    links = []
    skipped_types = {}
    for p in proxies:
        ptype = str(p.get('type', 'unknown')).lower()
        try:
            link = node_to_link(p)
            if link:
                links.append(link)
            else:
                skipped_types[ptype] = skipped_types.get(ptype, 0) + 1
        except Exception as e:
            skipped_types[f"{ptype} (error: {e})"] = skipped_types.get(f"{ptype} (error: {e})", 0) + 1

    tmp_happ = HAPP_PATH + ".tmp"
    with open(tmp_happ, 'w', encoding='utf-8') as f:
        f.write(f"#profile-title: {PROFILE_TITLE}\n")
        f.write(f"#profile-update-interval: {UPDATE_HOURS}\n")
        f.write('\n'.join(links) + '\n')
    os.replace(tmp_happ, HAPP_PATH)

    print(f"[+] {CLASH_PATH} ({len(proxy_names)} серверов)")
    print(f"[+] {HAPP_PATH} ({len(links)} ссылок для Happ)")
    if skipped_types:
        print(f"    [!] Не экспортировано в Happ: {skipped_types}")

if __name__ == "__main__":
    main()
