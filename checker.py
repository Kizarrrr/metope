#!/usr/bin/env python3

import os
import sys
import re
import socket
import json
import base64
import shutil
import hashlib
import urllib.parse
import urllib.request
import subprocess
import time
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

try:
    import requests
    import yaml
except ImportError:
    print("[!] Error: Missing required packages. Run: pip install requests pyyaml")
    sys.exit(1)

HEADERS = {
    "User-Agent": "clash.meta"
}

def is_forbidden_host(host: str) -> bool:
    h = str(host or '').strip().strip('[]').rstrip('.')
    if not h:
        return True
    hl = h.lower()
    if hl in ('localhost', '0.0.0.0') or hl.endswith(('.local', '.localhost', '.internal', '.lan', '.localdomain', '.home.arpa')):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return not ip.is_global
    except ValueError:
        return False

def normalize_url(url: str) -> str:
    url = url.strip()
    if "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    if "gitlab.com" in url and "/-/blob/" in url:
        url = url.replace("/-/blob/", "/-/raw/")
    return url

def safe_b64decode(s: str) -> str:
    s = s.strip().replace('-', '+').replace('_', '/')
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.b64decode(s).decode('utf-8', errors='ignore')

def parse_singbox_outbounds(data: dict) -> list:
    proxies = []
    for ob in data.get('outbounds', []):
        otype = ob.get('type')
        tag = ob.get('tag', 'singbox-node')
        server = ob.get('server')
        port = ob.get('server_port')
        if not server or not port:
            continue
        tls = ob.get('tls', {})
        transport = ob.get('transport', {})
        node = {'name': tag, 'server': str(server).strip(), 'port': int(port), 'udp': True}
        if otype == 'vless':
            node['type'] = 'vless'
            node['uuid'] = ob.get('uuid', '')
            node['cipher'] = 'auto'
            node['flow'] = ob.get('flow', '')
            node['tls'] = tls.get('enabled', False)
            if tls.get('server_name'):
                node['servername'] = tls['server_name']
            if tls.get('reality', {}).get('enabled'):
                node['reality-opts'] = {
                    'public-key': tls['reality'].get('public_key', ''),
                    'short-id': tls['reality'].get('short_id', '')
                }
            if tls.get('utls', {}).get('fingerprint'):
                node['client-fingerprint'] = tls['utls']['fingerprint']
            tr_type = str(transport.get('type', 'tcp')).lower()
            if tr_type in ('raw', 'none', ''):
                tr_type = 'tcp'
            node['network'] = tr_type
            if tr_type == 'ws':
                node['ws-opts'] = {'path': transport.get('path', '/'), 'headers': transport.get('headers', {})}
            elif tr_type == 'grpc':
                node['grpc-opts'] = {'grpc-service-name': transport.get('service_name', '')}
            proxies.append(node)
        elif otype == 'shadowsocks':
            node['type'] = 'ss'
            node['cipher'] = ob.get('method', '')
            node['password'] = ob.get('password', '')
            proxies.append(node)
        elif otype == 'trojan':
            node['type'] = 'trojan'
            node['password'] = ob.get('password', '')
            if tls.get('server_name'):
                node['sni'] = tls['server_name']
            proxies.append(node)
        elif otype == 'hysteria2':
            node['type'] = 'hysteria2'
            node['password'] = ob.get('password', '')
            if tls.get('server_name'):
                node['sni'] = tls['server_name']
            obfs = ob.get('obfs', {})
            if obfs.get('type'):
                node['obfs'] = obfs.get('type')
                node['obfs-password'] = obfs.get('password', '')
            proxies.append(node)
        elif otype == 'tuic':
            node['type'] = 'tuic'
            node['uuid'] = ob.get('uuid', '')
            node['password'] = ob.get('password', '')
            node['congestion-controller'] = ob.get('congestion_control', 'bbr')
            if tls.get('server_name'):
                node['sni'] = tls['server_name']
            proxies.append(node)
        elif otype == 'vmess':
            node['type'] = 'vmess'
            node['uuid'] = ob.get('uuid', '')
            node['alterId'] = int(ob.get('alter_id', 0))
            node['cipher'] = ob.get('security') or 'auto'
            node['tls'] = tls.get('enabled', False)
            if tls.get('server_name'):
                node['servername'] = tls['server_name']
            proxies.append(node)
    return proxies

def parse_raw_link(line: str) -> dict:
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    try:
        if line.startswith('vmess://') and '@' not in line:
            b64 = line[8:]
            try:
                data = json.loads(safe_b64decode(b64))
                net = str(data.get('net', 'tcp')).lower()
                if net in ('raw', 'none', ''):
                    net = 'tcp'
                tls = data.get('tls') == 'tls'
                cipher = data.get('scy') or 'auto'
                if cipher in ('none', 'null', ''):
                    cipher = 'auto'
                node = {
                    'name': data.get('ps', f"vmess-{data.get('add')}"),
                    'type': 'vmess',
                    'server': str(data.get('add', '')).strip(),
                    'port': int(data.get('port', 443)),
                    'uuid': data.get('id'),
                    'alterId': int(data.get('aid', 0)),
                    'cipher': cipher,
                    'udp': True,
                    'tls': tls,
                    'network': net,
                    'servername': data.get('sni') or data.get('host', '')
                }
                if data.get('fp'):
                    node['client-fingerprint'] = data['fp']
                if net == 'ws':
                    ws_dict = {'path': data.get('path', '/')}
                    host_hdr = data.get('host') or data.get('sni')
                    if host_hdr:
                        ws_dict['headers'] = {'Host': host_hdr}
                    node['ws-opts'] = ws_dict
                elif net == 'grpc':
                    node['grpc-opts'] = {
                        'grpc-service-name': data.get('path') or data.get('serviceName', '')
                    }
                elif net in ('h2', 'http'):
                    h2_dict = {'path': data.get('path', '/')}
                    if data.get('host'):
                        h2_dict['host'] = [data['host']]
                    node['h2-opts'] = h2_dict
                return node
            except Exception:
                pass

        if line.startswith('ssr://'):
            try:
                dec = safe_b64decode(line[6:])
                main_part, *qs_part = dec.split('/?', 1)
                parts = main_part.split(':')
                if len(parts) >= 6:
                    server, port, protocol, method, obfs, b64pass = parts[:6]
                    pwd = safe_b64decode(b64pass)
                    qs = urllib.parse.parse_qs(qs_part[0]) if qs_part else {}
                    remarks = safe_b64decode(qs.get('remarks', [''])[0]) if 'remarks' in qs else f"ssr-{server}"
                    obfsparam = safe_b64decode(qs.get('obfsparam', [''])[0]) if 'obfsparam' in qs else ''
                    protoparam = safe_b64decode(qs.get('protoparam', [''])[0]) if 'protoparam' in qs else ''
                    return {
                        'name': remarks or f"ssr-{server}",
                        'type': 'ssr',
                        'server': server.strip(),
                        'port': int(port),
                        'cipher': method,
                        'password': pwd,
                        'protocol': protocol,
                        'protocol-param': protoparam,
                        'obfs': obfs,
                        'obfs-param': obfsparam,
                        'udp': True
                    }
            except Exception:
                pass

        p = urllib.parse.urlparse(line)
        qs = urllib.parse.parse_qs(p.query)
        name = urllib.parse.unquote(p.fragment) if p.fragment else f"{p.scheme}-{p.hostname}"
        scheme = p.scheme.lower()

        if scheme in ('hy2', 'hysteria2'):
            auth_val = urllib.parse.unquote(p.password) if p.password else (urllib.parse.unquote(p.username) if p.username else '')
            if p.username and p.password:
                auth_val = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password)}"
            node = {
                'name': name,
                'type': 'hysteria2',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 443),
                'password': auth_val
            }
            sni_val = qs.get('sni', [''])[0] or qs.get('peer', [''])[0]
            if sni_val:
                node['sni'] = sni_val
            if qs.get('insecure', ['0'])[0] == '1' or qs.get('allowInsecure', ['0'])[0] == '1':
                node['skip-cert-verify'] = True
            obfs = qs.get('obfs', [''])[0]
            if obfs:
                node['obfs'] = obfs
            obfs_pw = qs.get('obfs-password', [''])[0]
            if obfs_pw:
                node['obfs-password'] = obfs_pw
            if 'alpn' in qs:
                alpn_list = [x.strip() for x in qs['alpn'][0].split(',') if x.strip()]
                if alpn_list:
                    node['alpn'] = alpn_list
            fp = qs.get('fp', [''])[0]
            node['client-fingerprint'] = fp if fp else 'firefox'
            ports = qs.get('mport', [''])[0] or qs.get('ports', [''])[0]
            if ports:
                node['ports'] = ports
            up_val = qs.get('up', [''])[0].strip()
            down_val = qs.get('down', [''])[0].strip()
            if up_val:
                node['up'] = f"{up_val} Mbps" if up_val.isdigit() else up_val
            if down_val:
                node['down'] = f"{down_val} Mbps" if down_val.isdigit() else down_val
            return node

        elif scheme in ('hy', 'hysteria'):
            node = {
                'name': name,
                'type': 'hysteria',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 443),
                'auth-str': p.password or p.username or qs.get('auth', [''])[0],
                'protocol': qs.get('protocol', ['udp'])[0]
            }
            sni_val = qs.get('sni', [''])[0] or qs.get('peer', [''])[0]
            if sni_val:
                node['sni'] = sni_val
            if qs.get('insecure', ['0'])[0] == '1' or qs.get('allowInsecure', ['0'])[0] == '1':
                node['skip-cert-verify'] = True
            if 'alpn' in qs:
                alpn_list = [x.strip() for x in qs['alpn'][0].split(',') if x.strip()]
                if alpn_list:
                    node['alpn'] = alpn_list
            obfs_param = qs.get('obfsParam', [''])[0] or qs.get('obfs-password', [''])[0]
            if obfs_param:
                node['obfs'] = obfs_param
            elif 'obfs' in qs and qs['obfs'][0] and qs['obfs'][0] != 'xplus':
                node['obfs'] = qs['obfs'][0]
            up_val = qs.get('upmbps', [''])[0] or qs.get('up', ['50 Mbps'])[0] or '50 Mbps'
            down_val = qs.get('downmbps', [''])[0] or qs.get('down', ['100 Mbps'])[0] or '100 Mbps'
            if up_val.isdigit():
                up_val = f"{up_val} Mbps"
            if down_val.isdigit():
                down_val = f"{down_val} Mbps"
            node['up'] = up_val
            node['down'] = down_val
            return node

        elif scheme == 'vless':
            security = qs.get('security', [''])[0].lower()
            net = qs.get('type', ['tcp'])[0].lower()
            if net in ('raw', 'none', ''):
                net = 'tcp'
            uuid_val = urllib.parse.unquote(p.username or '')
            node = {
                'name': name,
                'type': 'vless',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 443),
                'uuid': uuid_val,
                'udp': True,
                'tls': security in ('tls', 'reality'),
                'network': net
            }
            sn_val = qs.get('sni', [''])[0] or qs.get('peer', [''])[0]
            if sn_val:
                node['servername'] = sn_val
            if qs.get('insecure', ['0'])[0] == '1' or qs.get('allowInsecure', ['0'])[0] == '1':
                node['skip-cert-verify'] = True
            if security == 'reality':
                pbk = qs.get('pbk', [''])[0]
                if pbk:
                    ro = {'public-key': pbk}
                    sid = qs.get('sid', [''])[0]
                    if sid:
                        ro['short-id'] = sid
                    spx = qs.get('spx', [''])[0]
                    if spx:
                        ro['spider-x'] = spx
                    node['reality-opts'] = ro
                else:
                    node['tls'] = True
            fp = qs.get('fp', [''])[0]
            node['client-fingerprint'] = fp if fp else 'firefox'
            if 'alpn' in qs:
                alpn_list = [x.strip() for x in qs['alpn'][0].split(',') if x.strip()]
                if alpn_list:
                    node['alpn'] = alpn_list
            if 'flow' in qs and qs['flow'][0]:
                node['flow'] = qs['flow'][0]
            if net == 'ws':
                ws_dict = {'path': qs.get('path', ['/'])[0]}
                host_hdr = qs.get('host', [node.get('servername', '')])[0]
                if host_hdr and host_hdr.strip():
                    ws_dict['headers'] = {'Host': host_hdr.strip()}
                node['ws-opts'] = ws_dict
            elif net == 'grpc':
                node['grpc-opts'] = {
                    'grpc-service-name': qs.get('serviceName', [''])[0] or qs.get('path', [''])[0]
                }
            elif net in ('h2', 'http'):
                node['h2-opts'] = {
                    'path': qs.get('path', ['/'])[0],
                    'host': [qs.get('host', [node.get('servername', '')])[0]]
                }
            elif net == 'xhttp':
                xo = {'path': qs.get('path', ['/'])[0]}
                if 'host' in qs:
                    xo['host'] = qs['host'][0]
                if 'mode' in qs:
                    xo['mode'] = qs['mode'][0]
                node['xhttp-opts'] = xo
            elif net != 'tcp':
                node['network'] = 'tcp'
            return node

        elif scheme == 'vmess':
            net = qs.get('type', ['tcp'])[0].lower()
            if net in ('raw', 'none', ''):
                net = 'tcp'
            tls = qs.get('security', [''])[0].lower() in ('tls', 'auto')
            uuid_val = urllib.parse.unquote(p.username or '')
            node = {
                'name': name,
                'type': 'vmess',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 443),
                'uuid': uuid_val,
                'alterId': int(qs.get('alterId', ['0'])[0]),
                'cipher': 'auto',
                'udp': True,
                'tls': tls,
                'network': net
            }
            sn_val = qs.get('sni', [''])[0] or qs.get('host', [''])[0]
            if sn_val:
                node['servername'] = sn_val
            if net == 'ws':
                ws_dict = {'path': qs.get('path', ['/'])[0]}
                host_hdr = qs.get('host', [node.get('servername', '')])[0]
                if host_hdr and host_hdr.strip():
                    ws_dict['headers'] = {'Host': host_hdr.strip()}
                node['ws-opts'] = ws_dict
            elif net == 'grpc':
                node['grpc-opts'] = {'grpc-service-name': qs.get('serviceName', [''])[0] or qs.get('path', [''])[0]}
            elif net != 'tcp':
                node['network'] = 'tcp'
            return node

        elif scheme == 'trojan':
            security = qs.get('security', [''])[0].lower()
            net = qs.get('type', ['tcp'])[0].lower()
            if net in ('raw', 'none', ''):
                net = 'tcp'
            auth_val = urllib.parse.unquote(p.password or p.username or '')
            node = {
                'name': name,
                'type': 'trojan',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 443),
                'password': auth_val,
                'udp': True
            }
            sni_val = qs.get('sni', [''])[0] or qs.get('peer', [''])[0]
            if sni_val:
                node['sni'] = sni_val
            if qs.get('allowInsecure', ['0'])[0] == '1' or qs.get('insecure', ['0'])[0] == '1':
                node['skip-cert-verify'] = True
            if security == 'reality':
                pbk = qs.get('pbk', [''])[0]
                if pbk:
                    ro = {'public-key': pbk}
                    sid = qs.get('sid', [''])[0]
                    if sid:
                        ro['short-id'] = sid
                    node['reality-opts'] = ro
            if net != 'tcp':
                node['network'] = net
            fp = qs.get('fp', [''])[0]
            node['client-fingerprint'] = fp if fp else 'firefox'
            if 'alpn' in qs:
                alpn_list = [x.strip() for x in qs['alpn'][0].split(',') if x.strip()]
                if alpn_list:
                    node['alpn'] = alpn_list
            if net == 'ws':
                ws_dict = {'path': qs.get('path', ['/'])[0]}
                host_hdr = qs.get('host', [node.get('sni', '')])[0]
                if host_hdr and host_hdr.strip():
                    ws_dict['headers'] = {'Host': host_hdr.strip()}
                node['ws-opts'] = ws_dict
            elif net == 'grpc':
                node['grpc-opts'] = {
                    'grpc-service-name': qs.get('serviceName', [''])[0] or qs.get('path', [''])[0]
                }
            elif net != 'tcp':
                node['network'] = 'tcp'
            return node

        elif scheme == 'tuic':
            node = {
                'name': name,
                'type': 'tuic',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 443),
                'uuid': p.username or '',
                'password': p.password or '',
                'congestion-controller': qs.get('congestion_control', ['bbr'])[0],
                'alpn': [x.strip() for x in qs.get('alpn', ['h3'])[0].split(',') if x.strip()],
                'udp-relay-mode': qs.get('udp_relay_mode', ['native'])[0],
                'reduce-rtt': True,
                'udp': True
            }
            sni_val = qs.get('sni', [''])[0]
            if sni_val:
                node['sni'] = sni_val
            if qs.get('allow_insecure', ['0'])[0] == '1' or qs.get('insecure', ['0'])[0] == '1':
                node['skip-cert-verify'] = True
            return node

        elif scheme == 'ss':
            node = {
                'name': name,
                'type': 'ss',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 0),
                'udp': True
            }
            if p.username:
                decoded = safe_b64decode(p.username)
                if ':' in decoded:
                    cipher, pwd = decoded.split(':', 1)
                    node['cipher'] = cipher
                    node['password'] = pwd
                else:
                    node['cipher'] = urllib.parse.unquote(p.username)
                    node['password'] = urllib.parse.unquote(p.password or '')
            elif '@' not in line:
                decoded = safe_b64decode(p.netloc)
                if '@' in decoded:
                    userinfo, hostport = decoded.split('@', 1)
                    cipher, pwd = userinfo.split(':', 1)
                    host, port = hostport.split(':', 1)
                    node['server'] = str(host).strip()
                    node['port'] = int(port)
                    node['cipher'] = cipher
                    node['password'] = pwd
            if 'plugin' in qs and qs['plugin'][0]:
                parts = qs['plugin'][0].split(';')
                raw_plugin = parts[0].strip()
                opts = {}
                for part in parts[1:]:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        opts[k.strip()] = v.strip()
                    elif part.strip():
                        opts[part.strip()] = True
                if raw_plugin in ('obfs-local', 'simple-obfs', 'obfs'):
                    node['plugin'] = 'obfs'
                    m = opts.get('obfs') or opts.get('mode') or 'http'
                    h = opts.get('obfs-host') or opts.get('host') or ''
                    node['plugin-opts'] = {'mode': m}
                    if h:
                        node['plugin-opts']['host'] = h
                elif raw_plugin in ('v2ray-plugin', 'v2ray'):
                    node['plugin'] = 'v2ray-plugin'
                    v_opts = dict(opts)
                    if 'mode' not in v_opts:
                        v_opts['mode'] = 'websocket'
                    node['plugin-opts'] = v_opts
                else:
                    return None
            if 'cipher' in node and node['server'] and node['port']:
                return node

        elif scheme in ('socks5', 'socks'):
            return None

        elif scheme == 'snell':
            return {
                'name': name,
                'type': 'snell',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 443),
                'psk': p.username or '',
                'version': int(qs.get('version', ['4'])[0]),
                'obfs-opts': {'mode': qs.get('obfs', ['tls'])[0]}
            }

        elif scheme in ('wireguard', 'wg'):
            return {
                'name': name,
                'type': 'wireguard',
                'server': str(p.hostname or '').strip(),
                'port': int(p.port or 51820),
                'ip': qs.get('ip', ['10.0.0.2'])[0],
                'public-key': qs.get('public_key', [''])[0],
                'private-key': p.username or '',
                'preshared-key': qs.get('preshared_key', [''])[0],
                'udp': True
            }

        elif scheme in ('https', 'http'):
            return None

    except Exception:
        pass
    return None

def load_source(source_info, source_id: int = 1, max_size_mb: int = 30):
    req_headers = dict(HEADERS)
    if isinstance(source_info, str):
        raw_url = source_info.strip()
        name = raw_url.split('/')[-1]
    elif isinstance(source_info, dict):
        raw_url = source_info.get('url', '').strip()
        name = source_info.get('name', raw_url.split('/')[-1])
        headers_cfg = source_info.get('header') or source_info.get('headers') or {}
        if isinstance(headers_cfg, dict):
            for k, v in headers_cfg.items():
                if isinstance(v, list) and v:
                    req_headers[k] = str(v[0])
                elif v is not None:
                    req_headers[k] = str(v)
    else:
        return [], None

    url = normalize_url(raw_url)
    if not url:
        return [], raw_url

    print(f"[*] Сбор подписки [{source_id}]: {name}")
    try:
        max_bytes = max_size_mb * 1024 * 1024
        with requests.get(url, headers=req_headers, timeout=25, stream=True) as r:
            r.raise_for_status()
            raw_chunks = bytearray()
            exceeded = False
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    raw_chunks.extend(chunk)
                if len(raw_chunks) > max_bytes:
                    exceeded = True
                    break
            if exceeded:
                print(f"    [!] Превышен лимит размера источника ({max_size_mb} МБ)")
                return [], raw_url
            content = raw_chunks.decode('utf-8', errors='ignore').lstrip('\ufeff')
    except Exception as e:
        print(f"    [!] Пропуск ({e})")
        return [], raw_url

    nodes = []

    if "proxies:" in content:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
                for p in data['proxies']:
                    if isinstance(p, dict) and 'server' in p and 'port' in p:
                        try:
                            p['port'] = int(p['port'])
                            p['server'] = str(p['server']).strip()
                            p['_src_id'] = source_id
                            for k in ('dialer-proxy', 'interface-name', 'routing-mark', 'ip-version', 'smux', 'tfo', 'mptcp', 'udp-over-tcp', 'fast-open'):
                                p.pop(k, None)
                            nodes.append(p)
                        except (ValueError, TypeError):
                            pass
                print(f"    [+] Найдено {len(nodes)} прокси (YAML)")
                return nodes, None
        except Exception:
            pass

    if content.strip().startswith('{') and '"outbounds"' in content:
        try:
            sb_data = json.loads(content)
            sb_nodes = parse_singbox_outbounds(sb_data)
            for p in sb_nodes:
                p['_src_id'] = source_id
                nodes.append(p)
            if nodes:
                print(f"    [+] Найдено {len(nodes)} прокси (Sing-box JSON)")
                return nodes, None
        except Exception:
            pass

    first_chunk = content[:1000].lstrip()
    is_plain = any(first_chunk.startswith(p) for p in ('#', 'vmess://', 'vless://', 'ss://', 'trojan://', 'hy2://', 'hysteria2://', 'tuic://', 'hysteria://', 'ssr://', 'socks5://', 'snell://', 'wireguard://', 'wg://'))
    if not is_plain:
        stripped = content.strip().replace('\r', '').replace('\n', '')
        try:
            decoded = safe_b64decode(stripped)
            if "proxies:" in decoded:
                data = yaml.safe_load(decoded)
                if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
                    for p in data['proxies']:
                        if isinstance(p, dict) and 'server' in p and 'port' in p:
                            try:
                                p['port'] = int(p['port'])
                                p['server'] = str(p['server']).strip()
                                p['_src_id'] = source_id
                                for k in ('dialer-proxy', 'interface-name', 'routing-mark', 'ip-version', 'smux', 'tfo', 'mptcp', 'udp-over-tcp', 'fast-open'):
                                    p.pop(k, None)
                                nodes.append(p)
                            except (ValueError, TypeError):
                                pass
                    print(f"    [+] Найдено {len(nodes)} прокси (Base64 YAML)")
                    return nodes, None
            elif any(proto in decoded for proto in ('vless://', 'vmess://', 'ss://', 'hy2://', 'hysteria2://', 'trojan://', 'tuic://', 'hysteria://', 'ssr://', 'socks5://', 'snell://', 'wireguard://', 'wg://')):
                content = decoded
        except Exception:
            pass

    for line in content.splitlines():
        node = parse_raw_link(line)
        if node and node.get('server') and node.get('port'):
            node['_src_id'] = source_id
            nodes.append(node)

    print(f"    [+] Найдено {len(nodes)} прокси (Строки)")
    return nodes, None

COUNTRY_NAMES_RU = {
    'US': 'США', 'DE': 'Германия', 'NL': 'Нидерланды', 'FR': 'Франция',
    'GB': 'Великобритания', 'SE': 'Швеция', 'RU': 'Россия', 'FI': 'Финляндия',
    'PL': 'Польша', 'TR': 'Турция', 'SG': 'Сингапур', 'JP': 'Япония',
    'KR': 'Южная Корея', 'CA': 'Канада', 'IT': 'Италия', 'ES': 'Испания',
    'CH': 'Швейцария', 'AT': 'Австрия', 'AL': 'Албания', 'KZ': 'Казахстан',
    'BY': 'Беларусь', 'UA': 'Украина', 'EE': 'Эстония', 'LV': 'Латвия',
    'LT': 'Литва', 'MD': 'Молдова', 'GE': 'Грузия', 'AM': 'Армения',
    'AZ': 'Азербайджан', 'UZ': 'Узбекистан', 'KG': 'Кыргызстан', 'TJ': 'Таджикистан',
    'AE': 'ОАЭ', 'IL': 'Израиль', 'IN': 'Индия', 'HK': 'Гонконг',
    'TW': 'Тайвань', 'AU': 'Австралия', 'NZ': 'Новая Зеландия', 'BR': 'Бразилия',
    'AR': 'Аргентина', 'CL': 'Чили', 'ZA': 'ЮАР', 'NO': 'Норвегия',
    'DK': 'Дания', 'IS': 'Исландия', 'IE': 'Ирландия', 'BE': 'Бельгия',
    'LU': 'Люксембург', 'PT': 'Португалия', 'GR': 'Греция', 'CY': 'Кипр',
    'BG': 'Болгария', 'RO': 'Румыния', 'HU': 'Венгрия', 'CZ': 'Чехия',
    'SK': 'Словакия', 'SI': 'Словения', 'HR': 'Хорватия', 'RS': 'Сербия',
    'BA': 'Босния', 'ME': 'Черногория', 'MK': 'Северная Македония',
    'UN': 'Неизвестно'
}

GEOIP_CACHE = {}

def make_node_fingerprint(node: dict) -> tuple:
    server = str(node.get('server', '')).strip().lower()
    port = int(node.get('port', 0))
    ptype = str(node.get('type', '')).strip().lower()
    net = str(node.get('network') or 'tcp').strip().lower()
    cred = str(node.get('uuid') or node.get('password') or node.get('auth-str') or node.get('psk') or '').strip()
    sni = str(node.get('servername') or node.get('sni') or '').strip().lower()
    flow = str(node.get('flow', '')).strip().lower()
    ws_path = str((node.get('ws-opts') or {}).get('path') or '').strip()
    ws_host = str(((node.get('ws-opts') or {}).get('headers') or {}).get('Host') or ((node.get('ws-opts') or {}).get('headers') or {}).get('host') or '').strip().lower()
    grpc_service = str((node.get('grpc-opts') or {}).get('grpc-service-name') or '').strip()
    xhttp_path = str((node.get('xhttp-opts') or {}).get('path') or '').strip()
    xhttp_host = str((node.get('xhttp-opts') or {}).get('host') or '').strip().lower()
    xhttp_mode = str((node.get('xhttp-opts') or {}).get('mode') or '').strip().lower()
    ro = node.get('reality-opts') if isinstance(node.get('reality-opts'), dict) else {}
    pbk = str(ro.get('public-key') or '').strip()
    sid = str(ro.get('short-id') or '').strip().lower()
    spx = str(ro.get('spider-x') or '').strip()
    ss_cipher = str(node.get('cipher') or '').strip().lower()
    ss_plugin = str(node.get('plugin') or '').strip().lower()
    ss_opts = tuple(sorted((str(k).lower(), str(v)) for k, v in (node.get('plugin-opts') or {}).items()))
    obfs = str(node.get('obfs') or '').strip().lower()
    obfs_pw = str(node.get('obfs-password') or '').strip()

    return (
        server, port, ptype, net, cred, sni, flow,
        ws_path, ws_host, grpc_service,
        xhttp_path, xhttp_host, xhttp_mode,
        pbk, sid, spx,
        ss_cipher, ss_plugin, ss_opts,
        obfs, obfs_pw
    )

def deduplicate_nodes(nodes: list) -> list:
    seen = {}
    unique = []
    invalid_addrs = 0
    duplicates = 0
    filtered_proto = 0
    for n in nodes:
        ptype = str(n.get('type', '')).strip().lower()
        if ptype in ('vmess', 'openvpn', 'ovpn'):
            filtered_proto += 1
            continue

        server = str(n.get('server', '')).strip().lower()
        try:
            port = int(n.get('port', 0))
        except (ValueError, TypeError):
            invalid_addrs += 1
            continue

        if not server or port <= 0 or is_forbidden_host(server):
            invalid_addrs += 1
            continue

        key = make_node_fingerprint(n)
        if key in seen:
            duplicates += 1
            existing = seen[key]
            src_id = n.get('_src_id')
            if src_id:
                if '_src_ids' not in existing:
                    existing['_src_ids'] = {existing.get('_src_id')} if existing.get('_src_id') else set()
                existing['_src_ids'].add(src_id)
        else:
            seen[key] = n
            if n.get('_src_id'):
                n['_src_ids'] = {n['_src_id']}
            unique.append(n)

    print(f"[*] Этап 1: Дедупликация и очистка адресов:")
    print(f"    - Поступило с источников: {len(nodes)}")
    if invalid_addrs > 0:
        print(f"    - Отсеяно некорректных адресов/портов: {invalid_addrs}")
    if filtered_proto > 0:
        print(f"    - Отсеяно нежелательных протоколов (OpenVPN/VMess): {filtered_proto}")
    print(f"    - Отсеяно прямых дубликатов серверов: {duplicates}")
    print(f"    - Оставлено уникальных серверов: {len(unique)}")
    return unique

def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2 or code == 'UN':
        return '🌐'
    try:
        return chr(127397 + ord(code[0].upper())) + chr(127397 + ord(code[1].upper()))
    except Exception:
        return '🌐'

HOST_RESOLVE_CACHE = {}

def resolve_host_to_ip(host: str) -> str:
    host = str(host or '').strip().strip('[]').rstrip('.')
    if is_forbidden_host(host):
        return None
    if host in HOST_RESOLVE_CACHE:
        return HOST_RESOLVE_CACHE[host]
    try:
        ip = ipaddress.ip_address(host)
        res = host if ip.is_global else None
        HOST_RESOLVE_CACHE[host] = res
        return res
    except ValueError:
        pass
    try:
        for fam, *_, sa in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            try:
                ip = ipaddress.ip_address(sa[0])
                if ip.is_global:
                    HOST_RESOLVE_CACHE[host] = sa[0]
                    return sa[0]
            except ValueError:
                pass
    except (socket.gaierror, Exception):
        pass
    HOST_RESOLVE_CACHE[host] = None
    return None

def extract_geo_from_node(node: dict) -> tuple:
    orig_name = str(node.get('_original_name') or node.get('name') or '').strip()
    m = re.search(r'([\U0001F1E6-\U0001F1FF]{2})', orig_name)
    if m:
        flag = m.group(1)
        cc = "".join(chr(ord(c) - 127397) for c in flag).upper()
        cname = COUNTRY_NAMES_RU.get(cc, cc)
        return cc, cname, flag

    server = str(node.get('server', '')).strip().lower()
    parts = server.split('.')
    if len(parts) >= 2:
        tld = parts[-1]
        if len(tld) == 2 and tld.isalpha() and tld not in ('io', 'me', 'co', 'to', 'cc', 'tv', 'ws', 'sh'):
            cc = tld.upper()
            cname = COUNTRY_NAMES_RU.get(cc, cc)
            return cc, cname, country_code_to_flag(cc)
    return None, None, '🌐'

def batch_lookup_ip_geo(ip_list: list) -> dict:
    results = {}
    missing_ips = []
    for ip in ip_list:
        if not ip:
            continue
        if ip in GEOIP_CACHE:
            results[ip] = GEOIP_CACHE[ip]
        else:
            missing_ips.append(ip)

    chunk_size = 100
    for i in range(0, len(missing_ips), chunk_size):
        chunk = missing_ips[i:i + chunk_size]
        try:
            req_data = [{"query": ip, "fields": "status,countryCode,country,query"} for ip in chunk]
            resp = requests.post("http://ip-api.com/batch?lang=ru", json=req_data, timeout=8)
            if resp.status_code == 200:
                for item in resp.json():
                    q_ip = item.get('query')
                    if item.get('status') == 'success':
                        cc = (item.get('countryCode') or '').upper()
                        cname = COUNTRY_NAMES_RU.get(cc) or item.get('country', '')
                        if cname:
                            cname = re.split(r'[,(]', cname)[0].strip()
                        GEOIP_CACHE[q_ip] = (cc, cname)
                        results[q_ip] = (cc, cname)
                    else:
                        GEOIP_CACHE[q_ip] = ('UN', 'Неизвестно')
                        results[q_ip] = ('UN', 'Неизвестно')
        except Exception:
            pass
        if i + chunk_size < len(missing_ips):
            time.sleep(4)

    return results

def lookup_ip_geo(ip: str) -> tuple:
    if not ip:
        return 'UN', 'Неизвестно'
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
    try:
        r = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=4)
        if r.status_code == 200:
            data = r.json()
            cc = data.get('countryCode', '').upper()
            cname = COUNTRY_NAMES_RU.get(cc) or data.get('countryName', '')
            if cname:
                cname = re.split(r'[,(]', cname)[0].strip()
            GEOIP_CACHE[ip] = (cc, cname)
            return cc, cname
    except Exception:
        pass
    GEOIP_CACHE[ip] = ('UN', 'Неизвестно')
    return 'UN', 'Неизвестно'

def format_final_proxy_names(nodes: list):
    country_totals = {}
    for n in nodes:
        c = n.get('_cname', 'Неизвестно')
        country_totals[c] = country_totals.get(c, 0) + 1

    country_counters = {}
    for n in nodes:
        c = n.get('_cname', 'Неизвестно')
        flag = n.get('_flag') or country_code_to_flag(n.get('_cc', 'UN'))
        country_counters[c] = country_counters.get(c, 0) + 1
        num = country_counters[c]
        if country_totals[c] > 1:
            n['name'] = f"{flag} {c} {num:02d}"
        else:
            n['name'] = f"{flag} {c}"

def filter_by_quotas(nodes: list, settings: dict = None, is_candidate: bool = False) -> tuple:
    settings = settings or {}
    per_proto = int(settings.get('per_country_proto', 8))
    max_per_country = int(settings.get('max_per_country', 15))
    max_total = int(settings.get('max_total', 300))
    if is_candidate:
        per_proto = int(per_proto * 1.5)
        max_per_country = int(max_per_country * 1.5)
        max_total = int(max_total * 1.5)

    per_cp, per_c, best_nodes = {}, {}, []
    per_proto_dropped = 0
    max_country_dropped = 0
    max_total_dropped = 0
    for node in nodes:
        cc = node.get('_cc', 'UN')
        proto = str(node.get('type', '')).lower()
        if per_cp.get((cc, proto), 0) >= per_proto:
            per_proto_dropped += 1
            continue
        if per_c.get(cc, 0) >= max_per_country:
            max_country_dropped += 1
            continue
        if len(best_nodes) >= max_total:
            max_total_dropped += 1
            continue
        per_cp[(cc, proto)] = per_cp.get((cc, proto), 0) + 1
        per_c[cc] = per_c.get(cc, 0) + 1
        best_nodes.append(node)

    stats = {
        'per_proto_dropped': per_proto_dropped,
        'max_country_dropped': max_country_dropped,
        'max_total_dropped': max_total_dropped,
    }
    return best_nodes, stats

def assign_clean_country_names(working_nodes: list, settings: dict = None, is_candidate: bool = False) -> tuple:
    settings = settings or {}

    if not working_nodes:
        return [], {'per_proto_dropped': 0, 'max_country_dropped': 0, 'max_total_dropped': 0}

    print(f"[*] Этап 4: Определение геолокации и подготовка кандидатов:")
    print(f"    - Поступило на гео-анализ: {len(working_nodes)}")

    ips_to_query = list({n.get('_ip') for n in working_nodes if n.get('_ip')})
    if ips_to_query:
        print(f"    - Пакетный GeoIP-анализ по IP ({len(ips_to_query)} адресов)...")
        geo_map = batch_lookup_ip_geo(ips_to_query)
    else:
        geo_map = {}

    for node in working_nodes:
        ip = node.get('_ip')
        cc, cname = geo_map.get(ip, (None, None))
        flag = None
        if cc and cc != 'UN':
            flag = country_code_to_flag(cc)
        else:
            f_cc, f_cname, f_flag = extract_geo_from_node(node)
            if f_cc and f_cc != 'UN':
                cc, cname, flag = f_cc, f_cname, f_flag
            elif ip:
                cc, cname = lookup_ip_geo(ip)
                flag = country_code_to_flag(cc) if cc and cc != 'UN' else '🌐'

        if not cc or cc == 'UN':
            cc = 'UN'
            cname = 'Неизвестно'
            flag = '🌐'

        node['_cc'] = cc
        node['_cname'] = cname
        node['_flag'] = flag

    working_nodes.sort(key=lambda x: x.get('_score_delay', x.get('_delay', 9999)))

    best_nodes, geo_stats = filter_by_quotas(working_nodes, settings, is_candidate=is_candidate)
    format_final_proxy_names(best_nodes)

    per_proto = int(settings.get('per_country_proto', 8))
    max_per_country = int(settings.get('max_per_country', 15))
    max_total = int(settings.get('max_total', 300))
    if is_candidate:
        per_proto = int(per_proto * 1.5)
        max_per_country = int(max_per_country * 1.5)
        max_total = int(max_total * 1.5)

    print(f"    - Отсеяно дубликатов протокола в одной стране (лимит {per_proto}): {geo_stats['per_proto_dropped']}")
    print(f"    - Отсеяно по превышению лимита на страну (лимит {max_per_country}): {geo_stats['max_country_dropped']}")
    if geo_stats['max_total_dropped'] > 0:
        print(f"    - Отсеяно по превышению общего лимита (лимит {max_total}): {geo_stats['max_total_dropped']}")
    else:
        print(f"    - Отсеяно по превышению общего лимита (лимит {max_total}): 0")
    print(f"    - Отобрано уникальных узлов: {len(best_nodes)}")

    return best_nodes, geo_stats

def run_speed_test_finalists(finalists: list, settings: dict, mihomo_bin: str = "./mihomo") -> list:
    if not finalists:
        return []

    if not os.path.exists(mihomo_bin):
        if shutil.which("mihomo"):
            mihomo_bin = "mihomo"
        else:
            return finalists

    speed_url = settings.get('speed_test_url', 'https://speed.cloudflare.com/__down?bytes=300000')
    target_bytes = 300000
    if 'bytes=' in speed_url:
        try:
            m = re.search(r'bytes=(\d+)', speed_url)
            if m:
                target_bytes = int(m.group(1))
        except Exception:
            target_bytes = 300000
    min_bytes = int(target_bytes / 3)
    timeout_sec = int(settings.get('speed_test_timeout_sec', 8))
    max_workers = int(settings.get('speed_test_workers', 8))
    num_workers = min(max_workers, len(finalists))
    if num_workers < 1:
        num_workers = 1

    worker_buckets = [[] for _ in range(num_workers)]
    for idx, node in enumerate(finalists):
        worker_buckets[idx % num_workers].append(node)

    print(f"[*] Этап 5: Параллельный спид-тест финалистов ({num_workers} воркеров, тест {target_bytes // 1024} КБ, отсев <{min_bytes // 1024} КБ за {timeout_sec} с):")

    passed = []
    print_lock = threading.Lock()
    tested_counter = 0
    total_nodes = len(finalists)

    def worker_job(worker_id: int, nodes: list) -> list:
        nonlocal tested_counter
        if not nodes:
            return []

        mixed_port = 18000 + worker_id
        socks_port = 18100 + worker_id
        controller_port = 19100 + worker_id
        cfg_path = f"temp_speed_cfg_{worker_id}.yaml"

        clean_proxies = []
        for n in nodes:
            clean_p = {k: v for k, v in n.items() if not k.startswith('_') and v is not None}
            clean_p['name'] = n.get('_test_id') or f"node_{worker_id}_{id(n)}"
            if clean_p.get('network') in ('raw', 'none', ''):
                clean_p['network'] = 'tcp'
            if clean_p.get('tls') or 'reality-opts' in clean_p or clean_p.get('type') in ('vless', 'trojan', 'hysteria2', 'tuic'):
                if not clean_p.get('client-fingerprint'):
                    clean_p['client-fingerprint'] = 'firefox'
            clean_proxies.append(clean_p)

        test_config = {
            'port': mixed_port,
            'socks-port': socks_port,
            'mode': 'global',
            'log-level': 'silent',
            'external-controller': f"127.0.0.1:{controller_port}",
            'secret': '',
            'proxies': clean_proxies
        }

        proc = None
        local_passed = []
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                yaml.dump(test_config, f, allow_unicode=True)

            proc = subprocess.Popen([mihomo_bin, "-d", ".", "-f", cfg_path],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            ready = False
            for _ in range(50):
                time.sleep(0.1)
                try:
                    res = requests.get(f"http://127.0.0.1:{controller_port}/version", timeout=0.5)
                    if res.status_code == 200:
                        ready = True
                        break
                except Exception:
                    pass
                if proc.poll() is not None:
                    break

            if not ready:
                with print_lock:
                    print(f"    [!] Воркер #{worker_id} не запустился, пропускаем {len(nodes)} узлов")
                return []

            proxies_dict = {
                'http': f'http://127.0.0.1:{mixed_port}',
                'https': f'http://127.0.0.1:{mixed_port}'
            }

            for node in nodes:
                tid = node.get('_test_id') or f"node_{worker_id}_{id(node)}"
                name_display = node.get('name') or node.get('_original_name') or tid
                speed_kbps = 0.0
                success = False
                downloaded = 0
                elapsed = 0.0
                try:
                    requests.put(f"http://127.0.0.1:{controller_port}/proxies/GLOBAL", json={'name': tid}, timeout=2)
                    time.sleep(0.03)

                    start_time = time.time()
                    downloaded = 0
                    try:
                        with requests.Session() as s:
                            s.trust_env = False
                            with s.get(speed_url, proxies=proxies_dict, timeout=(3.0, timeout_sec), stream=True, headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'}) as r:
                                if r.status_code in (200, 206):
                                    for chunk in r.iter_content(chunk_size=8192):
                                        if chunk:
                                            downloaded += len(chunk)
                                        if downloaded >= target_bytes:
                                            break
                                        if time.time() - start_time > timeout_sec:
                                            break
                    except Exception:
                        pass

                    elapsed = time.time() - start_time
                    if downloaded >= min_bytes and elapsed > 0:
                        speed_kbps = round((downloaded / 1024.0) / elapsed, 1)
                        success = True

                    if success:
                        node['_speed'] = speed_kbps
                        local_passed.append(node)

                    with print_lock:
                        tested_counter += 1
                        if success:
                            print(f"    [{tested_counter}/{total_nodes}] {name_display}: {speed_kbps} КБ/с ({round(downloaded/1024)} КБ за {round(elapsed, 2)} с) - [OK]")
                        else:
                            print(f"    [{tested_counter}/{total_nodes}] {name_display}: отсев (<{min_bytes // 1024} КБ за {timeout_sec} с)")
                except Exception as e:
                    with print_lock:
                        tested_counter += 1
                        print(f"    [{tested_counter}/{total_nodes}] {name_display}: отсев (ошибка: {e})")

        finally:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            try:
                if os.path.exists(cfg_path):
                    os.remove(cfg_path)
            except Exception:
                pass

        return local_passed

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(worker_job, wid, bucket) for wid, bucket in enumerate(worker_buckets) if bucket]
        for f in as_completed(futures):
            res = f.result()
            if res:
                passed.extend(res)

    if not passed and finalists:
        print("[!] Предупреждение: Спид-тест не пропустил узлы. Сохраняем исходный пул финалистов.")
        passed = finalists
    else:
        passed.sort(key=lambda x: x.get('_score_delay', x.get('_delay', 9999)))

    return passed

def run_health_checks(nodes: list, settings: dict) -> tuple:
    empty_stats = {
        'invalid_configs': 0,
        'tested_count': 0,
        'dead_count': 0,
        'dead_base': 0,
        'dead_yt': 0,
        'dead_tg': 0,
        'dead_cf': 0,
        'alive_count': 0,
        'high_ping_count': 0,
        'passed_ping_count': 0,
        'per_proto_dropped': 0,
        'max_country_dropped': 0,
        'max_total_dropped': 0
    }
    if not nodes:
        return [], empty_stats

    mihomo_bin = "./mihomo"
    if not os.path.exists(mihomo_bin):
        if shutil.which("mihomo"):
            mihomo_bin = "mihomo"
        else:
            print("[!] Ошибка: Ядро Mihomo не найдено. Проверка невозможна.")
            return [], empty_stats

    test_url = settings.get('test_url', 'http://www.gstatic.com/generate_204')
    timeout_ms = settings.get('test_timeout_ms', 3000)
    concurrency = settings.get('max_concurrent_checks', 80)

    valid_types = {'ss', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'wireguard', 'snell'}

    distinct_hosts = {
        str(n.get('server', '')).strip().strip('[]').rstrip('.')
        for n in nodes
        if str(n.get('type', '')).lower() in valid_types and n.get('server')
    }
    distinct_hosts = {h for h in distinct_hosts if h and not is_forbidden_host(h)}
    if distinct_hosts:
        with ThreadPoolExecutor(max_workers=40) as pool:
            list(pool.map(resolve_host_to_ip, distinct_hosts))

    clean_proxies = []
    valid_nodes = []
    for idx, n in enumerate(nodes):
        ptype = str(n.get('type', '')).lower()
        if ptype not in valid_types:
            continue

        server = str(n.get('server', '')).strip()
        if not server or ' ' in server or '\t' in server or '\n' in server or '\r' in server or is_forbidden_host(server):
            continue
        resolved_ip = resolve_host_to_ip(server)
        if not resolved_ip:
            continue
        n['_ip'] = resolved_ip
        try:
            port = int(n.get('port', 0))
            if not (1 <= port <= 65535):
                continue
        except (ValueError, TypeError):
            continue

        n['server'] = server
        n['port'] = port

        net_val = str(n.get('network') or 'tcp').lower()
        if net_val in ('raw', 'none', ''):
            net_val = 'tcp'
        if net_val not in ('tcp', 'ws', 'grpc', 'h2', 'http', 'xhttp'):
            continue

        if ptype == 'ss':
            c = str(n.get('cipher', '')).lower().replace('–', '-').replace('—', '-').strip()
            if c == 'chacha20-poly1305':
                c = 'chacha20-ietf-poly1305'
            valid_ss_ciphers = {
                'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
                'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
                '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                '2022-blake3-chacha20-poly1305',
                'chacha8-ietf-poly1305', 'xchacha8-ietf-poly1305',
                '2022-blake3-chacha8-poly1305',
                'aes-128-gcm-siv', 'aes-256-gcm-siv',
                'aegis-128l', 'aegis-256',
                'lea-128-gcm', 'lea-192-gcm', 'lea-256-gcm',
                'ascon128', 'ascon128a'
            }
            if c not in valid_ss_ciphers:
                continue
            pwd = str(n.get('password', '')).strip()
            if not pwd or '\n' in pwd or '\r' in pwd or len(pwd) > 500:
                continue
            n['cipher'] = c
            n['password'] = pwd
            plugin = str(n.get('plugin', '')).lower().strip()
            if plugin:
                if plugin == 'obfs-local':
                    plugin = 'obfs'
                    n['plugin'] = 'obfs'
                if plugin not in ('obfs', 'v2ray-plugin'):
                    continue

        elif ptype == 'vmess':
            uid = str(n.get('uuid', '')).strip().lower()
            if len(uid) not in (32, 36) or not re.match(r'^[0-9a-fA-F-]+$', uid):
                continue
            n['uuid'] = uid
            c = str(n.get('cipher', '')).lower().strip()
            if c not in ('auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'):
                n['cipher'] = 'auto'
            if not n.get('tls'):
                continue
            if n.get('network') not in ('tcp', 'ws', 'grpc', 'h2', 'http', 'xhttp'):
                n['network'] = 'tcp'
            if n.get('network') != 'ws':
                n.pop('ws-opts', None)
            if n.get('network') != 'grpc':
                n.pop('grpc-opts', None)
            if n.get('network') != 'h2':
                n.pop('h2-opts', None)
            if n.get('network') != 'xhttp':
                n.pop('xhttp-opts', None)
        elif ptype == 'vless':
            uid = str(n.get('uuid', '')).strip().lower()
            if len(uid) not in (32, 36) or not re.match(r'^[0-9a-fA-F-]+$', uid):
                continue
            n['uuid'] = uid
            if not n.get('tls') and 'reality-opts' not in n:
                continue
            if 'reality-opts' in n:
                pbk = str((n['reality-opts'] or {}).get('public-key', '')).strip()
                if len(pbk) < 32:
                    del n['reality-opts']
            if n.get('network') not in ('tcp', 'ws', 'grpc', 'h2', 'http', 'xhttp'):
                n['network'] = 'tcp'
            if n.get('network') != 'ws':
                n.pop('ws-opts', None)
            if n.get('network') != 'grpc':
                n.pop('grpc-opts', None)
            if n.get('network') != 'h2':
                n.pop('h2-opts', None)
            if n.get('network') != 'xhttp':
                n.pop('xhttp-opts', None)
            if n.get('network') != 'tcp':
                n.pop('flow', None)
        elif ptype == 'trojan':
            pwd = str(n.get('password', '')).strip()
            if not pwd or '\n' in pwd or '\r' in pwd:
                continue
            n['password'] = pwd
            if 'reality-opts' in n:
                pbk = str((n['reality-opts'] or {}).get('public-key', '')).strip()
                if len(pbk) < 32:
                    del n['reality-opts']
            if n.get('network') not in ('tcp', 'ws', 'grpc', 'h2', 'http', 'xhttp'):
                n['network'] = 'tcp'
            if n.get('network') != 'ws':
                n.pop('ws-opts', None)
            if n.get('network') != 'grpc':
                n.pop('grpc-opts', None)
            if n.get('network') != 'h2':
                n.pop('h2-opts', None)
            if n.get('network') != 'xhttp':
                n.pop('xhttp-opts', None)
        elif ptype in ('hy2', 'hysteria2'):
            n['type'] = 'hysteria2'
            pwd = str(n.get('password', '')).strip()
            if not pwd or '\n' in pwd or '\r' in pwd:
                continue
            n['password'] = pwd
        elif ptype in ('hy', 'hysteria'):
            n['type'] = 'hysteria'
            if not n.get('auth-str'):
                continue
            up_val = str(n.get('up', '')).strip()
            down_val = str(n.get('down', '')).strip()
            if not up_val:
                up_val = '50 Mbps'
            elif up_val.isdigit():
                up_val = f"{up_val} Mbps"
            if not down_val:
                down_val = '100 Mbps'
            elif down_val.isdigit():
                down_val = f"{down_val} Mbps"
            n['up'] = up_val
            n['down'] = down_val
        elif ptype == 'tuic':
            if not n.get('uuid') or not n.get('password'):
                continue
        elif ptype == 'snell':
            if not n.get('psk'):
                continue
        elif ptype == 'wireguard':
            if not n.get('public-key') or not n.get('private-key'):
                continue
        else:
            continue

        n['_test_id'] = f"test_node_{idx:05d}"
        n['_original_name'] = n.get('name', f"Server-{idx}").strip()
        n['name'] = n['_test_id']
        clean_p = {k: v for k, v in n.items() if not k.startswith('_') and v is not None}
        if clean_p.get('network') in ('raw', 'none', ''):
            clean_p['network'] = 'tcp'
        if 'fingerprint' in clean_p:
            fp_val = str(clean_p.pop('fingerprint', '')).strip()
            if fp_val and 'client-fingerprint' not in clean_p:
                clean_p['client-fingerprint'] = fp_val
        if clean_p.get('tls') or 'reality-opts' in clean_p or clean_p.get('type') in ('vless', 'trojan', 'hysteria2', 'tuic'):
            if not clean_p.get('client-fingerprint'):
                clean_p['client-fingerprint'] = 'firefox'
        clean_proxies.append(clean_p)
        valid_nodes.append(n)

    invalid_configs = len(nodes) - len(valid_nodes)
    print(f"[*] Этап 2: Валидация протоколов перед проверкой ядра:")
    print(f"    - Поступило на валидацию: {len(nodes)}")
    print(f"    - Отсеяно с поврежденными/неполными параметрами: {invalid_configs}")
    print(f"    - Допущено к тестированию через ядро: {len(valid_nodes)}")

    if not valid_nodes:
        return [], empty_stats

    test_config = {
        'port': 17890,
        'socks-port': 17891,
        'mode': 'global',
        'log-level': 'silent',
        'external-controller': '127.0.0.1:19090',
        'secret': '',
        'proxies': clean_proxies
    }

    config_path = "temp_mihomo_config.yaml"
    ready = False
    proc = None
    max_retries = 50

    for attempt in range(max_retries):
        if not clean_proxies:
            break
        test_config['proxies'] = clean_proxies
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(test_config, f, allow_unicode=True)

        if attempt == 0:
            print(f"[*] Запуск ядра JustClash ({mihomo_bin}) для тестирования {len(clean_proxies)} серверов...")
        else:
            print(f"[*] Перезапуск ядра после удаления поврежденных узлов ({len(clean_proxies)} серверов)...")

        log_file = open("mihomo.log", "w", encoding="utf-8")
        proc = subprocess.Popen([mihomo_bin, "-d", ".", "-f", config_path],
                                stdout=log_file, stderr=subprocess.STDOUT)

        ready = False
        for _ in range(60):
            time.sleep(0.2)
            try:
                res = requests.get("http://127.0.0.1:19090/version", timeout=1)
                if res.status_code == 200:
                    ready = True
                    break
            except Exception:
                pass
            if proc.poll() is not None:
                break

        log_file.flush()
        log_file.close()

        if ready:
            break

        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()

        error_log = ""
        try:
            with open("mihomo.log", "r", encoding="utf-8") as rf:
                error_log = rf.read()
        except Exception:
            pass

        bad_indices = set()
        for m in re.finditer(r"Parse config error:\s*proxy\s*(\d+):", error_log):
            bad_indices.add(int(m.group(1)))
        if bad_indices:
            for bad_idx in sorted(bad_indices, reverse=True):
                if 0 <= bad_idx < len(clean_proxies):
                    bad_node = clean_proxies.pop(bad_idx)
                    if bad_idx < len(valid_nodes):
                        valid_nodes.pop(bad_idx)
                    print(f"    [!] Удален несовместимый узел #{bad_idx}: {bad_node.get('name', bad_node.get('type'))}")
            continue

        print("[!] Ошибка: Контроллер Mihomo не ответил. Завершение.")
        if error_log:
            print("--- Mihomo Core Output ---")
            print(error_log[-2000:])
            print("--------------------------")
        break

    if not ready:
        try:
            if os.path.exists(config_path):
                os.remove(config_path)
            if os.path.exists("mihomo.log"):
                os.remove("mihomo.log")
        except Exception:
            pass
        return [], empty_stats

    alive_delays = {}
    dead_base = 0
    dead_yt = 0
    dead_tg = 0
    dead_cf = 0
    dead_count = 0
    high_ping_count = 0
    passed_ping_nodes = []

    try:
        print(f"[*] Этап 3: Активное тестирование доступности (Таймаут: {timeout_ms} мс, Потоков: {concurrency})...")

        verify_url = settings.get('verify_url', 'https://cp.cloudflare.com/generate_204')
        strict = bool(settings.get('strict_check', True))
        alt_url = "http://connect.rom.miui.com/generate_204"

        youtube_url = settings.get('youtube_url', 'https://redirector.googlevideo.com/report_mapping?di=no')
        yt_alt = "https://www.youtube.com/generate_204"
        telegram_url = settings.get('telegram_url', 'https://web.telegram.org')
        tg_alt = "https://api.telegram.org"
        check_yt = bool(settings.get('check_youtube', True))
        check_tg = bool(settings.get('check_telegram', True))

        def api_delay(tid, url):
            try:
                resp = requests.get(
                    f"http://127.0.0.1:19090/proxies/{urllib.parse.quote(tid)}/delay",
                    params={'timeout': timeout_ms, 'url': url},
                    timeout=(timeout_ms / 1000.0) + 1.5)
                if resp.status_code == 200:
                    d = resp.json().get('delay', 0)
                    if d and d > 0:
                        return d
            except Exception:
                pass
            return None

        def test_single_node(node):
            tid = node['_test_id']
            d_base = api_delay(tid, test_url) or api_delay(tid, alt_url)
            if d_base is None:
                return tid, None, "dead_base", 0, 0
            d_yt = 0
            if check_yt:
                d_yt = api_delay(tid, youtube_url) or api_delay(tid, yt_alt)
                if not d_yt:
                    return tid, None, "dead_yt", 0, 0
            d_tg = 0
            if check_tg:
                d_tg = api_delay(tid, telegram_url) or api_delay(tid, tg_alt)
                if not d_tg:
                    return tid, None, "dead_tg", 0, 0
            if strict:
                if not api_delay(tid, verify_url):
                    return tid, None, "dead_cf", 0, 0
            return tid, d_base, "ok", d_yt, d_tg


        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(test_single_node, n) for n in valid_nodes]
            for f in as_completed(futures):
                res = f.result()
                tid, delay, reason = res[0], res[1], res[2]
                d_yt = res[3] if len(res) > 3 else 0
                d_tg = res[4] if len(res) > 4 else 0
                if delay is not None:
                    alive_delays[tid] = (delay, d_yt, d_tg)
                else:
                    if reason == "dead_base":
                        dead_base += 1
                    elif reason == "dead_yt":
                        dead_yt += 1
                    elif reason == "dead_tg":
                        dead_tg += 1
                    elif reason == "dead_cf":
                        dead_cf += 1

        dead_count = len(valid_nodes) - len(alive_delays)
        print(f"      * Базовый коннект (Google/Xiaomi): {dead_base}")
        if check_yt:
            print(f"      * Недоступен YouTube: {dead_yt}")
        if check_tg:
            print(f"      * Недоступен Telegram: {dead_tg}")
        if strict:
            print(f"      * Недоступен Cloudflare: {dead_cf}")

        passed_ping_nodes = []
        for node in valid_nodes:
            tid = node['_test_id']
            if tid in alive_delays:
                delay, d_yt, d_tg = alive_delays[tid]
                node['_delay'] = delay
                valid_delays = [d for d in (delay, d_yt, d_tg) if d and d > 0]
                node['_score_delay'] = round(sum(valid_delays) / len(valid_delays)) if valid_delays else delay
                passed_ping_nodes.append(node)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        try:
            if os.path.exists(config_path):
                os.remove(config_path)
            if os.path.exists("mihomo.log"):
                os.remove("mihomo.log")
        except Exception:
            pass

    check_speed = bool(settings.get('check_speed', True))
    if check_speed and passed_ping_nodes:
        candidates, cand_stats = assign_clean_country_names(passed_ping_nodes, settings, is_candidate=True)
        speed_tested = run_speed_test_finalists(candidates, settings, mihomo_bin)
        speed_dropped = len(candidates) - len(speed_tested)
        final_nodes, final_geo_stats = filter_by_quotas(speed_tested, settings, is_candidate=False)
        format_final_proxy_names(final_nodes)
        geo_stats = {
            'per_proto_dropped': cand_stats.get('per_proto_dropped', 0) + final_geo_stats.get('per_proto_dropped', 0),
            'max_country_dropped': cand_stats.get('max_country_dropped', 0) + final_geo_stats.get('max_country_dropped', 0),
            'max_total_dropped': cand_stats.get('max_total_dropped', 0) + final_geo_stats.get('max_total_dropped', 0),
        }
    else:
        candidates = passed_ping_nodes
        speed_dropped = 0
        final_nodes, geo_stats = assign_clean_country_names(passed_ping_nodes, settings, is_candidate=False)

    total_dropped_in_checks = len(nodes) - len(final_nodes)
    print(f"[✅] Проверка завершена: отобрано {len(final_nodes)} рабочих серверов (всего отсеяно с начала проверки: {total_dropped_in_checks})")

    stats = {
        'invalid_configs': invalid_configs,
        'tested_count': len(valid_nodes),
        'dead_count': dead_count,
        'dead_base': dead_base,
        'dead_yt': dead_yt,
        'dead_tg': dead_tg,
        'dead_cf': dead_cf,
        'alive_count': len(alive_delays),
        'high_ping_count': high_ping_count,
        'passed_ping_count': len(passed_ping_nodes),
        'per_proto_dropped': geo_stats.get('per_proto_dropped', 0),
        'max_country_dropped': geo_stats.get('max_country_dropped', 0),
        'max_total_dropped': geo_stats.get('max_total_dropped', 0),
        'speed_dropped': speed_dropped,
        'speed_timeout_sec': int(settings.get('speed_test_timeout_sec', 8))
    }

    return final_nodes, stats

def main():
    if not os.path.exists("sources.yaml"):
        print("[!] Файл sources.yaml не найден!")
        sys.exit(1)

    with open("sources.yaml", "r", encoding="utf-8") as f:
        conf = yaml.safe_load(f)

    settings = conf.get('settings', {})
    sources = conf.get('sources', [])
    max_source_size_mb = int(settings.get('max_source_size_mb', 30))

    all_nodes = []
    failed_sources = []
    for idx, s in enumerate(sources, start=1):
        nodes, failed_url = load_source(s, source_id=idx, max_size_mb=max_source_size_mb)
        if failed_url:
            failed_sources.append(failed_url)
        all_nodes.extend(nodes)

    if not all_nodes:
        print("[!] Ошибка: Серверы не обнаружены.")
        sys.exit(1)

    unique_nodes = deduplicate_nodes(all_nodes)
    working_nodes, health_stats = run_health_checks(unique_nodes, settings)

    if not working_nodes:
        print("[!] Ошибка: Рабочие серверы не найдены. Предыдущий кэш сохранен.")
        sys.exit(1)

    os.makedirs("output", exist_ok=True)
    out_file = "output/proxies.yaml"

    prev_count = 0
    if os.path.exists(out_file):
        try:
            with open(out_file, 'r', encoding='utf-8') as pf:
                pdata = yaml.safe_load(pf) or {}
                prev_count = len(pdata.get('proxies', []))
        except Exception:
            pass

    force_update = os.environ.get("FORCE_UPDATE", "").lower() in ("true", "1", "yes")
    max_target = int(settings.get('max_total', 300))
    effective_baseline = min(prev_count, max_target)

    if not force_update and effective_baseline >= 20 and len(working_nodes) < int(effective_baseline * 0.5):
        print(f"[!] Ошибка: Порог регрессии ({len(working_nodes)} < 50% от порога {effective_baseline}). Предыдущий кэш сохранен.")
        sys.exit(1)

    clean_proxies = []
    for p in working_nodes:
        clean_p = {k: v for k, v in p.items() if not k.startswith('_') and v is not None}
        if p.get('_cc'):
            clean_p['country'] = p['_cc']
        if clean_p.get('type') not in ('vmess', 'ss', 'ssr') and 'cipher' in clean_p:
            del clean_p['cipher']
        if clean_p.get('network') in ('raw', 'none', ''):
            clean_p['network'] = 'tcp'
        if clean_p.get('sni') in ('', "''", '""'):
            del clean_p['sni']
        if clean_p.get('servername') in ('', "''", '""'):
            del clean_p['servername']
        if 'fingerprint' in clean_p:
            fp_val = str(clean_p.pop('fingerprint', '')).strip()
            if fp_val and 'client-fingerprint' not in clean_p:
                clean_p['client-fingerprint'] = fp_val
        if clean_p.get('tls') or 'reality-opts' in clean_p or clean_p.get('type') in ('vless', 'trojan', 'hysteria2', 'tuic'):
            fp = clean_p.get('client-fingerprint')
            if not fp:
                clean_p['client-fingerprint'] = 'firefox'
        clean_proxies.append(clean_p)

    output_data = {
        'proxies': clean_proxies
    }

    src_stats = {}
    for n in working_nodes:
        sid = n.get('_src_id', 1)
        src_stats[sid] = src_stats.get(sid, 0) + 1

    active_srcs = [f"{i}-{src_stats[i]}" for i in range(1, len(sources) + 1) if src_stats.get(i, 0) > 0]
    src_summary = " ".join(active_srcs) if active_srcs else "0"

    tmp_out = out_file + ".tmp"
    with open(tmp_out, "w", encoding="utf-8") as f:
        now_msk = datetime.now(timezone(timedelta(hours=3))).strftime("%Y-%m-%d %H:%M:%S МСК")
        total_collected = len(all_nodes)
        total_unique = len(unique_nodes)
        total_duplicates = total_collected - total_unique
        total_alive = len(clean_proxies)
        limits_dropped = health_stats['per_proto_dropped'] + health_stats['max_country_dropped'] + health_stats['max_total_dropped']

        delays = [n.get('_delay', 0) for n in working_nodes]
        min_ping = min(delays) if delays else 0
        max_ping = max(delays) if delays else 0
        avg_ping = round(sum(delays) / total_alive) if total_alive else 0

        speeds = [n.get('_speed', 0) for n in working_nodes if '_speed' in n]
        min_speed = min(speeds) if speeds else 0
        max_speed = max(speeds) if speeds else 0
        avg_speed = round(sum(speeds) / len(speeds), 1) if speeds else 0

        f.write(f"# ============================================================\n")
        f.write(f"# Обновлено: {now_msk}\n")
        if failed_sources:
            for fs in failed_sources:
                f.write(f"# Недоступный источник: {fs}\n")
        f.write(f"# Собрано: {total_collected} | Дубликатов: {total_duplicates} | Уникальных: {total_unique}\n")
        f.write(f"# Проверено: {health_stats['tested_count']} | Ответили: {health_stats['alive_count']} | Отсеяно суммарно: {health_stats['dead_count']}\n")
        f.write(f"#   - не ответили на базовый тест: {health_stats.get('dead_base', 0)}\n")
        if health_stats.get('dead_yt', 0) > 0:
            f.write(f"#   - недоступен YouTube: {health_stats.get('dead_yt', 0)}\n")
        if health_stats.get('dead_tg', 0) > 0:
            f.write(f"#   - недоступен Telegram: {health_stats.get('dead_tg', 0)}\n")
        if health_stats.get('dead_cf', 0) > 0:
            f.write(f"#   - недоступен Cloudflare: {health_stats.get('dead_cf', 0)}\n")
        speed_sec = health_stats.get('speed_timeout_sec', 8)
        if health_stats.get('speed_dropped', 0) > 0:
            f.write(f"# Отсеяно по низкой скорости (<100 КБ за {speed_sec} с): {health_stats['speed_dropped']}\n")
        f.write(f"# Отсеяно по лимитам стран и протоколов: {limits_dropped}\n")
        f.write(f"# Итого рабочих серверов в подписке: {total_alive}\n")
        f.write(f"# Пинг: от {min_ping} ms до {max_ping} ms (средний: {avg_ping} ms)\n")
        if speeds:
            f.write(f"# Скорость: от {min_speed} до {max_speed} КБ/с (средняя: {avg_speed} КБ/с)\n")
        f.write(f"# Источники: {src_summary}\n")
        f.write(f"# ============================================================\n\n")
        yaml.dump(output_data, f, allow_unicode=True, sort_keys=False)

    os.replace(tmp_out, out_file)

    print("\n" + "=" * 64)
    print("📊 ИТОГОВАЯ СВОДКА ОТБОРА (ВОРОНКА СЕРВЕРОВ):")
    print(f"  1. Собрано с источников:                {total_collected}")
    print(f"  2. Отсеяно дубликатов и битых адресов: -{total_duplicates} -> осталось {total_unique}")
    if health_stats.get('invalid_configs', 0) > 0:
        print(f"  3. Отсеяно с ошибками в конфиге:       -{health_stats['invalid_configs']} -> допущено к тесту {health_stats['tested_count']}")
    print(f"  4. Отсеяно не прошедших проверку сети: -{health_stats['dead_count']} -> ответило {health_stats['alive_count']}")
    print(f"     * базовый доступ:                   -{health_stats.get('dead_base', 0)}")
    if health_stats.get('dead_yt', 0) > 0:
        print(f"     * недоступен YouTube:               -{health_stats.get('dead_yt', 0)}")
    if health_stats.get('dead_tg', 0) > 0:
        print(f"     * недоступен Telegram:              -{health_stats.get('dead_tg', 0)}")
    if health_stats.get('dead_cf', 0) > 0:
        print(f"     * недоступен Cloudflare:            -{health_stats.get('dead_cf', 0)}")
    step_num = 5
    if health_stats.get('speed_dropped', 0) > 0:
        print(f"  {step_num}. Отсеяно по низкой скорости:         -{health_stats['speed_dropped']}")
        step_num += 1
    print(f"  {step_num}. Отсеяно дублей протокола в стране:  -{health_stats['per_proto_dropped']}")
    if health_stats['max_country_dropped'] > 0:
        print(f"     Отсеяно по лимиту на страну:        -{health_stats['max_country_dropped']}")
    if health_stats['max_total_dropped'] > 0:
        print(f"     Отсеяно по общему лимиту:           -{health_stats['max_total_dropped']}")
    print(f"  🏁 ГОТОВО К ИСПОЛЬЗОВАНИЮ:              {total_alive} серверов")
    print(f"  ⚡ Пинг: от {min_ping} ms до {max_ping} ms (средний: {avg_ping} ms)")
    if speeds:
        print(f"  🚀 Скорость: от {min_speed} до {max_speed} КБ/с (средняя: {avg_speed} КБ/с)")
    print(f"  📋 По источникам: {src_summary}")
    print("=" * 64 + "\n")

if __name__ == "__main__":
    main()
