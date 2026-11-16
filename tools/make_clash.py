#!/usr/bin/env python3
"""把 configs/*.txt 里的明文 URI 转成 Clash Meta (mihomo) YAML 订阅。
不支持的传输(xhttp/xudp 等 Xray 专有)会被跳过并统计。"""
import base64, glob, json, os, re, sys, urllib.parse

OUT = sys.argv[1] if len(sys.argv) > 1 else "clash.yaml"
LIMIT = int(sys.argv[2]) if len(sys.argv) > 2 else 400

def b64d(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)

def q(u):
    return urllib.parse.parse_qs(u, keep_blank_values=True)

def name_of(u, default):
    frag = urllib.parse.unquote(u.split('#', 1)[1]) if '#' in u else ''
    return (frag or default)[:60].replace('"', "'")

def parse_vless(u):
    m = re.match(r'vless://([^@]+)@([^:/?#]+):(\d+)([^#]*)', u)
    if not m: return None
    uuid, host, port, rest = m.group(1), m.group(2), int(m.group(3)), m.group(4)
    p = q(rest.lstrip('?'))
    g = lambda k, d='': (p.get(k, [d])[0] or d)
    net = g('type', 'tcp'); sec = g('security', 'none')
    n = name_of(u, f"{host}:{port}")
    base = {"name": n, "type": "vless", "server": host, "port": port, "uuid": uuid, "udp": True, "network": net}
    if sec in ('tls', 'reality', 'xtls'):
        base["tls"] = True
        sni = g('sni') or g('host') or host
        base["servername"] = sni
        if g('fp'): base["client-fingerprint"] = g('fp')
        if g('allowInsecure') == '1' or g('insecure') == '1': base["skip-cert-verify"] = True
        if sec == 'reality':
            base["reality-opts"] = {"public-key": g('pbk'), "short-id": g('sid')}
            base["flow"] = g('flow') or ''
            if not base["flow"]: base.pop("flow")
    if net == 'ws':
        base["ws-opts"] = {"path": g('path', '/')}
        if g('host'): base["ws-opts"]["headers"] = {"Host": g('host')}
    elif net == 'grpc':
        base["grpc-opts"] = {"grpc-service-name": g('serviceName', g('path', ''))}
    elif net in ('tcp', 'http', 'h2'):
        pass
    else:
        return None  # xhttp / xudp / kcp / quic 等不支持
    return base

def parse_trojan(u):
    m = re.match(r'trojan://([^@]+)@([^:/?#]+):(\d+)([^#]*)', u)
    if not m: return None
    pw, host, port, rest = m.group(1), m.group(2), int(m.group(3)), m.group(4)
    p = q(rest.lstrip('?')); net = p.get('type', ['tcp'])[0]
    base = {"name": name_of(u, f"{host}:{port}"), "type": "trojan", "server": host, "port": port,
            "password": urllib.parse.unquote(pw), "udp": True, "sni": p.get('sni', [host])[0],
            "skip-cert-verify": p.get('allowInsecure', ['0'])[0] == '1'}
    if net == 'ws':
        base["network"] = "ws"; base["ws-opts"] = {"path": p.get('path', ['/'])[0]}
        if p.get('host'): base["ws-opts"]["headers"] = {"Host": p['host'][0]}
    elif net == 'grpc':
        base["network"] = "grpc"; base["grpc-opts"] = {"grpc-service-name": p.get('serviceName', [''])[0]}
    elif net != 'tcp':
        return None
    return base

def parse_vmess(u):
    try:
        j = json.loads(b64d(u[8:]).decode('utf-8', 'ignore'))
    except Exception:
        return None
    net = j.get('net', 'tcp'); tls = str(j.get('tls', '')).lower() in ('tls', 'reality', 'true')
    base = {"name": (j.get('ps') or f"{j.get('add')}:{j.get('port')}")[:60], "type": "vmess",
            "server": j.get('add'), "port": int(j.get('port', 443)), "uuid": j.get('id'),
            "alterId": int(j.get('aid', 0) or 0), "cipher": "auto", "udp": True}
    if tls:
        base["tls"] = True; base["servername"] = j.get('sni') or j.get('host') or j['server']
        base["skip-cert-verify"] = True
    if net == 'ws':
        base["network"] = "ws"; base["ws-opts"] = {"path": j.get('path', '/')}
        if j.get('host'): base["ws-opts"]["headers"] = {"Host": j['host']}
    elif net == 'grpc':
        base["network"] = "grpc"; base["grpc-opts"] = {"grpc-service-name": j.get('path', '')}
    elif net not in ('tcp', 'h2'):
        return None
    return base

def parse_ss(u):
    body = u[5:]
    body, _, frag = body.partition('#')
    if '@' in body:
        user, hostpart = body.split('@', 1)
        try:
            method_pass = b64d(user).decode('utf-8', 'ignore')
        except Exception:
            method_pass = urllib.parse.unquote(user)
        hp = hostpart.split('/')[0].split('?')[0]
        m = re.match(r'([^\s:]+):(\d+)', hp)
        if not m or ':' not in method_pass: return None
        method, pw = method_pass.split(':', 1)
        return {"name": urllib.parse.unquote(frag)[:60] or hp, "type": "ss", "server": m.group(1),
                "port": int(m.group(2)), "cipher": method, "password": pw, "udp": True}
    try:
        data = b64d(body).decode('utf-8', 'ignore')
        m = re.match(r'([^:]+):([^@]+)@([^\s:]+):(\d+)', data)
        if not m: return None
        return {"name": urllib.parse.unquote(frag)[:60] or m.group(3), "type": "ss", "server": m.group(3),
                "port": int(m.group(4)), "cipher": m.group(1), "password": m.group(2), "udp": True}
    except Exception:
        return None

def parse_hy2(u):
    m = re.match(r'hy2://([^@]+)@([^:/?#]+):(\d+)([^#]*)', u)
    if not m: return None
    base = {"name": name_of(u, f"{m.group(2)}:{m.group(3)}"), "type": "hysteria2",
            "server": m.group(2), "port": int(m.group(3)), "password": urllib.parse.unquote(m.group(1)),
            "skip-cert-verify": True}
    p = q(m.group(4).lstrip('?'))
    if p.get('sni'): base["sni"] = p['sni'][0]
    return base

PARSERS = {'vless': parse_vless, 'trojan': parse_trojan, 'vmess': parse_vmess, 'ss': parse_ss, 'hy2': parse_hy2}

def main():
    seen, proxies, skipped = set(), [], 0
    files = sorted(glob.glob('configs/*.txt'), key=lambda p: (len(os.path.basename(p)), p))
    for f in files:
        if os.path.basename(f) in ('counts.json',): continue
        for line in open(f, encoding='utf-8', errors='ignore'):
            line = line.strip()
            if not line or line.startswith('#'): continue
            scheme = line.split('://', 1)[0] if '://' in line else ''
            if scheme not in PARSERS: continue
            if len(proxies) >= LIMIT: break
            try:
                p = PARSERS[scheme](line)
            except Exception:
                p = None
            if not p:
                skipped += 1; continue
            key = (p['type'], p['server'], p['port'], p.get('uuid') or p.get('password'))
            if key in seen: continue
            seen.add(key)
            p['name'] = re.sub(r'[^\w\-\u4e00-\u9fff\.\(\)\[\] ]', '_', p['name'])[:50] or f"{p['server']}:{p['port']}"
            proxies.append(p)
        if len(proxies) >= LIMIT: break

    names = [p['name'] for p in proxies]
    lines = ['# FlClash / mihomo 订阅 · 自动生成', 'mixed-port: 7890', 'allow-lan: false',
             'mode: rule', 'log-level: info', 'ipv6: true', 'unified-delay: true', 'tcp-concurrent: true',
             'proxies:']
    def qv(v):
        if isinstance(v, bool): return 'true' if v else 'false'
        if isinstance(v, (int, float)): return str(v)
        return '"' + str(v).replace('"', "'") + '"'
    for p in proxies:
        lines.append(f'  - name: {qv(p["name"])}')
        for k, v in p.items():
            if k == 'name': continue
            if isinstance(v, dict):
                lines.append(f'    {k}:')
                for kk, vv in v.items():
                    lines.append(f'      {kk}: {qv(vv)}')
            else:
                lines.append(f'    {k}: {qv(v)}')
    lines += ['proxy-groups:', '  - name: 🚀 节点选择', '    type: select', '    proxies:']
    lines.append('      - ♻️ 自动选择')
    for n in names[:400]: lines.append(f'      - {qv(n)}')
    lines += ['  - name: ♻️ 自动选择', '    type: url-test', '    url: http://www.gstatic.com/generate_204',
              '    interval: 300', '    tolerance: 50', '    proxies:']
    for n in names[:400]: lines.append(f'      - {qv(n)}')
    lines += ['rules:', '  - GEOIP,CN,DIRECT', '  - MATCH,🚀 节点选择']
    open(OUT, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print(f"wrote {OUT}: {len(proxies)} nodes, skipped {skipped}")

main()
