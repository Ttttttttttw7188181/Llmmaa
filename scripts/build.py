#!/usr/bin/env python3
"""Build a Sing-box config from public subscription links.

Supported URI inputs: vless://, trojan://, ss:// and vmess://.
This emits a sing-box configuration (not a provider-specific encoded subscription).
Only TCP reachability is checked; that does not prove a proxy handshake works.
"""
from __future__ import annotations
import base64
import json
import os
import re
import socket
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = ROOT / "sources" / "urls.txt"
DIST = ROOT / "dist"
TIMEOUT = float(os.getenv("NODE_CHECK_TIMEOUT", "2.5"))
MAX_NODES = int(os.getenv("MAX_NODES", "500"))

def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Llmmaa-subscription-builder/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8-sig", errors="replace")

def decode_b64(value: str) -> bytes:
    value = value.strip()
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value.encode())

def host_port(netloc: str):
    parsed = urllib.parse.urlsplit("//" + netloc)
    return parsed.hostname, parsed.port

def safe_tag(s: str) -> str:
    s = urllib.parse.unquote(s or "").strip()
    return re.sub(r"[\x00-\x1f]", "", s)[:100]

def parse_uri(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        u = urllib.parse.urlsplit(line)
        scheme = u.scheme.lower()
        if scheme == "vmess":
            raw = decode_b64(u.netloc or u.path)
            obj = json.loads(raw.decode("utf-8", errors="replace"))
            server = obj.get("add") or obj.get("server")
            port = int(obj.get("port", 0))
            if not server or not port:
                return None
            tls = str(obj.get("tls", "")).lower() == "tls"
            network = obj.get("net", "tcp")
            outbound = {
                "type": "vmess", "tag": safe_tag(obj.get("ps") or f"VMess {server}"),
                "server": server, "server_port": port,
                "uuid": obj.get("id", ""), "security": obj.get("scy") or "auto",
                "alter_id": int(obj.get("aid", 0)),
            }
            if network == "ws":
                outbound["transport"] = {"type": "ws", "path": obj.get("path") or "/"}
                host = (obj.get("host") or "")
                if host:
                    outbound["transport"]["headers"] = {"Host": host}
            if tls:
                outbound["tls"] = {"enabled": True, "server_name": obj.get("sni") or obj.get("host") or server}
            return outbound
        if scheme not in ("vless", "trojan", "ss"):
            return None
        server, port = host_port(u.netloc)
        if not server or not port:
            return None
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        get = lambda k, default="": (q.get(k) or [default])[0]
        tag = safe_tag(urllib.parse.unquote(u.fragment)) or f"{scheme.upper()} {server}:{port}"
        if scheme == "vless":
            outbound = {"type": "vless", "tag": tag, "server": server, "server_port": port,
                        "uuid": urllib.parse.unquote(u.username or "")}
            flow = get("flow")
            if flow:
                outbound["flow"] = flow
            security = get("security").lower()
            if security in ("tls", "reality"):
                tls = {"enabled": True, "server_name": get("sni") or get("serverName") or server}
                alpn = get("alpn")
                if alpn:
                    tls["alpn"] = alpn.split(",")
                if security == "reality":
                    tls["reality"] = {"enabled": True, "public_key": get("pbk") or get("publicKey"),
                                      "short_id": get("sid") or get("shortId", ""))
                outbound["tls"] = tls
            transport = get("type", "tcp").lower()
            if transport == "ws":
                headers = {}
                if get("host"):
                    headers["Host"] = get("host")
                outbound["transport"] = {"type": "ws", "path": get("path") or "/", **({"headers": headers} if headers else {})}
            elif transport == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": get("serviceName")}
            return outbound
        if scheme == "trojan":
            outbound = {"type": "trojan", "tag": tag, "server": server, "server_port": port,
                        "password": urllib.parse.unquote(u.username or "")}
            outbound["tls"] = {"enabled": True, "server_name": get("sni") or server}
            if get("type").lower() == "ws":
                headers = {"Host": get("host")} if get("host") else {}
                outbound["transport"] = {"type": "ws", "path": get("path") or "/", **({"headers": headers} if headers else {})}
            return outbound
        # Shadowsocks URI: ss://BASE64(method:password)@host:port or BASE64(method:password@host:port)
        raw = urllib.parse.unquote(u.username or "")
        if not raw and u.netloc:
            raw = u.netloc.split("@", 1)[0]
        try:
            decoded = decode_b64(raw).decode()
            method, password = decoded.split(":", 1)
        except Exception:
            if ":" in raw:
                method, password = raw.split(":", 1)
            else:
                return None
        return {"type": "shadowsocks", "tag": tag, "server": server, "server_port": port,
                "method": method, "password": password}
    except Exception as e:
        print(f"Skipping unparsable line: {type(e).__name__}")
        return None

def tcp_reachable(outbound) -> bool:
    host, port = outbound.get("server"), outbound.get("server_port")
    try:
        with socket.create_connection((host, int(port)), timeout=TIMEOUT):
            return True
    except Exception:
        return False

COUNTRIES = [
    ("Finland", ["finland", "suomi", "🇫🇮", " fi "]),
    ("Germany", ["germany", "deutschland", "🇩🇪", " de "]),
    ("Netherlands", ["netherlands", "holland", "🇳🇱", " nl "]),
    ("France", ["france", "🇫🇷", " fr "]),
    ("United States", ["united states", "usa", "🇺🇸", " us "]),
    ("United Kingdom", ["united kingdom", "uk", "britain", "🇬🇧", " gb "]),
    ("Sweden", ["sweden", "🇸🇪", " se "]),
    ("Poland", ["poland", "🇵🇱", " pl "]),
    ("Russia", ["russia", "россия", "🇷🇺", " ru "]),
    ("Japan", ["japan", "🇯🇵", " jp "]),
    ("Singapore", ["singapore", "🇸🇬", " sg "]),
    ("Turkey", ["turkey", "türkiye", "🇹🇷", " tr "]),
    ("Canada", ["canada", "🇨🇦", " ca "]),
    ("Switzerland", ["switzerland", "🇨🇭", " ch "]),
    ("Austria", ["austria", "🇦🇹", " at "]),
    ("Latvia", ["latvia", "🇱🇻", " lv "]),
    ("Estonia", ["estonia", "🇪🇪", " ee "]),
    ("Lithuania", ["lithuania", "🇱🇹", " lt "]),
    ("Czechia", ["czech", "🇨🇿", " cz "]),
    ("Italy", ["italy", "🇮🇹", " it "]),
    ("Spain", ["spain", "🇪🇸", " es "]),
]
def country_of(tag: str):
    t = f" {tag.lower()} "
    for country, markers in COUNTRIES:
        if any(m in t for m in markers):
            return country
    return None

def main():
    if not SOURCE_FILE.exists():
        raise SystemExit("Missing sources/urls.txt")
    urls = [x.strip() for x in SOURCE_FILE.read_text().splitlines()
            if x.strip() and not x.strip().startswith("#")]
    lines = []
    for url in urls:
        try:
            lines.extend(fetch_text(url).splitlines())
            print(f"Fetched source: {url}")
        except Exception as e:
            print(f"Source failed: {url} ({type(e).__name__})")
    nodes, seen = [], set()
    for line in lines:
        ob = parse_uri(line)
        if not ob:
            continue
        identity = (ob["type"], ob.get("server"), ob.get("server_port"), ob.get("tag"))
        if identity in seen:
            continue
        seen.add(identity)
        nodes.append(ob)
        if len(nodes) >= MAX_NODES:
            break
    if not nodes:
        raise SystemExit("No supported proxy links found; refusing to publish an empty config.")

    alive = []
    for i, ob in enumerate(nodes, 1):
        ok = tcp_reachable(ob)
        print(f"[{i}/{len(nodes)}] {'reachable' if ok else 'unreachable'}: {ob['tag']}")
        if ok:
            alive.append(ob)
    # Do not publish an empty config if all checks fail: TCP checks can be blocked even for valid nodes.
    chosen = alive or nodes
    used_tags = set()
    for i, ob in enumerate(chosen, 1):
        base = ob["tag"] or f"node-{i}"
        tag = base
        suffix = 2
        while tag in used_tags or tag in ("direct", "block", "Auto", "БС", "ЧС"):
            tag = f"{base} ({suffix})"
            suffix += 1
        ob["tag"] = tag
        used_tags.add(tag)

    tags = [ob["tag"] for ob in chosen]
    outbounds = list(chosen)
    outbounds.extend([
        {"type": "urltest", "tag": "Авто", "outbounds": tags, "url": "https://www.gstatic.com/generate_204",
         "interval": "5m", "tolerance": 80},
        {"type": "selector", "tag": "БС", "outbounds": ["Авто"] + tags, "default": "Авто"},
        {"type": "selector", "tag": "ЧС", "outbounds": ["Авто"] + tags, "default": "Авто"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ])
    grouped = {}
    for ob in chosen:
        c = country_of(ob["tag"])
        if c:
            grouped.setdefault(c, []).append(ob["tag"])
    for country, ctags in sorted(grouped.items()):
        outbounds.append({"type": "selector", "tag": f"Страна: {country}", "outbounds": ctags, "default": ctags[0]})

    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": "Авто"}],
                "final": "dns-remote", "strategy": "prefer_ipv4"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": outbounds,
        "route": {"auto_detect_interface": True, "final": "Авто"}
    }
    DIST.mkdir(parents=True, exist_ok=True)
    (DIST / "antinet-singbox.json").write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n")
    (DIST / "nodes.txt").write_text("\n".join(f"{o['tag']} — {o['server']}:{o['server_port']}" for o in chosen) + "\n")
    (DIST / "status.json").write_text(json.dumps({
        "source_count": len(urls), "parsed_nodes": len(nodes), "tcp_reachable": len(alive),
        "published_nodes": len(chosen), "note": "TCP reachability only; not a full proxy handshake test.",
        "groups": ["Авто", "БС", "ЧС"] + [f"Страна: {c}" for c in sorted(grouped)]
    }, ensure_ascii=False, indent=2) + "\n")
    print(f"Published {len(chosen)} nodes; country groups: {', '.join(sorted(grouped)) or 'none'}")

if __name__ == "__main__":
    main()
