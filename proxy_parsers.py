"""
Разбор ссылок-конфигов (vless://, vmess://, trojan://, ss://) в outbound
для sing-box. Покрывает основные варианты (TCP/WS/gRPC, TLS/Reality),
но экзотические кастомные схемы отдельных панелей могут не распознаться —
такие конфиги просто попадут в unparsed и будут пропущены при проверке.
"""

import base64
import json
from urllib.parse import urlparse, parse_qs, unquote


def _b64decode(s: str) -> bytes:
    s = s.strip()
    padding = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + padding)
    except Exception:
        return base64.b64decode(s + padding)


def parse_vless(uri: str) -> dict:
    parsed = urlparse(uri)
    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": parsed.username,
    }
    if qs.get("flow"):
        outbound["flow"] = qs["flow"]

    net = qs.get("type", "tcp")
    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": unquote(qs.get("path", "/")),
        }
        if qs.get("host"):
            outbound["transport"]["headers"] = {"Host": qs["host"]}
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": qs.get("serviceName", "")}

    security = qs.get("security", "none")
    if security in ("tls", "reality"):
        tls = {
            "enabled": True,
            "server_name": qs.get("sni", parsed.hostname),
            "insecure": qs.get("allowInsecure", "0") == "1",
        }
        if security == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": qs.get("pbk", ""),
                "short_id": qs.get("sid", ""),
            }
            tls["utls"] = {"enabled": True, "fingerprint": qs.get("fp", "chrome")}
        outbound["tls"] = tls
    return outbound


def parse_vmess(uri: str) -> dict:
    raw = uri[len("vmess://"):]
    data = json.loads(_b64decode(raw))

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": data.get("add"),
        "server_port": int(data.get("port")),
        "uuid": data.get("id"),
        "security": "auto",
        "alter_id": int(data.get("aid", 0) or 0),
    }
    net = data.get("net", "tcp")
    if net == "ws":
        outbound["transport"] = {"type": "ws", "path": data.get("path", "/")}
        if data.get("host"):
            outbound["transport"]["headers"] = {"Host": data["host"]}
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": data.get("path", "")}

    if str(data.get("tls", "")).lower() == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": data.get("sni") or data.get("host") or data.get("add"),
            "insecure": True,
        }
    return outbound


def parse_trojan(uri: str) -> dict:
    parsed = urlparse(uri)
    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": unquote(parsed.username or ""),
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni", parsed.hostname),
            "insecure": qs.get("allowInsecure", "0") == "1",
        },
    }
    if qs.get("type") == "ws":
        outbound["transport"] = {"type": "ws", "path": unquote(qs.get("path", "/"))}
    return outbound


def parse_ss(uri: str) -> dict:
    raw = uri[len("ss://"):]
    raw = raw.split("#", 1)[0]

    if "@" in raw:
        userinfo_b64, hostport = raw.split("@", 1)
        hostport = hostport.split("?", 1)[0].split("/", 1)[0]
        try:
            userinfo = _b64decode(userinfo_b64).decode()
            method, password = userinfo.split(":", 1)
        except Exception:
            # некоторые генераторы кладут method:password в открытом виде
            method, password = unquote(userinfo_b64).split(":", 1)
        host, port = hostport.rsplit(":", 1)
    else:
        decoded = _b64decode(raw).decode()
        methodpass, hostport = decoded.rsplit("@", 1)
        method, password = methodpass.split(":", 1)
        host, port = hostport.rsplit(":", 1)

    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "method": method,
        "password": password,
    }


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
}


def parse_uri(uri: str):
    """Возвращает (protocol, outbound_dict) или (None, None), если не распознано."""
    for prefix, fn in PARSERS.items():
        if uri.startswith(prefix):
            proto = prefix.split("://")[0]
            try:
                return proto, fn(uri)
            except Exception:
                return None, None
    return None, None
