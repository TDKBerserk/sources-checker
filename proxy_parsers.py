"""
Разбор ссылок:
vless://
vmess://
trojan://
ss://

для sing-box.
"""

import base64
import json

from urllib.parse import (
    urlparse,
    parse_qs,
    unquote
)


def _b64decode(value):

    value = value.strip()

    padding = "=" * (
        -len(value) % 4
    )

    try:

        return base64.urlsafe_b64decode(
            value + padding
        )

    except Exception:

        return base64.b64decode(
            value + padding
        )


def parse_vless(uri):

    parsed = urlparse(uri)

    qs = {
        key: value[0]
        for key, value
        in parse_qs(
            parsed.query
        ).items()
    }

    if not parsed.hostname:
        return None

    if not parsed.port:
        return None

    if not parsed.username:
        return None

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": parsed.username,
    }

    if qs.get("flow"):

        outbound["flow"] = qs[
            "flow"
        ]

    network = qs.get(
        "type",
        "tcp"
    )

    if network == "ws":

        outbound["transport"] = {
            "type": "ws",
            "path": unquote(
                qs.get(
                    "path",
                    "/"
                )
            )
        }

        if qs.get("host"):

            outbound[
                "transport"
            ][
                "headers"
            ] = {
                "Host": qs["host"]
            }

    elif network == "grpc":

        outbound["transport"] = {
            "type": "grpc",
            "service_name": qs.get(
                "serviceName",
                ""
            )
        }

    security = qs.get(
        "security",
        "none"
    )

    if security in (
        "tls",
        "reality"
    ):

        tls = {
            "enabled": True,
            "server_name": qs.get(
                "sni",
                parsed.hostname
            ),
            "insecure": (
                qs.get(
                    "allowInsecure",
                    "0"
                ) == "1"
            )
        }

        if security == "reality":

            tls["reality"] = {
                "enabled": True,
                "public_key": qs.get(
                    "pbk",
                    ""
                ),
                "short_id": qs.get(
                    "sid",
                    ""
                )
            }

            tls["utls"] = {
                "enabled": True,
                "fingerprint": qs.get(
                    "fp",
                    "chrome"
                )
            }

        outbound["tls"] = tls

    return outbound


def parse_vmess(uri):

    raw = uri[
        len("vmess://"):
    ]

    data = json.loads(
        _b64decode(
            raw
        )
    )

    server = data.get("add")
    port = data.get("port")
    uuid = data.get("id")

    if not server:
        return None

    if not port:
        return None

    if not uuid:
        return None

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "uuid": uuid,
        "security": (
            data.get(
                "scy",
                "auto"
            )
        ),
    }

    network = data.get(
        "net",
        "tcp"
    )

    if network == "ws":

        outbound["transport"] = {
            "type": "ws",
            "path": data.get(
                "path",
                "/"
            )
        }

        if data.get("host"):

            outbound[
                "transport"
            ][
                "headers"
            ] = {
                "Host": data["host"]
            }

    elif network == "grpc":

        outbound["transport"] = {
            "type": "grpc",
            "service_name": data.get(
                "path",
                ""
            )
        }

    if str(
        data.get(
            "tls",
            ""
        )
    ).lower() == "tls":

        outbound["tls"] = {
            "enabled": True,
            "server_name": (
                data.get("sni")
                or data.get("host")
                or server
            ),
            "insecure": True
        }

    return outbound


def parse_trojan(uri):

    parsed = urlparse(uri)

    qs = {
        key: value[0]
        for key, value
        in parse_qs(
            parsed.query
        ).items()
    }

    if not parsed.hostname:
        return None

    if not parsed.port:
        return None

    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": unquote(
            parsed.username or ""
        ),
        "tls": {
            "enabled": True,
            "server_name": qs.get(
                "sni",
                parsed.hostname
            ),
            "insecure": (
                qs.get(
                    "allowInsecure",
                    "0"
                ) == "1"
            )
        }
    }

    if qs.get(
        "type"
    ) == "ws":

        outbound["transport"] = {
            "type": "ws",
            "path": unquote(
                qs.get(
                    "path",
                    "/"
                )
            )
        }

    return outbound


def parse_ss(uri):

    raw = uri[
        len("ss://"):
    ]

    raw = raw.split(
        "#",
        1
    )[0]

    if "@" in raw:

        userinfo, hostport = (
            raw.split(
                "@",
                1
            )
        )

        hostport = (
            hostport
            .split("?", 1)[0]
            .split("/", 1)[0]
        )

        try:

            decoded = _b64decode(
                userinfo
            ).decode()

            method, password = (
                decoded.split(
                    ":",
                    1
                )
            )

        except Exception:

            try:

                method, password = (
                    unquote(
                        userinfo
                    ).split(
                        ":",
                        1
                    )
                )

            except Exception:

                return None

        if ":" not in hostport:
            return None

        host, port = (
            hostport.rsplit(
                ":",
                1
            )
        )

    else:

        try:

            decoded = _b64decode(
                raw
            ).decode()

            methodpass, hostport = (
                decoded.rsplit(
                    "@",
                    1
                )
            )

            method, password = (
                methodpass.split(
                    ":",
                    1
                )
            )

            host, port = (
                hostport.rsplit(
                    ":",
                    1
                )
            )

        except Exception:

            return None

    try:

        port = int(port)

    except Exception:

        return None

    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password
    }


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss
}


def parse_uri(uri):

    for prefix, parser in (
        PARSERS.items()
    ):

        if uri.startswith(prefix):

            protocol = prefix.split(
                "://"
            )[0]

            try:

                outbound = parser(
                    uri
                )

                if outbound is None:

                    return (
                        None,
                        None
                    )

                return (
                    protocol,
                    outbound
                )

            except Exception:

                return (
                    None,
                    None
                )

    return (
        None,
        None
    )
