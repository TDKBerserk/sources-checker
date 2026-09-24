#!/usr/bin/env python3
"""
Реальная проверка живости прокси-конфигов (vless/vmess/trojan/ss) — как в INCY:
для каждого конфига поднимается локальный sing-box-туннель, и через него
делается настоящий HTTP GET на тестовый URL. Проверяется не "открывается ли
страница со ссылкой", а "реально ли работает сам сервер".

Источники:
  - sources.txt в корне репозитория (если есть)
  - любые *.txt файлы в папке sources/ — сюда можно накидывать свои файлы
    с подписками или готовыми конфигами, скрипт подхватит их сам

Каждая строка источника может быть:
  - прямой ссылкой-конфигом (vless://... , vmess://... , trojan://... , ss://...)
  - HTTP(S)-ссылкой на подписку (обычной или base64) — тогда скрипт её скачает
    и вытащит из неё все конфиги

Результат:
  working_servers/vless.txt
  working_servers/vmess.txt
  working_servers/trojan.txt
  working_servers/ss.txt
  working_servers/all_configs.txt   <- общий файл, его же кладём в NotZapret | Bypass

Запуск:
    pip install requests
    (sing-box должен быть в PATH — см. workflow check_servers.yml)
    python check_servers.py
"""

import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import concurrent.futures
from pathlib import Path

import requests

from proxy_parsers import parse_uri

SOURCES_ROOT = Path(".")
SOURCES_DIR = Path("sources")
OUT_DIR = Path("working_servers")

TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "5"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "15"))
SINGBOX_STARTUP_WAIT = float(os.environ.get("SINGBOX_STARTUP_WAIT", "0.6"))
BASE_PORT = 20000

URI_RE = re.compile(r"(vless|vmess|trojan|ss)://[^\s\"'<>]+")


def find_free_port(offset: int) -> int:
    return BASE_PORT + offset


def collect_source_lines() -> list[str]:
    lines: list[str] = []
    root_sources = SOURCES_ROOT / "sources.txt"
    if root_sources.exists():
        lines += [l.strip() for l in root_sources.read_text(encoding="utf-8", errors="ignore").splitlines()]
    if SOURCES_DIR.exists():
        for f in SOURCES_DIR.glob("*.txt"):
            lines += [l.strip() for l in f.read_text(encoding="utf-8", errors="ignore").splitlines()]
    return [l for l in lines if l and not l.startswith("#")]


def extract_configs_from_text(text: str) -> list[str]:
    found = URI_RE.findall(text)
    # findall с группой возвращает только группу, поэтому ищем заново без группы захвата
    return re.findall(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+", text)


def fetch_subscription(url: str) -> list[str]:
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        print(f"  [!] не удалось скачать подписку {url}: {e}", file=sys.stderr)
        return []

    # подписка часто целиком закодирована в base64
    stripped = text.strip()
    decoded = None
    try:
        padding = "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(stripped + padding).decode("utf-8", errors="ignore")
    except Exception:
        decoded = None

    candidates = []
    if decoded and ("://" in decoded):
        candidates = extract_configs_from_text(decoded)
    if not candidates:
        candidates = extract_configs_from_text(text)
    return candidates


def gather_all_uris() -> list[str]:
    raw_lines = collect_source_lines()
    all_uris: set[str] = set()

    for line in raw_lines:
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            all_uris.add(line)
        elif line.startswith(("http://", "https://")):
            print(f"Скачиваю подписку: {line}")
            for uri in fetch_subscription(line):
                all_uris.add(uri)
        # иначе — не распознанная строка, пропускаем

    return sorted(all_uris)


def build_singbox_config(outbound: dict, port: int) -> dict:
    return {
        "log": {"level": "error"},
        "inbounds": [
            {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
    }


def check_one(uri: str, port: int) -> tuple[str, str | None, bool, str]:
    """Возвращает (uri, protocol, ok, detail)."""
    proto, outbound = parse_uri(uri)
    if not outbound:
        return uri, None, False, "не распознан формат ссылки"

    cfg = build_singbox_config(outbound, port)
    cfg_path = Path(f"/tmp/sb_cfg_{port}.json")
    cfg_path.write_text(json.dumps(cfg))

    proc = None
    try:
        proc = subprocess.Popen(
            ["sing-box", "run", "-c", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(SINGBOX_STARTUP_WAIT)
        if proc.poll() is not None:
            return uri, proto, False, "sing-box не запустился (плохой конфиг)"

        proxies = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        }
        start = time.time()
        resp = requests.get(TEST_URL, proxies=proxies, timeout=TEST_TIMEOUT)
        latency_ms = int((time.time() - start) * 1000)
        ok = resp.status_code < 400
        return uri, proto, ok, f"{resp.status_code} за {latency_ms}ms"
    except Exception as e:
        return uri, proto, False, f"ошибка: {e}"
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        cfg_path.unlink(missing_ok=True)


def main():
    uris = gather_all_uris()
    print(f"Всего уникальных конфигов для проверки: {len(uris)}")
    if not uris:
        print("Нечего проверять — добавь ссылки в sources.txt или в файлы папки sources/")
        return

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {
            pool.submit(check_one, uri, find_free_port(i)): uri
            for i, uri in enumerate(uris)
        }
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            uri, proto, ok, detail = fut.result()
            results.append((uri, proto, ok, detail))
            done += 1
            status = "OK  " if ok else "DEAD"
            print(f"[{done}/{len(uris)}] {status} {proto or '?':8s} {detail}")

    OUT_DIR.mkdir(exist_ok=True)
    by_proto: dict[str, list[str]] = {"vless": [], "vmess": [], "trojan": [], "ss": []}
    all_working = []

    for uri, proto, ok, detail in results:
        if ok and proto in by_proto:
            by_proto[proto].append(uri)
            all_working.append(uri)

    for proto, items in by_proto.items():
        (OUT_DIR / f"{proto}.txt").write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")

    (OUT_DIR / "all_configs.txt").write_text(
        "\n".join(all_working) + ("\n" if all_working else ""), encoding="utf-8"
    )

    print(f"\nГотово: {len(all_working)} рабочих из {len(uris)} проверенных")
    for proto, items in by_proto.items():
        print(f"  {proto}: {len(items)}")


if __name__ == "__main__":
    main()
