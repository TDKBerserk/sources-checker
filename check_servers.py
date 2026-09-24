#!/usr/bin/env python3
"""
Реальная проверка живости (INCY-style: HTTP GET через настоящий туннель
sing-box) для источников из sources.txt и файлов в папке sources/.

Логика по каждой строке-источнику:

  - Прямой конфиг (vless://, vmess://, trojan://, ss://):
      жив -> оставляем как есть
      мёртв -> убираем

  - Ссылка на подписку (http/https):
      скачиваем, вытаскиваем из неё все конфиги, проверяем каждый.
      * если ВСЕ конфиги внутри живы -> в итоговый файл идёт сама ссылка
        на подписку без изменений (незачем её разбирать)
      * если живы ЧАСТЬ конфигов -> подписку целиком выбрасываем,
        но "вытягиваем" из неё живые конфиги и кладём их в итоговый
        файл по отдельности (чтобы не терять рабочие серверы)
      * если не живёт ни один -> строка целиком выбрасывается

Результат — один-единственный файл sources.txt (перезаписывается в корне
репозитория). Никакого деления на подпапки/протоколы.

Запуск:
    pip install requests
    (sing-box должен быть в PATH)
    python check_servers.py
"""

import base64
import json
import os
import re
import subprocess
import sys
import time
import concurrent.futures
from pathlib import Path

import requests

from proxy_parsers import parse_uri

SOURCES_ROOT = Path(".")
SOURCES_DIR = Path("sources")
OUTPUT_FILE = Path("sources.txt")

TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "5"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "15"))
SINGBOX_STARTUP_WAIT = float(os.environ.get("SINGBOX_STARTUP_WAIT", "0.6"))
BASE_PORT = 20000

CONFIG_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://")
URI_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+")


def collect_source_lines() -> list[str]:
    lines: list[str] = []
    root_sources = SOURCES_ROOT / "sources.txt"
    if root_sources.exists():
        lines += root_sources.read_text(encoding="utf-8", errors="ignore").splitlines()
    if SOURCES_DIR.exists():
        for f in sorted(SOURCES_DIR.glob("*.txt")):
            lines += f.read_text(encoding="utf-8", errors="ignore").splitlines()

    seen = set()
    result = []
    for l in lines:
        l = l.strip()
        if not l or l.startswith("#") or l in seen:
            continue
        seen.add(l)
        result.append(l)
    return result


def fetch_subscription(url: str) -> list[str]:
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        print(f"  [!] не удалось скачать подписку {url}: {e}", file=sys.stderr)
        return []

    stripped = text.strip()
    decoded = None
    try:
        padding = "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(stripped + padding).decode("utf-8", errors="ignore")
    except Exception:
        decoded = None

    candidates = []
    if decoded and "://" in decoded:
        candidates = URI_PATTERN.findall(decoded)
    if not candidates:
        candidates = URI_PATTERN.findall(text)
    seen = set()
    uniq = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def build_singbox_config(outbound: dict, port: int) -> dict:
    return {
        "log": {"level": "error"},
        "inbounds": [
            {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
    }


def check_one(uri: str, port: int) -> tuple[str, bool, str]:
    """Возвращает (uri, ok, detail). Реальная проверка через sing-box-туннель."""
    proto, outbound = parse_uri(uri)
    if not outbound:
        return uri, False, "не распознан формат ссылки"

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
            return uri, False, "sing-box не запустился (плохой конфиг)"

        proxies = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        }
        start = time.time()
        resp = requests.get(TEST_URL, proxies=proxies, timeout=TEST_TIMEOUT)
        latency_ms = int((time.time() - start) * 1000)
        ok = resp.status_code < 400
        return uri, ok, f"{resp.status_code} за {latency_ms}ms"
    except Exception as e:
        return uri, False, f"ошибка: {e}"
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        cfg_path.unlink(missing_ok=True)


def main():
    raw_lines = collect_source_lines()
    print(f"Источников в списке: {len(raw_lines)}")
    if not raw_lines:
        print("Нечего проверять — пусто в sources.txt и в sources/")
        return

    direct_entries: list[str] = []
    subs: dict[str, list[str]] = {}

    for line in raw_lines:
        if line.startswith(CONFIG_PREFIXES):
            direct_entries.append(line)
        elif line.startswith(("http://", "https://")):
            print(f"Скачиваю подписку: {line}")
            configs = fetch_subscription(line)
            subs[line] = configs
        else:
            print(f"  [?] непонятная строка, пропускаю: {line[:60]}")

    tasks: list[tuple[str, str | None]] = []
    for uri in direct_entries:
        tasks.append((uri, None))
    for sub_url, configs in subs.items():
        for uri in configs:
            tasks.append((uri, sub_url))

    print(f"Всего конфигов для реальной проверки: {len(tasks)}")

    results: dict[str, bool] = {}
    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futures = {
                pool.submit(check_one, uri, BASE_PORT + i): uri
                for i, (uri, _owner) in enumerate(tasks)
            }
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                uri, ok, detail = fut.result()
                results[uri] = ok
                done += 1
                status = "OK  " if ok else "DEAD"
                print(f"[{done}/{len(tasks)}] {status} {detail}  {uri[:70]}")

    output_lines: list[str] = []
    for line in raw_lines:
        if line.startswith(CONFIG_PREFIXES):
            if results.get(line):
                output_lines.append(line)

        elif line.startswith(("http://", "https://")):
            configs = subs.get(line, [])
            if not configs:
                continue
            alive = [c for c in configs if results.get(c)]
            if len(alive) == len(configs):
                output_lines.append(line)
            elif alive:
                output_lines.extend(alive)

    OUTPUT_FILE.write_text("\n".join(output_lines) + ("\n" if output_lines else ""), encoding="utf-8")

    total_subs = len(subs)
    fully_alive_subs = sum(1 for u, c in subs.items() if c and all(results.get(x) for x in c))
    partial_subs = sum(1 for u, c in subs.items() if c and 0 < sum(results.get(x, False) for x in c) < len(c))
    dead_subs = total_subs - fully_alive_subs - partial_subs

    print(f"\nГотово: {len(output_lines)} строк в итоговом sources.txt")
    print(f"  подписок целиком живых: {fully_alive_subs}")
    print(f"  подписок частично живых (вытянуты рабочие конфиги): {partial_subs}")
    print(f"  подписок мёртвых/пустых: {dead_subs}")
    print(f"  прямых конфигов живых: {sum(1 for u in direct_entries if results.get(u))}/{len(direct_entries)}")


if __name__ == "__main__":
    main()
