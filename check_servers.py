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

---
Патч (parallel fetch + per-sub sampling):
- Скачивание подписок было ПОСЛЕДОВАТЕЛЬНЫМ (for-цикл, один HTTP-запрос
  за другим). При тысячах подписок это само по себе съедало часы ещё до
  начала реальных sing-box-проверок. Теперь скачивание идёт пулом потоков
  (SUB_FETCH_CONCURRENCY), как и сами проверки.
- Добавлено ограничение MAX_CONFIGS_PER_SUB: если из одной подписки
  вытянулось аномально много конфигов, берём случайную выборку размера
  MAX_CONFIGS_PER_SUB вместо проверки всех (0 = без ограничения).
- Добавлена глобальная дедупликация URI между подписками: один и тот же
  конфиг, встретившийся в нескольких подписках, проверяется один раз.
- Поднят дефолт CONCURRENCY для самих sing-box-проверок.
- Добавлены чекпоинты: sources.txt дозаписывается частичным результатом
  каждые CHECKPOINT_EVERY проверок, чтобы при отмене джобы результат не
  терялся полностью.
"""

import base64
import json
import os
import random
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
CONCURRENCY = int(os.environ.get("CONCURRENCY", "40"))
SINGBOX_STARTUP_WAIT = float(os.environ.get("SINGBOX_STARTUP_WAIT", "0.6"))

SUB_FETCH_TIMEOUT = float(os.environ.get("SUB_FETCH_TIMEOUT", "10"))
SUB_FETCH_CONCURRENCY = int(os.environ.get("SUB_FETCH_CONCURRENCY", "30"))
MAX_CONFIGS_PER_SUB = int(os.environ.get("MAX_CONFIGS_PER_SUB", "0"))  # 0 = без лимита
CHECKPOINT_EVERY = int(os.environ.get("CHECKPOINT_EVERY", "200"))

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
        resp = requests.get(url, timeout=SUB_FETCH_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        print(f" [!] не удалось скачать подписку {url}: {e}", file=sys.stderr)
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

    if MAX_CONFIGS_PER_SUB and len(uniq) > MAX_CONFIGS_PER_SUB:
        uniq = random.sample(uniq, MAX_CONFIGS_PER_SUB)

    return uniq


def fetch_all_subscriptions(sub_urls: list[str]) -> dict[str, list[str]]:
    """Параллельно скачивает все подписки вместо последовательного for-цикла."""
    subs: dict[str, list[str]] = {}
    if not sub_urls:
        return subs

    with concurrent.futures.ThreadPoolExecutor(max_workers=SUB_FETCH_CONCURRENCY) as pool:
        futures = {pool.submit(fetch_subscription, url): url for url in sub_urls}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            url = futures[fut]
            try:
                configs = fut.result()
            except Exception as e:
                print(f" [!] ошибка подписки {url}: {e}", file=sys.stderr)
                configs = []
            subs[url] = configs
            done += 1
            print(f"[sub {done}/{len(sub_urls)}] {len(configs)} конфигов из {url}")

    return subs


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


def write_output(raw_lines: list[str], direct_entries: list[str],
                  subs: dict[str, list[str]], results: dict[str, bool]) -> list[str]:
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
    return output_lines


def main():
    raw_lines = collect_source_lines()
    print(f"Источников в списке: {len(raw_lines)}")
    if not raw_lines:
        print("Нечего проверять — пусто в sources.txt и в sources/")
        return

    direct_entries: list[str] = []
    sub_urls: list[str] = []

    for line in raw_lines:
        if line.startswith(CONFIG_PREFIXES):
            direct_entries.append(line)
        elif line.startswith(("http://", "https://")):
            sub_urls.append(line)
        else:
            print(f" [?] непонятная строка, пропускаю: {line[:60]}")

    print(f"Подписок для скачивания: {len(sub_urls)} (параллельно, {SUB_FETCH_CONCURRENCY} потоков)")
    subs = fetch_all_subscriptions(sub_urls)

    # Глобальная дедупликация: один и тот же конфиг может встречаться
    # и как прямая запись, и в нескольких подписках сразу — проверяем один раз.
    uri_owners: dict[str, list[str | None]] = {}
    for uri in direct_entries:
        uri_owners.setdefault(uri, []).append(None)
    for sub_url, configs in subs.items():
        for uri in configs:
            uri_owners.setdefault(uri, []).append(sub_url)

    tasks = list(uri_owners.keys())
    total_raw = len(direct_entries) + sum(len(c) for c in subs.values())
    print(f"Всего конфигов для реальной проверки: {len(tasks)} (без дублей, было бы {total_raw})")

    results: dict[str, bool] = {}
    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futures = {
                pool.submit(check_one, uri, BASE_PORT + i): uri
                for i, uri in enumerate(tasks)
            }
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                uri, ok, detail = fut.result()
                results[uri] = ok
                done += 1
                status = "OK  " if ok else "DEAD"
                print(f"[{done}/{len(tasks)}] {status} {detail} {uri[:70]}")

                if CHECKPOINT_EVERY and done % CHECKPOINT_EVERY == 0:
                    write_output(raw_lines, direct_entries, subs, results)
                    print(f"  [checkpoint] промежуточный sources.txt сохранён ({done}/{len(tasks)})")

    output_lines = write_output(raw_lines, direct_entries, subs, results)

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
