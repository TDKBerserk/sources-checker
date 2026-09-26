#!/usr/bin/env python3
"""
Проверка источников через реальный sing-box туннель.

Логика:

1. Прямой конфиг:
   vless://
   vmess://
   trojan://
   ss://

   Живой  -> оставить
   Мёртвый -> удалить

2. Подписка:
   http://
   https://

   Успешно скачалась + есть хотя бы один живой конфиг
       -> оставить ИМЕННО ССЫЛКУ НА ПОДПИСКУ

   Успешно скачалась + 0 живых конфигов
       -> удалить подписку

   Не удалось скачать / timeout / HTTP ошибка
       -> НЕ удалять подписку

Никакие конфиги из подписки отдельно в sources.txt НЕ вытаскиваются.

Результат:
    sources.txt

Отчёт:
    check_report.txt

Поддерживается шардинг для GitHub Actions.
"""

import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import requests

from proxy_parsers import parse_uri


# ---------------------------------------------------------
# Настройки
# ---------------------------------------------------------

SOURCES_ROOT = Path(".")
SOURCES_DIR = Path("sources")

OUTPUT_FILE = Path(
    os.environ.get(
        "OUTPUT_FILE",
        "sources.txt"
    )
)

REPORT_FILE = Path(
    os.environ.get(
        "REPORT_FILE",
        "check_report.txt"
    )
)

SHARD_INDEX = int(
    os.environ.get(
        "SHARD_INDEX",
        "0"
    )
)

TOTAL_SHARDS = max(
    1,
    int(
        os.environ.get(
            "TOTAL_SHARDS",
            "1"
        )
    )
)

TEST_URL = os.environ.get(
    "TEST_URL",
    "https://www.gstatic.com/generate_204"
)

TEST_TIMEOUT = float(
    os.environ.get(
        "TEST_TIMEOUT",
        "5"
    )
)

CONCURRENCY = int(
    os.environ.get(
        "CONCURRENCY",
        "24"
    )
)

SUB_FETCH_CONCURRENCY = int(
    os.environ.get(
        "SUB_FETCH_CONCURRENCY",
        "40"
    )
)

SUB_FETCH_TIMEOUT = float(
    os.environ.get(
        "SUB_FETCH_TIMEOUT",
        "10"
    )
)

SINGBOX_STARTUP_WAIT = float(
    os.environ.get(
        "SINGBOX_STARTUP_WAIT",
        "0.6"
    )
)

CHECKPOINT_EVERY = int(
    os.environ.get(
        "CHECKPOINT_EVERY",
        "200"
    )
)

BASE_PORT = 20000

CONFIG_PREFIXES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
)

URI_PATTERN = re.compile(
    r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+"
)


# ---------------------------------------------------------
# Чтение источников
# ---------------------------------------------------------

def collect_source_lines():
    """
    Читает sources.txt и, если существует,
    дополнительные txt-файлы из sources/.

    Для GitHub shard каждая исходная строка
    попадает только в один shard.
    """

    lines = []

    root_sources = SOURCES_ROOT / "sources.txt"

    if root_sources.exists():

        lines.extend(
            root_sources.read_text(
                encoding="utf-8",
                errors="ignore"
            ).splitlines()
        )

    if SOURCES_DIR.exists():

        for file in sorted(
            SOURCES_DIR.glob("*.txt")
        ):

            lines.extend(
                file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).splitlines()
            )

    result = []
    seen = set()

    for line in lines:

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line in seen:
            continue

        seen.add(line)
        result.append(line)

    # -----------------------------------------------------
    # Шардинг
    # -----------------------------------------------------

    if TOTAL_SHARDS > 1:

        sharded = []

        for line in result:

            value = int(
                hashlib.sha1(
                    line.encode(
                        "utf-8",
                        "ignore"
                    )
                ).hexdigest(),
                16
            )

            if value % TOTAL_SHARDS == SHARD_INDEX:

                sharded.append(line)

        result = sharded

    return result


# ---------------------------------------------------------
# Загрузка подписки
# ---------------------------------------------------------

def fetch_subscription(url):
    """
    Возвращает:

        ("ok", configs)

    если подписка успешно скачалась,

        ("error", [])

    если скачать не удалось.
    """

    try:

        response = requests.get(
            url,
            timeout=SUB_FETCH_TIMEOUT,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(sources-checker)"
                )
            }
        )

        response.raise_for_status()

        text = response.text

    except Exception as exc:

        print(
            f"[SUB ERROR] {url} -> {exc}",
            file=sys.stderr
        )

        # Очень важно:
        # ошибка скачивания НЕ означает,
        # что подписка мёртвая.
        return "error", []

    stripped = text.strip()

    candidates = []

    # -----------------------------------------------------
    # Сначала пробуем обычный текст
    # -----------------------------------------------------

    candidates.extend(
        URI_PATTERN.findall(
            text
        )
    )

    # -----------------------------------------------------
    # Потом Base64
    # -----------------------------------------------------

    try:

        padding = "=" * (
            -len(stripped) % 4
        )

        import base64

        decoded = base64.b64decode(
            stripped + padding
        ).decode(
            "utf-8",
            errors="ignore"
        )

        candidates.extend(
            URI_PATTERN.findall(
                decoded
            )
        )

    except Exception:
        pass

    # -----------------------------------------------------
    # Дедупликация
    # -----------------------------------------------------

    configs = []
    seen = set()

    for config in candidates:

        config = config.strip()

        if not config:
            continue

        if config in seen:
            continue

        seen.add(config)
        configs.append(config)

    return "ok", configs


# ---------------------------------------------------------
# Параллельная загрузка подписок
# ---------------------------------------------------------

def fetch_all_subscriptions(urls):

    result = {}

    if not urls:
        return result

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=SUB_FETCH_CONCURRENCY
    ) as executor:

        futures = {
            executor.submit(
                fetch_subscription,
                url
            ): url
            for url in urls
        }

        done = 0

        for future in concurrent.futures.as_completed(
            futures
        ):

            url = futures[future]

            try:

                status, configs = future.result()

            except Exception as exc:

                status = "error"
                configs = []

                print(
                    f"[SUB EXCEPTION] "
                    f"{url} -> {exc}",
                    file=sys.stderr
                )

            result[url] = (
                status,
                configs
            )

            done += 1

            if status == "ok":

                print(
                    f"[SUB {done}/{len(urls)}] "
                    f"{len(configs)} конфигов: "
                    f"{url}"
                )

            else:

                print(
                    f"[SUB {done}/{len(urls)}] "
                    f"ОШИБКА СКАЧИВАНИЯ: "
                    f"{url}"
                )

    return result


# ---------------------------------------------------------
# Sing-box
# ---------------------------------------------------------

def build_singbox_config(
    outbound,
    port
):

    return {
        "log": {
            "level": "error"
        },

        "inbounds": [
            {
                "type": "mixed",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": port
            }
        ],

        "outbounds": [
            outbound,
            {
                "type": "direct",
                "tag": "direct"
            }
        ]
    }


def check_one(
    uri,
    port
):

    protocol, outbound = parse_uri(
        uri
    )

    if not outbound:

        return (
            uri,
            False,
            "не распознан формат"
        )

    config = build_singbox_config(
        outbound,
        port
    )

    config_path = Path(
        f"/tmp/sb_cfg_{port}.json"
    )

    config_path.write_text(
        json.dumps(
            config,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    process = None

    try:

        process = subprocess.Popen(
            [
                "sing-box",
                "run",
                "-c",
                str(config_path)
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(
            SINGBOX_STARTUP_WAIT
        )

        if process.poll() is not None:

            return (
                uri,
                False,
                "sing-box не запустился"
            )

        proxies = {
            "http":
                f"http://127.0.0.1:{port}",

            "https":
                f"http://127.0.0.1:{port}"
        }

        started = time.time()

        response = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TEST_TIMEOUT
        )

        latency = int(
            (
                time.time()
                - started
            ) * 1000
        )

        if response.status_code < 400:

            return (
                uri,
                True,
                f"OK {response.status_code} "
                f"{latency}ms"
            )

        return (
            uri,
            False,
            f"HTTP {response.status_code}"
        )

    except Exception as exc:

        return (
            uri,
            False,
            str(exc)
        )

    finally:

        if process is not None:

            process.terminate()

            try:

                process.wait(
                    timeout=3
                )

            except Exception:

                process.kill()

        config_path.unlink(
            missing_ok=True
        )


# ---------------------------------------------------------
# Проверка конфигов
# ---------------------------------------------------------

def check_configs(configs):

    if not configs:
        return {}

    unique = []
    seen = set()

    for config in configs:

        if config in seen:
            continue

        seen.add(config)
        unique.append(config)

    results = {}

    print(
        f"Конфигов для проверки: "
        f"{len(unique)}"
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=CONCURRENCY
    ) as executor:

        futures = {}

        for index, uri in enumerate(
            unique
        ):

            port = (
                BASE_PORT
                + (
                    index
                    % max(
                        CONCURRENCY,
                        1
                    )
                )
            )

            future = executor.submit(
                check_one,
                uri,
                port
            )

            futures[future] = uri

        completed = 0

        for future in concurrent.futures.as_completed(
            futures
        ):

            uri, alive, detail = (
                future.result()
            )

            results[uri] = alive

            completed += 1

            print(
                f"[{completed}/{len(unique)}] "
                f"{'OK' if alive else 'DEAD'} "
                f"{detail}"
            )

    return results


# ---------------------------------------------------------
# Формирование результата
# ---------------------------------------------------------

def build_output(
    raw_lines,
    direct_results,
    subscriptions,
    config_results
):

    output = []

    for line in raw_lines:

        # -------------------------------------------------
        # Прямой конфиг
        # -------------------------------------------------

        if line.startswith(
            CONFIG_PREFIXES
        ):

            if direct_results.get(
                line,
                False
            ):

                output.append(
                    line
                )

            continue

        # -------------------------------------------------
        # Подписка
        # -------------------------------------------------

        if line.startswith(
            (
                "http://",
                "https://"
            )
        ):

            status, configs = (
                subscriptions.get(
                    line,
                    (
                        "error",
                        []
                    )
                )
            )

            # -------------------------------------------------
            # Не удалось скачать:
            # оставляем ссылку, чтобы временная ошибка
            # не уничтожила хороший источник.
            # -------------------------------------------------

            if status != "ok":

                output.append(
                    line
                )

                continue

            # -------------------------------------------------
            # Успешно скачали, но конфигов нет:
            # удалить.
            # -------------------------------------------------

            if not configs:

                continue

            # -------------------------------------------------
            # Есть хотя бы один живой конфиг:
            # оставляем САМУ ПОДПИСКУ.
            #
            # Никаких vless/vmess/ss/trojan отдельно.
            # -------------------------------------------------

            alive_count = sum(
                1
                for config in configs
                if config_results.get(
                    config,
                    False
                )
            )

            if alive_count > 0:

                output.append(
                    line
                )

            # Если alive_count == 0:
            # ничего не добавляем -> подписка удаляется.

    # Дедупликация
    final = []
    seen = set()

    for line in output:

        if line in seen:
            continue

        seen.add(line)
        final.append(line)

    OUTPUT_FILE.write_text(
        "\n".join(final)
        + (
            "\n"
            if final
            else ""
        ),
        encoding="utf-8"
    )

    return final


# ---------------------------------------------------------
# Отчёт
# ---------------------------------------------------------

def write_report(
    raw_lines,
    direct_results,
    subscriptions,
    config_results
):

    lines = []

    lines.append(
        f"SHARD: "
        f"{SHARD_INDEX}/"
        f"{TOTAL_SHARDS}"
    )

    lines.append(
        f"INPUT: "
        f"{len(raw_lines)}"
    )

    lines.append("")

    # -----------------------------------------------------
    # Подписки с рабочими конфигами
    # -----------------------------------------------------

    lines.append(
        "[SUBSCRIPTIONS_KEPT]"
    )

    for url, (
        status,
        configs
    ) in sorted(
        subscriptions.items()
    ):

        if status != "ok":
            continue

        alive = sum(
            1
            for config in configs
            if config_results.get(
                config,
                False
            )
        )

        if alive > 0:

            lines.append(
                f"{url} | "
                f"alive={alive}/"
                f"{len(configs)}"
            )

    lines.append("")

    # -----------------------------------------------------
    # Подписки удалённые
    # -----------------------------------------------------

    lines.append(
        "[SUBSCRIPTIONS_REMOVED]"
    )

    for url, (
        status,
        configs
    ) in sorted(
        subscriptions.items()
    ):

        if status != "ok":
            continue

        if not configs:

            lines.append(
                f"{url} | "
                f"NO_CONFIGS"
            )

            continue

        alive = sum(
            1
            for config in configs
            if config_results.get(
                config,
                False
            )
        )

        if alive == 0:

            lines.append(
                f"{url} | "
                f"alive=0/"
                f"{len(configs)}"
            )

    lines.append("")

    # -----------------------------------------------------
    # Ошибки скачивания
    # -----------------------------------------------------

    lines.append(
        "[SUBSCRIPTIONS_FETCH_ERROR]"
    )

    for url, (
        status,
        configs
    ) in sorted(
        subscriptions.items()
    ):

        if status != "ok":

            lines.append(
                url
            )

    lines.append("")

    # -----------------------------------------------------
    # Прямые конфиги
    # -----------------------------------------------------

    lines.append(
        "[DIRECT_CONFIGS_REMOVED]"
    )

    for uri, alive in sorted(
        direct_results.items()
    ):

        if not alive:

            lines.append(
                uri
            )

    REPORT_FILE.write_text(
        "\n".join(lines)
        + "\n",
        encoding="utf-8"
    )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    raw_lines = (
        collect_source_lines()
    )

    print(
        f"Источников этого shard: "
        f"{len(raw_lines)}"
    )

    if not raw_lines:

        OUTPUT_FILE.write_text(
            "",
            encoding="utf-8"
        )

        REPORT_FILE.write_text(
            "Пустой shard\n",
            encoding="utf-8"
        )

        return

    # -----------------------------------------------------
    # Прямые конфиги
    # -----------------------------------------------------

    direct_entries = [
        line
        for line in raw_lines
        if line.startswith(
            CONFIG_PREFIXES
        )
    ]

    # -----------------------------------------------------
    # Подписки
    # -----------------------------------------------------

    subscription_urls = [
        line
        for line in raw_lines
        if line.startswith(
            (
                "http://",
                "https://"
            )
        )
    ]

    print(
        f"Прямых конфигов: "
        f"{len(direct_entries)}"
    )

    print(
        f"Подписок: "
        f"{len(subscription_urls)}"
    )

    # -----------------------------------------------------
    # Скачиваем подписки
    # -----------------------------------------------------

    subscriptions = (
        fetch_all_subscriptions(
            subscription_urls
        )
    )

    # -----------------------------------------------------
    # Собираем все конфиги подписок
    # -----------------------------------------------------

    subscription_configs = []

    for status, configs in (
        subscriptions.values()
    ):

        if status != "ok":
            continue

        subscription_configs.extend(
            configs
        )

    # -----------------------------------------------------
    # Проверяем прямые + подписочные конфиги
    # -----------------------------------------------------

    all_configs = (
        direct_entries
        + subscription_configs
    )

    unique_configs = []
    seen = set()

    for config in all_configs:

        if config in seen:
            continue

        seen.add(config)

        unique_configs.append(
            config
        )

    print(
        f"Уникальных конфигов "
        f"для проверки: "
        f"{len(unique_configs)}"
    )

    config_results = (
        check_configs(
            unique_configs
        )
    )

    # -----------------------------------------------------
    # Результаты прямых конфигов
    # -----------------------------------------------------

    direct_results = {
        uri:
            config_results.get(
                uri,
                False
            )
        for uri in direct_entries
    }

    # -----------------------------------------------------
    # Сохраняем sources.txt
    # -----------------------------------------------------

    final = build_output(
        raw_lines,
        direct_results,
        subscriptions,
        config_results
    )

    # -----------------------------------------------------
    # Отчёт
    # -----------------------------------------------------

    write_report(
        raw_lines,
        direct_results,
        subscriptions,
        config_results
    )

    # -----------------------------------------------------
    # Статистика
    # -----------------------------------------------------

    kept_subs = 0
    removed_subs = 0
    fetch_errors = 0

    for status, configs in (
        subscriptions.values()
    ):

        if status != "ok":

            fetch_errors += 1
            continue

        alive = sum(
            1
            for config in configs
            if config_results.get(
                config,
                False
            )
        )

        if alive > 0:

            kept_subs += 1

        else:

            removed_subs += 1

    dead_direct = sum(
        1
        for alive in direct_results.values()
        if not alive
    )

    print("")
    print(
        "=============================="
    )
    print(
        "ПРОВЕРКА ЗАВЕРШЕНА"
    )
    print(
        "=============================="
    )

    print(
        f"Подписок оставлено: "
        f"{kept_subs}"
    )

    print(
        f"Подписок удалено: "
        f"{removed_subs}"
    )

    print(
        f"Ошибок скачивания: "
        f"{fetch_errors}"
    )

    print(
        f"Прямых конфигов удалено: "
        f"{dead_direct}"
    )

    print(
        f"Итоговых строк: "
        f"{len(final)}"
    )

    print(
        f"Файл: "
        f"{OUTPUT_FILE}"
    )

    print(
        f"Отчёт: "
        f"{REPORT_FILE}"
    )


if __name__ == "__main__":
    main()
