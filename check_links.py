#!/usr/bin/env python3
"""
Проверка живости ссылок из sources.txt.
Запускать локально или в GitHub Actions (matrix/step в parser.yml / update.yml).

Использование:
    pip install aiohttp
    python check_links.py sources_dedup.txt

На выходе:
    alive.txt  — ссылки, ответившие 2xx/3xx
    dead.txt   — ссылки с ошибкой, таймаутом или 4xx/5xx
    report.txt — сводка по каждой ссылке (код ответа / ошибка)
"""

import asyncio
import sys
import aiohttp

CONCURRENCY = 50          # одновременных запросов
TIMEOUT = 15              # секунд на запрос
RETRIES = 2               # повторов при ошибке/таймауте
USER_AGENT = "Mozilla/5.0 (compatible; LinkChecker/1.0)"


async def check_one(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore):
    async with sem:
        last_err = None
        for attempt in range(RETRIES + 1):
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                    allow_redirects=True,
                    headers={"User-Agent": USER_AGENT},
                ) as resp:
                    ok = resp.status < 400
                    return url, ok, str(resp.status)
            except Exception as e:
                last_err = e
                await asyncio.sleep(0.5)
        return url, False, f"ERROR: {last_err!r}"


async def main(path: str):
    with open(path, encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    sem = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_one(session, u, sem) for u in urls]
        results = []
        done = 0
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            done += 1
            if done % 100 == 0:
                print(f"{done}/{len(urls)} проверено...", file=sys.stderr)

    # сохраняем в исходном порядке файла
    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: order[r[0]])

    alive = [u for u, ok, _ in results if ok]
    dead = [u for u, ok, _ in results if not ok]

    with open("alive.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(alive) + "\n")
    with open("dead.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(dead) + "\n")
    with open("report.txt", "w", encoding="utf-8") as f:
        for u, ok, status in results:
            f.write(f"{'OK ' if ok else 'DEAD'}\t{status}\t{u}\n")

    print(f"\nГотово: {len(alive)} живых, {len(dead)} мёртвых из {len(urls)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python check_links.py <файл_со_ссылками>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
