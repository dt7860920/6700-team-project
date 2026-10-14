import asyncio
import time

import httpx


async def one_request(client, payload):
    start = time.perf_counter()
    response = await client.post("/predict", json=payload)
    elapsed = time.perf_counter() - start
    return response, elapsed


async def main():
    payload = {"user_id": "test", "interests": ["reading"]}
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000", timeout=30.0
    ) as client:
        tasks = [one_request(client, payload) for _ in range(10)]
        batch_start = time.perf_counter()
        results = await asyncio.gather(*tasks)
        batch_elapsed = time.perf_counter() - batch_start
    responses = [r for r, _ in results]
    timings = [t for _, t in results]
    slowest_r = max(timings)
    slowest_ind = timings.index(slowest_r)
    for i, elapsed in enumerate(timings):
        print(f"Request {i}: {elapsed:.4f}s")
    print(f"Total Wall-Clock Time: {batch_elapsed:.3f}s")
    print(f"Slowest Individual Request: {slowest_r:.4f}s")
    print(f"Request Index With The Slowest Time: {slowest_ind}")
    print(f"All Succeeded: {all(r.status_code == 200 for r in responses)}")


asyncio.run(main())

# Wall-Clock Time (Pre-Fix): 15.058 Seconds
# Slowest Request (Pre-Fix): Request 9 (15.0485 Seconds)

# Wall-Clock Time (Post-Fix): 1.528 Seconds
# Slowest Request (Post-Fix): Request 0 (1.5251 Seconds)
