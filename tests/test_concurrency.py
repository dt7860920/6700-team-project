import asyncio
import time
import httpx

async def main():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        payload = {"user_id": "test", "interests": ["reading"]}
        start = time.perf_counter()
        tasks = [client.post("/predict", json=payload) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start
        print(f"Total wall-clock time: {elapsed:.2f}s")
        print(f"All succeeded: {all(r.status_code == 200 for r in results)}")

asyncio.run(main())

#Wall-Clock Time: 1.54 Seconds