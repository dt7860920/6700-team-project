# Discussion: Async Responsiveness

## Step-by-step trace of one request
| Step | Computing or Waiting | On what | Approx. duration |
|---|---|---|---|
| Receive request, validate with Pydantic | Computing | CPU | <1ms |
| Call model.predict() | Waiting (blocking version) | Model inference | 1.5s |
| Serialize response | Computing | CPU | <1ms |

## Measurements (10 concurrent requests)

**Before (blocking, see tag `blocking-version`):**
- Total wall-clock time: 15.06s
- Slowest individual request: 15.05s

**After (fixed with `asyncio.to_thread`):**
- Total wall-clock time: 1.53s
- Slowest individual request: 1.53s

## What caused the difference
In the blocking version the single-threaded event loop ran `model.predict()`
synchronously inside an `async def` handler, so all 10 requests were served
strictly one after another (~10 x 1.5s). Offloading the blocking call to a
worker thread with `asyncio.to_thread` lets FastAPI handle the 10 calls
concurrently, so wall-clock time drops to roughly a single request's latency.

The measurement script is `scripts/measure_concurrency.py`; the automated
regression test is `tests/test_responsiveness.py`.
