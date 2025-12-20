# stream/traffic.py

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import asyncio, json, random

router = APIRouter()

@router.get("/stream/traffic")
async def traffic_stream():
    """
    SSE endpoint that continuously streams live traffic metrics.
    """
    async def event_generator():
        while True:
            # Simulate live metrics
            data = {
                "packet_rate": random.randint(80, 120),
                "flow_rate": random.randint(30, 70),
                "bytes_per_sec": random.randint(10000, 50000)
            }
            # SSE format: each message prefixed by "data:" and ended by double newline
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(1)  # update every 1 second

    return StreamingResponse(event_generator(), media_type="text/event-stream")
