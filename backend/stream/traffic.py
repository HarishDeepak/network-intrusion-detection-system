# stream/traffic.py

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from services.traffic import add_traffic_point

import asyncio, json, random, time

router = APIRouter()

@router.get("/stream/traffic")
async def traffic_stream():
    """
    SSE endpoint that continuously streams live traffic metrics.
    """
    async def event_generator():
        while True:
            data = {
                "timestamp": time.time(),   # ✅ THIS IS THE FIX
                "packet_rate": random.randint(80, 120),
                "flow_rate": random.randint(30, 70),
                "bytes_per_sec": random.randint(10000, 50000)
            }
            add_traffic_point(data) 
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
