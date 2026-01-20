# main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.stats import router as stats_router
from api.analytics import router as analytics_router
from api.packets import router as packets_router
from api.alerts import router as alerts_router
from stream.traffic import router as stream_router

app = FastAPI(title="Network Anomaly Detection API")

# (Optional) Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers; we could use prefixes like "/api" or others as needed
app.include_router(stats_router, prefix="/api")
app.include_router(analytics_router, prefix="/api")
app.include_router(packets_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(stream_router)  # SSE endpoints under /stream

