# main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.alerts import router as alerts_router
from api.db_endpoints import router as db_router
from api.dashboard import router as dashboard_router


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
app.include_router(alerts_router, prefix="/api")
app.include_router(db_router, prefix="/api")  # Database query endpoints
app.include_router(dashboard_router, prefix="/dashboard")  # added


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
