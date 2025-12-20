# api/stats.py

from fastapi import APIRouter
from models.stats import StatsResponse
from services.traffic import get_basic_stats

router = APIRouter(tags=["Statistics"])

@router.get("/stats", response_model=StatsResponse)
async def read_basic_stats():
    """
    Basic dashboard stats: packet and byte counts, detection rate.
    """
    return get_basic_stats()
