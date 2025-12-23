# api/analytics.py

from fastapi import APIRouter
from models.charts import AttackDistribution, TimeTrends
from services.traffic import get_attack_distribution, get_time_trends
from services.traffic import get_traffic_history

router = APIRouter(tags=["Analytics"])

@router.get("/analytics/attack_distribution", response_model=AttackDistribution)
async def attack_distribution():
    """
    Distribution of attack types vs normal traffic.
    """
    return get_attack_distribution()

@router.get("/analytics/time_trends", response_model=TimeTrends)
async def time_trends():
    """
    Time series trends for packet rate, flow rate, and bytes per second.
    """
    return get_time_trends()

@router.get("/analytics/traffic_history")
async def traffic_history():
    return get_traffic_history()
