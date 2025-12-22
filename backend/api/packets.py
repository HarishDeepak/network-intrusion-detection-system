# api/packets.py

from typing import List
from fastapi import APIRouter, Query
from models.packet import PacketWithPrediction
from services.traffic import generate_packets

router = APIRouter(tags=["Packets"])

@router.get("/packets", response_model=List[PacketWithPrediction])
async def list_packets(count: int = Query(5, ge=1, le=100)):
    """
    List recent packet data with simulated ML predictions.
    Query parameter 'count' specifies how many packets to generate.
    """
    return generate_packets(count)
