from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database.db_session import get_db
from services.traffic import get_recent_zeek_traffic

router = APIRouter(tags=["Traffic"])

@router.get("/api/traffic")
def fetch_traffic(limit: int = 20, db: Session = Depends(get_db)):
    return get_recent_zeek_traffic(db, limit)
