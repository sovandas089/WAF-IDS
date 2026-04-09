from sqlalchemy import Column, Integer, String, DateTime, Float
from datetime import datetime
from backend.database import Base

class AlertLog(Base):
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, index=True)
    method = Column(String)
    path = Column(String)
    severity = Column(String, index=True)
    score = Column(Integer)
    reasons = Column(String)
    snippet = Column(String)

class BlockHistory(Base):
    __tablename__ = "block_history"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip = Column(String, index=True, unique=True)
    unblock_time = Column(Float) # Epoch time for automatic unblocking
    reason = Column(String)
