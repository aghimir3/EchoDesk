from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.mssql import JSON
from app.utils.db import Base
from datetime import datetime, timezone

class ProcessTicket(Base):
    __tablename__ = "process_tickets"
    process_id = Column(String(36), primary_key=True, index=True)
    ticket_number = Column(String, nullable=True)
    status = Column(String, default="started")
    updates = Column(JSON, default=list)  # List of update messages
    result = Column(JSON, nullable=True)  # Result or error as JSON
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))