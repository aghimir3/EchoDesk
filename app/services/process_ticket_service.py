from typing import Optional, List, Dict, Any
from app.utils.db import SessionLocal
from app.models.db_models import ProcessTicket

def create_process(process_id: str, status: str = "started", updates: List[str] = None, result: Optional[Dict] = None) -> None:
    session = SessionLocal()
    try:
        updates = updates or ["Process started"]
        new_process = ProcessTicket(
            process_id=process_id,
            status=status,
            updates=updates,
            result=result
        )
        session.add(new_process)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def update_process(process_id: str, status: Optional[str] = None, updates: Optional[List[str]] = None, 
                  result: Optional[Dict] = None, ticket_number: Optional[str] = None) -> None:
    session = SessionLocal()
    try:
        process = session.query(ProcessTicket).filter_by(process_id=process_id).first()
        if process:
            if status is not None:
                process.status = status
            if updates is not None:
                process.updates = updates
            if result is not None:
                process.result = result
            if ticket_number is not None:
                process.ticket_number = ticket_number
            session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def add_update(process_id: str, update: str) -> None:
    session = SessionLocal()
    try:
        process = session.query(ProcessTicket).filter_by(process_id=process_id).first()
        if process:
            process.updates = process.updates + [update]
            session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_process(process_id: str) -> Optional[ProcessTicket]:
    session = SessionLocal()
    try:
        return session.query(ProcessTicket).filter_by(process_id=process_id).first()
    finally:
        session.close()

def get_ticket_number(process_id: str) -> Optional[str]:
    process = get_process(process_id)
    return process.ticket_number if process else None