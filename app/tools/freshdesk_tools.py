import os
import requests
import logging
from typing import Optional
from agents import function_tool
from tenacity import retry, stop_after_attempt, wait_fixed
from app.utils.freshdesk_utils import get_freshdesk_auth, get_freshdesk_url

logger = logging.getLogger(__name__)

@function_tool
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def create_ticket_action(
    title: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    email: Optional[str] = None,
    license_type: Optional[str] = None,
    action: str = None,
    department: Optional[str] = None,
    job_title: Optional[str] = None,
    group_id: Optional[str] = None,
    new_password: Optional[str] = None,
    transcript: Optional[str] = None,
    process_id: Optional[str] = None
) -> dict:
    logger.debug("Creating Freshdesk ticket with title: %s", title)
    url = get_freshdesk_url("api/v2/tickets")
    email_pattern = os.environ.get("EMAIL_PATTERN", "@yourdomain.com")
    ticket_email = email if email else f"{first_name.lower()}.{last_name.lower()}{email_pattern}" if first_name and last_name else "unknown@example.com"
    description = f"Action: {action}\n"
    if first_name and last_name:
        description += f"Name: {first_name} {last_name}\n"
    if email:
        description += f"Email: {email}\n"
    if license_type:
        description += f"License type: {license_type}\n"
    if department:
        description += f"Department: {department}\n"
    if job_title:
        description += f"Job title: {job_title}\n"
    if group_id:
        description += f"Group ID: {group_id}\n"
    if new_password:
        description += f"New password: {new_password}\n"
    if transcript:
        description += f"\nOriginal request: {transcript}"
    if process_id:
        description += f"\nProcess ID: {process_id}"
    payload = {
        "subject": title,
        "description": description,
        "email": ticket_email,
        "priority": 2,
        "status": 2
    }
    response = requests.post(url, json=payload, auth=get_freshdesk_auth())
    response.raise_for_status()
    ticket_data = response.json()
    if not isinstance(ticket_data, dict) or "id" not in ticket_data:
        logger.error("Ticket creation failed: Invalid response data")
        raise Exception("Ticket creation did not return valid JSON data.")
    ticket_id = str(ticket_data.get("id"))
    logger.info("Freshdesk ticket created: %s", ticket_id)
    return {"ticketId": ticket_id}

@function_tool
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def update_ticket_action(ticket_info: str, audit_log: str) -> dict:
    logger.debug("Updating Freshdesk ticket %s", ticket_info)
    ticket_id = ticket_info
    if not ticket_id:
        logger.error("Ticket ID is missing for update")
        raise Exception("Ticket ID is missing.")
    url = get_freshdesk_url(f"api/v2/tickets/{ticket_id}/notes")
    payload = {"body": audit_log, "private": False}
    response = requests.post(url, json=payload, auth=get_freshdesk_auth())
    response.raise_for_status()
    logger.info("Freshdesk ticket %s updated with audit log", ticket_id)
    return {"ticketId": ticket_id, "auditLog": audit_log}