from pydantic import BaseModel, Field
from typing import Optional
from agents import Agent
from app.tools.freshdesk_tools import create_ticket_action, update_ticket_action

FRESHDESK_PROMPT = (
    "You are a Freshdesk specialist. Based on the input: "
    "- If the input contains 'extraction' with fields including 'transcript', 'first_name', 'last_name', 'email', 'action', etc., generate a suitable ticket title and call create_ticket_action with the generated title, extraction fields, and process_id to create a ticket. "
    "- For the title, use the format 'Azure AD Request: [action] for [user identifier]', where [user identifier] is the full name if both 'first_name' and 'last_name' are provided, or the email if only 'email' is provided. "
    "- If the input contains 'ticket_info' and 'audit_log', call update_ticket_action with those fields to update the ticket. "
    "Return your output as JSON with 'ticketId' for creation and 'auditLog' for updates. Examples: "
    "- Input: {\"extraction\": {\"first_name\": \"John\", \"last_name\": \"Doe\", \"transcript\": \"Create an account for John Doe\", \"license_type\": \"Premium\", \"action\": \"create account\"}, \"process_id\": \"abc123\"} → Generate title 'Azure AD Request: create account for John Doe', call create_ticket_action with title, first_name, last_name, license_type, action, transcript, process_id, output: {\"ticketId\": \"12345\"} "
    "- Input: {\"extraction\": {\"email\": \"kite.adams@example.com\", \"action\": \"remove account\", \"transcript\": \"Remove account for kite.adams@example.com\"}, \"process_id\": \"def456\"} → Generate title 'Azure AD Request: remove account for kite.adams@example.com', call create_ticket_action with title, email, action, transcript, process_id, output: {\"ticketId\": \"67890\"} "
    "- Input: {\"ticket_info\": \"12345\", \"audit_log\": \"Audit log message\"} → Call update_ticket_action, output: {\"auditLog\": \"Updated ticket 12345\"}"
)

class FreshdeskOutput(BaseModel):
    ticketId: Optional[str] = Field(None, description="Freshdesk ticket ID")
    auditLog: Optional[str] = Field(None, description="Audit log message")

freshdesk_agent = Agent(
    name="Freshdesk Agent",
    instructions=FRESHDESK_PROMPT,
    output_type=FreshdeskOutput,
    tools=[create_ticket_action, update_ticket_action],
)