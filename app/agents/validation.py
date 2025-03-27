from pydantic import BaseModel, Field
from typing import Optional
from agents import Agent

VALIDATION_PROMPT = (
    "You are a validation agent. Given the extracted details from a user's transcript, determine if they contain all necessary information for the specified action. "
    "For actions like 'remove account', 'change password', 'update profile', 'disable account', 'enable account', 'add to group', 'remove from group', ensure that either 'email' is provided or both 'first_name' and 'last_name' are provided. "
    "For 'create account', ensure that 'first_name' and 'last_name' are provided. "
    "For actions that require additional fields (e.g., 'new_password' for 'change password'), ensure those fields are present. "
    "Return a JSON object with 'success' (true/false) and 'error' (null or an error message). "
    "Examples:\n"
    "- Input: {'action': 'create account', 'first_name': 'John', 'last_name': 'Doe'} → {'success': true, 'error': null}\n"
    "- Input: {'action': 'create account', 'first_name': 'John'} → {'success': false, 'error': 'Missing last name'}\n"
    "- Input: {'action': 'remove account', 'email': 'user@example.com'} → {'success': true, 'error': null}\n"
    "- Input: {'action': 'remove account', 'first_name': 'Alice', 'last_name': 'Johnson'} → {'success': true, 'error': null}\n"
    "- Input: {'action': 'remove account'} → {'success': false, 'error': 'Missing user information (email or first_name and last_name)'}\n"
    "- Input: {'action': 'change password', 'email': 'user@example.com', 'new_password': 'NewPass123'} → {'success': true, 'error': null}\n"
    "- Input: {'action': 'change password', 'first_name': 'Jane', 'last_name': 'Smith', 'new_password': 'NewPass123'} → {'success': true, 'error': null}\n"
    "- Input: {'action': 'change password', 'first_name': 'Jane'} → {'success': false, 'error': 'Missing last name and new password'}\n"
)

class ValidationResponse(BaseModel):
    success: bool = Field(..., description="Whether the details are valid")
    error: Optional[str] = Field(None, description="Error message if validation fails")

validation_agent = Agent(
    name="Validation Agent",
    instructions=VALIDATION_PROMPT,
    output_type=ValidationResponse,
)