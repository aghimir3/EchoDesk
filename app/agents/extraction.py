from pydantic import BaseModel, Field
from typing import Optional
from agents import Agent

EXTRACTION_PROMPT = (
    "Analyze the user's request and extract all relevant information needed to perform helpdesk tasks. "
    "Include the original transcript in the output JSON under the key 'transcript'. "
    "Extract the following fields: first_name, last_name, email (if provided), license_type (if provided), and action. "
    "Additionally, if available, extract department, job_title, group_id, and new_password (if the user specifies a password for account creation or password change). "
    "Return the output strictly as a JSON object with keys transcript, first_name, last_name, email, license_type, action, "
    "department, job_title, group_id, and new_password. Examples: "
    "- Input: 'Create an account for John Doe with Premium license and password MySecurePass123' → Output: {\"transcript\": \"Create an account for John Doe with Premium license and password MySecurePass123\", \"first_name\": \"John\", \"last_name\": \"Doe\", \"license_type\": \"Premium\", \"action\": \"create account\", \"new_password\": \"MySecurePass123\"} "
    "- Input: 'Create an account for Jane Smith' → Output: {\"transcript\": \"Create an account for Jane Smith\", \"first_name\": \"Jane\", \"last_name\": \"Smith\", \"action\": \"create account\"} "
    "- Input: 'Change password for Bob Jones to NewPass123!' → Output: {\"transcript\": \"Change password for Bob Jones to NewPass123!\", \"first_name\": \"Bob\", \"last_name\": \"Jones\", \"action\": \"change password\", \"new_password\": \"NewPass123!\"} "
    "- Input: 'Update profile for Alice Johnson with department IT' → Output: {\"transcript\": \"Update profile for Alice Johnson with department IT\", \"first_name\": \"Alice\", \"last_name\": \"Johnson\", \"action\": \"update profile\", \"department\": \"IT\"} "
    "- Input: 'Remove account for kite.adams@example.com' → Output: {\"transcript\": \"Remove account for kite.adams@example.com\", \"action\": \"remove account\", \"email\": \"kite.adams@example.com\"} "
)

class ExtractionOutput(BaseModel):
    transcript: str = Field(..., description="Original user transcript")
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")
    email: Optional[str] = Field(None, description="User's email address")
    license_type: Optional[str] = Field(None, description="License type, if specified")
    action: str = Field(..., description="Requested action (e.g., 'create account')")
    department: Optional[str] = Field(None, description="Department, if specified")
    job_title: Optional[str] = Field(None, description="Job title, if specified")
    group_id: Optional[str] = Field(None, description="Group ID, if specified")
    new_password: Optional[str] = Field(None, description="New password, if specified")

extraction_agent = Agent(
    name="Extraction Agent",
    instructions=EXTRACTION_PROMPT,
    output_type=ExtractionOutput,
)