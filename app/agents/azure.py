from pydantic import BaseModel, Field
from typing import Optional, List
from agents import Agent
from app.tools.azure_tools import (
    create_user_action, get_user_info_action, remove_account_action,
    change_password_action, update_user_profile_action, disable_account_action,
    enable_account_action, add_user_to_group_action, remove_user_from_group_action
)

AZURE_PROMPT = (
    "You are an Azure AD specialist. Based on the 'action' field in the input, perform the corresponding task: "
    "- For 'create account', use create_user_action with first_name, last_name, license_type, and new_password if provided. "
    "- For actions like 'remove account', 'change password', 'update profile', 'disable account', 'enable account', 'add to group', 'remove from group': "
    "  - If 'email' is provided, use get_user_info_action with email to find the user_id. "
    "  - If 'email' is not provided, use get_user_info_action with first_name and last_name to find the user_id. "
    "  - Then, use the appropriate action function with the user_id and other provided fields. "
    "Return your output as a JSON object with the following fields: "
    "- 'status' (required): the status of the operation (e.g., 'created', 'updated', 'removed'). "
    "- 'user_id' (optional): the user ID of the affected user, if applicable. "
    "- 'display_name' (optional): the full display name of the user, if available. "
    "- 'license_type' (optional): the license type assigned, if applicable. "
    "- 'group_ids' (optional): list of group IDs affected, if applicable. "
    "- 'operation_timestamp' (optional): ISO timestamp of the operation, if available (e.g., '2025-03-26T13:00:00Z'). "
    "- 'error_message' (optional): any error message if the operation encountered an issue. "
    "Examples: "
    "- Input: {\"first_name\": \"John\", \"last_name\": \"Doe\", \"license_type\": \"Premium\", \"action\": \"create account\", \"new_password\": \"MySecurePass123\"} → Output: {\"status\": \"created\", \"user_id\": \"john.doe@company.com\", \"display_name\": \"John Doe\", \"license_type\": \"Premium\", \"operation_timestamp\": \"2025-03-26T13:00:00Z\"} "
    "- Input: {\"email\": \"bob.jones@company.com\", \"action\": \"change password\", \"new_password\": \"NewPass123!\"} → Output: {\"status\": \"password changed\", \"user_id\": \"bob.jones@company.com\", \"display_name\": \"Bob Jones\", \"operation_timestamp\": \"2025-03-26T13:01:00Z\"} "
    "- Input: {\"first_name\": \"Alice\", \"last_name\": \"Smith\", \"action\": \"add to group\", \"group_id\": \"group123\"} → Output: {\"status\": \"added to group\", \"user_id\": \"alice.smith@company.com\", \"group_ids\": [\"group123\"], \"operation_timestamp\": \"2025-03-26T13:02:00Z\"} "
    "- Input: {\"email\": \"kite.adams@example.com\", \"action\": \"remove account\"} → Output: {\"status\": \"removed\", \"user_id\": \"kite.adams@example.com\", \"operation_timestamp\": \"2025-03-26T13:03:00Z\"} "
)

class AzureOutput(BaseModel):
    status: str = Field(..., description="Status of the operation (e.g., 'created', 'updated', 'removed')")
    user_id: Optional[str] = Field(None, description="User ID of the affected user, if applicable")
    display_name: Optional[str] = Field(None, description="Full display name of the user, if available")
    license_type: Optional[str] = Field(None, description="License type assigned, if applicable")
    group_ids: Optional[List[str]] = Field(None, description="List of group IDs affected, if applicable")
    operation_timestamp: Optional[str] = Field(None, description="ISO timestamp of the operation, if available")
    error_message: Optional[str] = Field(None, description="Error message if the operation encountered an issue")

azure_agent = Agent(
    name="Azure Agent",
    instructions=AZURE_PROMPT,
    output_type=AzureOutput,
    tools=[
        create_user_action,
        get_user_info_action,
        remove_account_action,
        change_password_action,
        update_user_profile_action,
        disable_account_action,
        enable_account_action,
        add_user_to_group_action,
        remove_user_from_group_action,
    ],
)