import os
import re
import json
import uvicorn
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Any, List
from functools import wraps
from agents import Agent, Runner, function_tool
from tenacity import retry, stop_after_attempt, wait_fixed
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize FastAPI app
app = FastAPI()

# Utility Functions for Azure API
def get_azure_access_token() -> str:
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    }
    response = requests.post(token_url, data=token_data)
    response.raise_for_status()
    access_token = response.json().get("access_token")
    if not access_token:
        raise Exception("Failed to acquire Azure access token.")
    return access_token

def get_azure_headers(content_type: Optional[str] = None) -> dict:
    token = get_azure_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    return headers

# Freshdesk Helper Functions
def get_freshdesk_auth() -> tuple:
    api_key = os.environ.get("FRESHDESK_API_KEY")
    return (api_key, "X")

def get_freshdesk_url(path: str) -> str:
    freshdesk_domain = os.environ.get("FRESHDESK_DOMAIN")
    return f"https://{freshdesk_domain}/{path}"

# Standard Response Model
class StandardResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None

# Decorator to Standardize Function Tool Output
def standardize_output(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return StandardResponse(success=True, data=result).model_dump()
        except Exception as e:
            return StandardResponse(success=False, error=str(e)).model_dump()
    return wrapper

# Pydantic Model for Enhanced Extraction Output
class EnhancedExtractionOutput(BaseModel):
    first_name: str
    last_name: str
    license_type: Optional[str] = None
    action: str
    department: Optional[str] = None
    job_title: Optional[str] = None
    group_id: Optional[str] = None
    new_password: Optional[str] = None

# Pydantic Model for Freshdesk Output
class FreshdeskOutput(BaseModel):
    ticketId: Optional[str] = None
    auditLog: Optional[str] = None

# Helper Function to Extract JSON from Text Output
def extract_json_from_text(text: str) -> dict:
    match = re.search(r"```json(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if match:
        json_str = match.group(1).strip()
    else:
        match = re.search(r"({.*})", text, re.DOTALL)
        if match:
            json_str = match.group(1).strip()
        else:
            raise Exception("No JSON found in the text output.")
    try:
        return json.loads(json_str)
    except Exception as e:
        raise Exception(f"Failed to parse JSON: {e}")

# Helper Function to Unwrap Standardized Responses
def unwrap_response(response):
    if (
        isinstance(response, dict)
        and "success" in response
        and "data" in response
        and "error" in response
        and response.get("success") is True
        and response.get("error") is None
    ):
        return response["data"]
    return response

# Helper function to escape OData filter values
def escape_odata_value(value: str) -> str:
    """Escape single quotes in OData filter values by doubling them."""
    return value.replace("'", "''")

# Function Tools for Freshdesk
@function_tool
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def create_ticket_action(
    first_name: str,
    last_name: str,
    license_type: Optional[str],
    action: str,
    department: Optional[str] = None,
    job_title: Optional[str] = None,
    group_id: Optional[str] = None,
    new_password: Optional[str] = None
) -> dict:
    url = get_freshdesk_url("api/v2/tickets")
    email_pattern = os.environ.get("EMAIL_PATTERN", "@yourdomain.com")
    email = f"{first_name.lower()}.{last_name.lower()}{email_pattern}"
    subject = f"Azure AD Request: {action} for {first_name} {last_name}"
    description = f"Please {action} for {first_name} {last_name}"
    if license_type:
        description += f" with a {license_type} license"
    description += "."
    if department:
        description += f" Department: {department}."
    if job_title:
        description += f" Job Title: {job_title}."
    if group_id:
        description += f" Group ID: {group_id}."
    if new_password:
        description += f" New Password: {new_password}."
    payload = {
        "subject": subject,
        "description": description,
        "email": email,
        "priority": 2,
        "status": 2
    }
    response = requests.post(url, json=payload, auth=get_freshdesk_auth())
    response.raise_for_status()
    ticket_data = response.json()
    if not isinstance(ticket_data, dict) or "id" not in ticket_data:
        raise Exception("Ticket creation did not return valid JSON data.")
    return {"ticketId": str(ticket_data.get("id"))}

@function_tool
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def update_ticket_action(ticket_info: str, audit_log: str) -> dict:
    ticket_id = ticket_info
    if not ticket_id:
        raise Exception("Ticket ID is missing.")
    url = get_freshdesk_url(f"api/v2/tickets/{ticket_id}/notes")
    payload = {"body": audit_log, "private": False}
    response = requests.post(url, json=payload, auth=get_freshdesk_auth())
    response.raise_for_status()
    return {"ticketId": ticket_id, "auditLog": audit_log}

# Function Tools for Azure
@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def create_user_action(first_name: str, last_name: str, license_type: Optional[str], new_password: Optional[str] = None) -> dict:
    email_pattern = os.environ.get("EMAIL_PATTERN", "@yourdomain.com")
    user_principal_name = f"{first_name.lower()}.{last_name.lower()}{email_pattern}"
    # Use provided password or fallback to default from .env
    password = new_password if new_password else os.environ.get("DEFAULT_PASSWORD", "SecureRandomPassword123!")
    headers = get_azure_headers("application/json")
    user_payload = {
        "accountEnabled": True,
        "displayName": f"{first_name} {last_name}",
        "mailNickname": first_name.lower(),
        "userPrincipalName": user_principal_name,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": password
        }
    }
    create_user_url = "https://graph.microsoft.com/v1.0/users"
    response = requests.post(create_user_url, json=user_payload, headers=headers)
    response.raise_for_status()
    user_data = response.json()
    user_id = user_data.get("id")
    assigned_license = None
    return {
        "azure": {
            "userPrincipalName": user_principal_name,
            "displayName": user_data.get("displayName"),
            "assignedLicense": assigned_license
        }
    }

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def get_user_info_action(
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    email: Optional[str] = None,
    display_name: Optional[str] = None
) -> dict:
    """
    Retrieve user information from Azure AD using multiple optional search criteria.
    At least one search criterion must be provided.
    """
    headers = get_azure_headers()
    filters = []
    
    if email:
        filters.append(f"userPrincipalName eq '{escape_odata_value(email)}'")
    if display_name:
        filters.append(f"displayName eq '{escape_odata_value(display_name)}'")
    if first_name and last_name:
        filters.append(f"givenName eq '{escape_odata_value(first_name)}' and surname eq '{escape_odata_value(last_name)}'")
    elif first_name:
        filters.append(f"givenName eq '{escape_odata_value(first_name)}'")
    elif last_name:
        filters.append(f"surname eq '{escape_odata_value(last_name)}'")

    if not filters:
        raise Exception("At least one search criterion (email, display_name, first_name, or last_name) must be provided.")

    filter_query = " and ".join(filters)
    get_url = f"https://graph.microsoft.com/v1.0/users?$filter={filter_query}"
    response = requests.get(get_url, headers=headers)
    response.raise_for_status()
    users_data = response.json()
    users = users_data.get("value", [])
    if not users:
        criteria = ", ".join([f"{k}='{v}'" for k, v in {"first_name": first_name, "last_name": last_name, "email": email, "display_name": display_name}.items() if v])
        raise Exception(f"No user found with criteria: {criteria}")
    return {"users": users}

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def remove_account_action(user_id: str) -> dict:
    headers = get_azure_headers()
    delete_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    response = requests.delete(delete_url, headers=headers)
    response.raise_for_status()
    return {"removedUser": user_id}

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def change_password_action(user_id: str, new_password: str) -> dict:
    headers = get_azure_headers("application/json")
    payload = {"passwordProfile": {"forceChangePasswordNextSignIn": True, "password": new_password}}
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    response = requests.patch(patch_url, json=payload, headers=headers)
    response.raise_for_status()
    return {"changedPasswordFor": user_id}

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def update_user_profile_action(user_id: str, department: Optional[str] = None, job_title: Optional[str] = None) -> dict:
    headers = get_azure_headers("application/json")
    payload = {}
    if department:
        payload["department"] = department
    if job_title:
        payload["jobTitle"] = job_title
    if not payload:
        raise Exception("No profile fields provided to update.")
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    response = requests.patch(patch_url, json=payload, headers=headers)
    response.raise_for_status()
    return {"updatedProfile": payload}

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def disable_account_action(user_id: str) -> dict:
    headers = get_azure_headers("application/json")
    payload = {"accountEnabled": False}
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    response = requests.patch(patch_url, json=payload, headers=headers)
    response.raise_for_status()
    return {"disabledUser": user_id}

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def enable_account_action(user_id: str) -> dict:
    headers = get_azure_headers("application/json")
    payload = {"accountEnabled": True}
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    response = requests.patch(patch_url, json=payload, headers=headers)
    response.raise_for_status()
    return {"enabledUser": user_id}

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def add_user_to_group_action(user_id: str, group_id: str) -> dict:
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
    payload = {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"}
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return {"addedToGroup": group_id}

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def remove_user_from_group_action(user_id: str, group_id: str) -> dict:
    headers = get_azure_headers()
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/{user_id}/$ref"
    response = requests.delete(url, headers=headers)
    response.raise_for_status()
    return {"removedFromGroup": group_id}

# Enhanced Extraction Agent
extraction_agent = Agent(
    name="Extraction Agent",
    instructions=(
        "Analyze the user's request and extract all relevant information needed to perform helpdesk tasks. "
        "Extract the following fields: first_name, last_name, license_type (if provided), and action. "
        "Additionally, if available, extract department, job_title, group_id, and new_password (if the user specifies a password for account creation or password change). "
        "Return the output strictly as a JSON object with keys first_name, last_name, license_type, action, "
        "department, job_title, group_id, and new_password. Examples: "
        "- Input: 'Create an account for John Doe with Premium license and password MySecurePass123' → Output: {\"first_name\": \"John\", \"last_name\": \"Doe\", \"license_type\": \"Premium\", \"action\": \"create account\", \"new_password\": \"MySecurePass123\"} "
        "- Input: 'Create an account for Jane Smith' → Output: {\"first_name\": \"Jane\", \"last_name\": \"Smith\", \"action\": \"create account\"} "
        "- Input: 'Change password for Bob Jones to NewPass123!' → Output: {\"first_name\": \"Bob\", \"last_name\": \"Jones\", \"action\": \"change password\", \"new_password\": \"NewPass123!\"} "
        "- Input: 'Update profile for Alice Johnson with department IT' → Output: {\"first_name\": \"Alice\", \"last_name\": \"Johnson\", \"action\": \"update profile\", \"department\": \"IT\"}"
    ),
    output_type=EnhancedExtractionOutput,
)

# Freshdesk Agent
freshdesk_agent = Agent(
    name="Freshdesk Agent",
    instructions=(
        "You are a Freshdesk specialist. Based on the input: "
        "- If the input contains 'first_name', 'last_name', 'license_type', and 'action', call create_ticket_action with those fields to create a ticket. "
        "- If the input contains 'ticket_info' and 'audit_log', call update_ticket_action with those fields to update the ticket. "
        "Return your output as JSON. Examples: "
        "- Input: {\"first_name\": \"John\", \"last_name\": \"Doe\", \"license_type\": \"Premium\", \"action\": \"create account\"} → Call create_ticket_action "
        "- Input: {\"ticket_info\": \"12345\", \"audit_log\": \"Audit log message\"} → Call update_ticket_action"
    ),
    output_type=FreshdeskOutput,
    tools=[create_ticket_action, update_ticket_action],
)

# Azure Agent
azure_agent = Agent(
    name="Azure Agent",
    instructions=(
        "You are an Azure AD specialist. Based on the 'action' field in the input, perform the corresponding task: "
        "- For 'create account', use create_user_action with first_name, last_name, license_type, and new_password if provided. "
        "- For 'remove account', use get_user_info_action with first_name and last_name to find the user_id, then use remove_account_action with user_id. "
        "- For 'update profile', use get_user_info_action to find the user_id, then use update_user_profile_action with user_id and provided fields (e.g., department, job_title). "
        "- For 'change password', use get_user_info_action to find the user_id, then use change_password_action with user_id and new_password. "
        "- For 'disable account', use get_user_info_action to find the user_id, then use disable_account_action with user_id. "
        "- For 'enable account', use get_user_info_action to find the user_id, then use enable_account_action with user_id. "
        "- For 'add to group', use get_user_info_action to find the user_id, then use add_user_to_group_action with user_id and group_id. "
        "- For 'remove from group', use get_user_info_action to find the user_id, then use remove_user_from_group_action with user_id and group_id. "
        "Return your output as JSON. Examples: "
        "- Input: {\"first_name\": \"John\", \"last_name\": \"Doe\", \"license_type\": \"Premium\", \"action\": \"create account\", \"new_password\": \"MySecurePass123\"} → Call create_user_action with first_name, last_name, license_type, new_password "
        "- Input: {\"first_name\": \"Jane\", \"last_name\": \"Smith\", \"action\": \"create account\"} → Call create_user_action with first_name, last_name, license_type=None, new_password=None "
        "- Input: {\"first_name\": \"Bob\", \"last_name\": \"Jones\", \"action\": \"change password\", \"new_password\": \"NewPass123!\"} → Call get_user_info_action, then change_password_action "
    ),
    output_type=None,  # Keeping flexible due to varied tool outputs
    tools=[
        create_user_action,
        get_user_info_action,
        remove_account_action,
        change_password_action,
        update_user_profile_action,
        disable_account_action,
        enable_account_action,
        add_user_to_group_action,
        remove_user_from_group_action
    ],
)

# API Endpoint
class AgentRequest(BaseModel):
    transcript: str

@app.post("/agent")
async def process_agent(request: AgentRequest):
    transcript = request.transcript

    # Extraction Step
    try:
        logging.info("Starting extraction")
        extraction_result = await Runner.run(extraction_agent, input=transcript)
        extraction = extraction_result.final_output
        logging.info(f"Extraction successful: {extraction}")
    except Exception as e:
        logging.error(f"Extraction failed: {e}")
        return StandardResponse(success=False, error="Failed to extract details from request")

    # Freshdesk Ticket Creation
    try:
        logging.info("Creating Freshdesk ticket")
        fd_input = json.dumps(extraction.model_dump())
        fd_result = await Runner.run(freshdesk_agent, input=fd_input)
        fd_data = fd_result.final_output
        ticket_info = fd_data.ticketId
        if not ticket_info:
            raise Exception("Ticket ID not found in Freshdesk response")
        logging.info(f"Freshdesk ticket created: {ticket_info}")
    except Exception as e:
        logging.error(f"Freshdesk ticket creation failed: {e}")
        return StandardResponse(success=False, error="Failed to create Freshdesk ticket")

    # Azure Actions
    try:
        logging.info("Performing Azure actions")
        azure_input = json.dumps(extraction.model_dump())
        azure_result = await Runner.run(azure_agent, input=azure_input)
        azure_data = azure_result.final_output
        logging.info(f"Azure actions performed: {azure_data}")
    except Exception as e:
        logging.error(f"Azure actions failed: {e}")
        return StandardResponse(success=False, error="Failed to perform Azure actions")

    # Prepare Audit Log
    audit_lines = []
    audit_lines.append("Hello team,")
    audit_lines.append(f"I have processed the request for {extraction.first_name} {extraction.last_name}.")
    audit_lines.append(f"Action requested: '{extraction.action}'.")
    audit_lines.append("All actions have been successfully completed.")
    audit_lines.append("Regards, IT Support")    
    # if azure_data:
    #     audit_lines.append("Azure actions performed:")
    #     audit_lines.append(f"{json.dumps(azure_data, indent=2)}")
    audit_log = "\n".join(audit_lines)

    # Update Freshdesk Ticket
    try:
        logging.info("Updating Freshdesk ticket")
        update_input = json.dumps({"ticket_info": ticket_info, "audit_log": audit_log})
        update_result = await Runner.run(freshdesk_agent, input=update_input)
        update_data = update_result.final_output
        logging.info(f"Freshdesk ticket updated: {update_data}")
    except Exception as e:
        logging.error(f"Freshdesk ticket update failed: {e}")
        return StandardResponse(success=False, error="Failed to update Freshdesk ticket")

    # Combine Results
    combined = {
        "ticket_info": ticket_info,
        "extracted": extraction.model_dump(),
        "azure": unwrap_response(azure_data),
        "audit": unwrap_response(update_data)
    }
    final_response = StandardResponse(success=True, data=combined).model_dump()
    return final_response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)