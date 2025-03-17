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

app = FastAPI()

# ---------------------------
# Utility Functions for Azure API
# ---------------------------
def get_azure_access_token() -> str:
    """Retrieve an access token from Azure AD using client credentials."""
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
    print(f"[Azure] Requesting token from: {token_url}")
    print(f"[Azure] Token payload: {token_data}")
    response = requests.post(token_url, data=token_data)
    print(f"[Azure] Token response status: {response.status_code}")
    print(f"[Azure] Token response body: {response.text}")
    response.raise_for_status()
    access_token = response.json().get("access_token")
    if not access_token:
        raise Exception("Failed to acquire Azure access token.")
    return access_token

def get_azure_headers(content_type: Optional[str] = None) -> dict:
    """Return headers for Azure API calls using the access token."""
    token = get_azure_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    print(f"[Azure] Headers: {headers}")
    return headers

# ---------------------------
# Freshdesk Helper Functions
# ---------------------------
def get_freshdesk_auth() -> tuple:
    """Return authentication tuple for Freshdesk API calls."""
    api_key = os.environ.get("FRESHDESK_API_KEY")
    return (api_key, "X")

def get_freshdesk_url(path: str) -> str:
    """Construct the full Freshdesk API URL using the domain from env."""
    freshdesk_domain = os.environ.get("FRESHDESK_DOMAIN")
    return f"https://{freshdesk_domain}/{path}"

# ---------------------------
# Standard Response Model
# ---------------------------
class StandardResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None

# ---------------------------
# Decorator to Standardize Function Tool Output
# ---------------------------
def standardize_output(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return StandardResponse(success=True, data=result).model_dump()
        except Exception as e:
            return StandardResponse(success=False, error=str(e)).model_dump()
    return wrapper

# ---------------------------
# Pydantic Model for Enhanced Extraction Output
# ---------------------------
class EnhancedExtractionOutput(BaseModel):
    first_name: str
    last_name: str
    license_type: str
    action: str                # e.g., "create account", "remove account", etc.
    department: Optional[str] = None
    job_title: Optional[str] = None
    group_id: Optional[str] = None
    new_password: Optional[str] = None

# ---------------------------
# Pydantic Model for Freshdesk Output
# ---------------------------
class FreshdeskOutput(BaseModel):
    ticketId: Optional[str] = None
    auditLog: Optional[str] = None
    logged: Optional[str] = None

# ---------------------------
# Pydantic Model for Azure Output
# ---------------------------
class AzureOutput(BaseModel):
    userPrincipalName: Optional[str] = None
    displayName: Optional[str] = None
    assignedLicense: Optional[str] = None
    updatedProfile: Optional[dict] = None
    changedPasswordFor: Optional[str] = None
    removedUser: Optional[str] = None
    disabledUser: Optional[str] = None
    enabledUser: Optional[str] = None
    addedToGroup: Optional[str] = None
    removedFromGroup: Optional[str] = None
    users: Optional[List[Any]] = None

# ---------------------------
# Helper Function to Extract JSON from Text Output
# ---------------------------
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

# ---------------------------
# Helper Function to Unwrap Standardized Responses
# ---------------------------
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

# ---------------------------
# Function Tools for Freshdesk (Ticket Creation & Audit Logging)
# ---------------------------
@function_tool
@standardize_output
def create_ticket_action(first_name: str, last_name: str, license_type: str) -> dict:
    url = get_freshdesk_url("api/v2/tickets")
    email_pattern = os.environ.get("EMAIL_PATTERN", "@yourdomain.com")
    email = f"{first_name.lower()}.{last_name.lower()}{email_pattern}"
    payload = {
        "subject": f"New Azure AD Request for {first_name} {last_name}",
        "description": f"Please create an account for {first_name} {last_name} with a {license_type or 'standard'} license.",
        "email": email,
        "priority": 2,
        "status": 2
    }
    print("FRESHDESK - CREATE TICKET: Request URL:", url)
    print("FRESHDESK - CREATE TICKET: Payload:", payload)
    response = requests.post(url, json=payload, auth=get_freshdesk_auth())
    print("FRESHDESK - CREATE TICKET: Response status:", response.status_code)
    print("FRESHDESK - CREATE TICKET: Response body:", response.text)
    response.raise_for_status()
    ticket_data = response.json()
    if not isinstance(ticket_data, dict) or "id" not in ticket_data:
        raise Exception("Ticket creation did not return valid JSON data.")
    return {"ticket": {"ticketId": str(ticket_data.get("id"))}}

@function_tool
@standardize_output
def update_ticket_action(ticket_info: str, audit_log: str) -> dict:
    """
    Updates a Freshdesk ticket by adding an audit log note.
    Expects ticket_info to be a string representing the ticket id.
    """
    ticket_id = ticket_info  # Assume it's already a string.
    if not ticket_id:
        raise Exception("Ticket ID is missing.")
    url = get_freshdesk_url(f"api/v2/tickets/{ticket_id}/notes")
    payload = {"body": audit_log, "private": False}
    print("FRESHDESK - UPDATE TICKET: Request URL:", url)
    print("FRESHDESK - UPDATE TICKET: Payload:", payload)
    response = requests.post(url, json=payload, auth=get_freshdesk_auth())
    print("FRESHDESK - UPDATE TICKET: Response status:", response.status_code)
    print("FRESHDESK - UPDATE TICKET: Response body:", response.text)
    response.raise_for_status()
    return {"updatedTicket": {"ticketId": ticket_id, "auditLog": audit_log}}

@function_tool
@standardize_output
def log_audit_action(ticket_id: str, message: str) -> dict:
    """
    Logs an audit message to the specified Freshdesk ticket.
    (This function can be used to log individual actions if needed.)
    """
    url = get_freshdesk_url(f"api/v2/tickets/{ticket_id}/notes")
    payload = {"body": message, "private": False}
    print("FRESHDESK - LOG AUDIT: Request URL:", url)
    print("FRESHDESK - LOG AUDIT: Payload:", payload)
    response = requests.post(url, json=payload, auth=get_freshdesk_auth())
    print("FRESHDESK - LOG AUDIT: Response status:", response.status_code)
    print("FRESHDESK - LOG AUDIT: Response body:", response.text)
    response.raise_for_status()
    return {"logged": message}

# ---------------------------
# Function Tools for Azure (User Management)
# ---------------------------
@function_tool
@standardize_output
def create_user_action(first_name: str, last_name: str, license_type: str) -> dict:
    """
    Creates a new Azure AD user.
    Returns the userPrincipalName and displayName.
    Also assigns a default password (from DEFAULT_PASSWORD) and, if provided, a default license (DEFAULT_LICENSE_SKUID).
    """
    email_pattern = os.environ.get("EMAIL_PATTERN", "@yourdomain.com")
    user_principal_name = f"{first_name.lower()}.{last_name.lower()}{email_pattern}"
    default_password = os.environ.get("DEFAULT_PASSWORD", "SecureRandomPassword123!")
    
    headers = get_azure_headers("application/json")
    user_payload = {
        "accountEnabled": True,
        "displayName": f"{first_name} {last_name}",
        "mailNickname": first_name.lower(),
        "userPrincipalName": user_principal_name,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": default_password
        }
    }
    print("AZURE - CREATE USER: Request URL: https://graph.microsoft.com/v1.0/users")
    print("AZURE - CREATE USER: Payload:", user_payload)
    create_user_url = "https://graph.microsoft.com/v1.0/users"
    response = requests.post(create_user_url, json=user_payload, headers=headers)
    print("AZURE - CREATE USER: Response status:", response.status_code)
    print("AZURE - CREATE USER: Response body:", response.text)
    response.raise_for_status()
    user_data = response.json()
    user_id = user_data.get("id")
    
    assigned_license = None
    default_license_sku = os.environ.get("DEFAULT_LICENSE_SKUID", "").strip()
    if default_license_sku and user_id:
        assign_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/assignLicense"
        license_payload = {
            "addLicenses": [{"skuId": default_license_sku}],
            "removeLicenses": []
        }
        print("AZURE - ASSIGN LICENSE: Request URL:", assign_url)
        print("AZURE - ASSIGN LICENSE: Payload:", license_payload)
        license_response = requests.post(assign_url, json=license_payload, headers=get_azure_headers("application/json"))
        print("AZURE - ASSIGN LICENSE: Response status:", license_response.status_code)
        print("AZURE - ASSIGN LICENSE: Response body:", license_response.text)
        license_response.raise_for_status()
        assigned_license = default_license_sku
    
    return {
        "azure": {
            "userPrincipalName": user_principal_name,
            "displayName": user_data.get("displayName"),
            "assignedLicense": assigned_license
        }
    }

@function_tool
@standardize_output
def update_user_profile_action(user_id: str, job_title: Optional[str] = None, department: Optional[str] = None, phone: Optional[str] = None) -> dict:
    """
    Updates the user profile in Azure AD.
    Allowed fields: job_title, department, and mobile phone.
    """
    headers = get_azure_headers("application/json")
    payload = {}
    if job_title:
        payload["jobTitle"] = job_title
    if department:
        payload["department"] = department
    if phone:
        payload["mobilePhone"] = phone
    if not payload:
        raise Exception("No profile fields provided to update.")
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    print("AZURE - UPDATE USER PROFILE: Request URL:", patch_url)
    print("AZURE - UPDATE USER PROFILE: Payload:", payload)
    response = requests.patch(patch_url, json=payload, headers=headers)
    print("AZURE - UPDATE USER PROFILE: Response status:", response.status_code)
    print("AZURE - UPDATE USER PROFILE: Response body:", response.text)
    response.raise_for_status()
    return {"updatedProfile": payload}

@function_tool
@standardize_output
def change_password_action(user_id: str, new_password: str) -> dict:
    headers = get_azure_headers("application/json")
    payload = {"passwordProfile": {"forceChangePasswordNextSignIn": True, "password": new_password}}
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    print("AZURE - CHANGE PASSWORD: Request URL:", patch_url)
    print("AZURE - CHANGE PASSWORD: Payload:", payload)
    response = requests.patch(patch_url, json=payload, headers=headers)
    print("AZURE - CHANGE PASSWORD: Response status:", response.status_code)
    print("AZURE - CHANGE PASSWORD: Response body:", response.text)
    response.raise_for_status()
    return {"changedPasswordFor": user_id}

@function_tool
@standardize_output
def remove_account_action(user_id: str) -> dict:
    headers = get_azure_headers()
    delete_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    print("AZURE - REMOVE ACCOUNT: Request URL:", delete_url)
    response = requests.delete(delete_url, headers=headers)
    print("AZURE - REMOVE ACCOUNT: Response status:", response.status_code)
    print("AZURE - REMOVE ACCOUNT: Response body:", response.text)
    response.raise_for_status()
    return {"removedUser": user_id}

@function_tool
@standardize_output
def disable_account_action(user_id: str) -> dict:
    headers = get_azure_headers("application/json")
    payload = {"accountEnabled": False}
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    print("AZURE - DISABLE ACCOUNT: Request URL:", patch_url)
    print("AZURE - DISABLE ACCOUNT: Payload:", payload)
    response = requests.patch(patch_url, json=payload, headers=headers)
    print("AZURE - DISABLE ACCOUNT: Response status:", response.status_code)
    print("AZURE - DISABLE ACCOUNT: Response body:", response.text)
    response.raise_for_status()
    return {"disabledUser": user_id}

@function_tool
@standardize_output
def enable_account_action(user_id: str) -> dict:
    headers = get_azure_headers("application/json")
    payload = {"accountEnabled": True}
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    print("AZURE - ENABLE ACCOUNT: Request URL:", patch_url)
    print("AZURE - ENABLE ACCOUNT: Payload:", payload)
    response = requests.patch(patch_url, json=payload, headers=headers)
    print("AZURE - ENABLE ACCOUNT: Response status:", response.status_code)
    print("AZURE - ENABLE ACCOUNT: Response body:", response.text)
    response.raise_for_status()
    return {"enabledUser": user_id}

@function_tool
@standardize_output
def get_user_info_action(
    email: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    display_name: Optional[str] = None,
    department: Optional[str] = None,
    job_title: Optional[str] = None
) -> dict:
    """
    Retrieves user(s) info from Azure AD.
    Search can be done by email, first_name and last_name, display_name, or department/job_title.
    If multiple users match, returns all matching accounts.
    """
    filters = []
    if email:
        filters.append(f"userPrincipalName eq '{email}'")
    if display_name:
        filters.append(f"displayName eq '{display_name}'")
    if first_name and last_name:
        filters.append(f"givenName eq '{first_name}' and surname eq '{last_name}'")
    if department:
        filters.append(f"department eq '{department}'")
    if job_title:
        filters.append(f"jobTitle eq '{job_title}'")
    if not filters:
        raise Exception("No valid search parameters provided.")
    filter_query = " and ".join(filters)
    
    headers = get_azure_headers("application/json")
    get_url = f"https://graph.microsoft.com/v1.0/users?$filter={filter_query}"
    print("AZURE - GET USER INFO: Request URL:", get_url)
    response = requests.get(get_url, headers=headers)
    print("AZURE - GET USER INFO: Response status:", response.status_code)
    print("AZURE - GET USER INFO: Response body:", response.text)
    response.raise_for_status()
    users_data = response.json()
    return {"users": users_data.get("value", [])}

@function_tool
@standardize_output
def update_user_profile_action(user_id: str, job_title: Optional[str] = None, department: Optional[str] = None, phone: Optional[str] = None) -> dict:
    """
    Updates the user profile in Azure AD.
    Allowed fields: job_title, department, and mobile phone.
    """
    headers = get_azure_headers("application/json")
    payload = {}
    if job_title:
        payload["jobTitle"] = job_title
    if department:
        payload["department"] = department
    if phone:
        payload["mobilePhone"] = phone
    if not payload:
        raise Exception("No profile fields provided to update.")
    patch_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    print("AZURE - UPDATE USER PROFILE: Request URL:", patch_url)
    print("AZURE - UPDATE USER PROFILE: Payload:", payload)
    response = requests.patch(patch_url, json=payload, headers=headers)
    print("AZURE - UPDATE USER PROFILE: Response status:", response.status_code)
    print("AZURE - UPDATE USER PROFILE: Response body:", response.text)
    response.raise_for_status()
    return {"updatedProfile": payload}

@function_tool
@standardize_output
def add_user_to_group_action(user_id: str, group_id: str) -> dict:
    """
    Adds a user to a group in Azure AD.
    """
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
    payload = {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"}
    print("AZURE - ADD USER TO GROUP: Request URL:", url)
    print("AZURE - ADD USER TO GROUP: Payload:", payload)
    response = requests.post(url, json=payload, headers=headers)
    print("AZURE - ADD USER TO GROUP: Response status:", response.status_code)
    print("AZURE - ADD USER TO GROUP: Response body:", response.text)
    response.raise_for_status()
    return {"addedToGroup": group_id}

@function_tool
@standardize_output
def remove_user_from_group_action(user_id: str, group_id: str) -> dict:
    """
    Removes a user from a group in Azure AD.
    """
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/{user_id}/$ref"
    print("AZURE - REMOVE USER FROM GROUP: Request URL:", url)
    response = requests.delete(url, headers=headers)
    print("AZURE - REMOVE USER FROM GROUP: Response status:", response.status_code)
    print("AZURE - REMOVE USER FROM GROUP: Response body:", response.text)
    response.raise_for_status()
    return {"removedFromGroup": group_id}

# ---------------------------
# Enhanced Extraction Agent
# ---------------------------
extraction_agent = Agent(
    name="Extraction Agent",
    instructions=(
        "Analyze the user's request and extract all relevant information needed to perform helpdesk tasks. "
        "Extract the following fields: first_name, last_name, license_type, and action. "
        "Additionally, if available, extract department, job_title, group_id, and new_password. "
        "Return the output strictly as a JSON object with keys first_name, last_name, license_type, action, "
        "department, job_title, group_id, and new_password. "
        "For example: "
        "{\"first_name\": \"John\", \"last_name\": \"Doe\", \"license_type\": \"Premium\", "
        "\"action\": \"create account\", \"department\": \"IT\", \"job_title\": \"Manager\", "
        "\"group_id\": \"group123\", \"new_password\": \"MyNewPass!\"}."
    ),
    output_type=EnhancedExtractionOutput,
)

# ---------------------------
# Freshdesk Agent (for ticket creation & audit logging)
# ---------------------------
freshdesk_agent = Agent(
    name="Freshdesk Agent",
    instructions=(
        "You are a Freshdesk specialist. "
        "Perform all Freshdesk-related tasks such as creating a ticket and updating it with an audit log message. "
        "Return your output as JSON."
    ),
    output_type=FreshdeskOutput,
    tools=[
        create_ticket_action,
        update_ticket_action,
        log_audit_action
    ],
)

# ---------------------------
# Azure Agent (for all Azure AD actions)
# ---------------------------
azure_agent = Agent(
    name="Azure Agent",
    instructions=(
        "You are an Azure AD specialist. "
        "Perform all Azure-related tasks such as creating a user, updating user profile, managing groups, "
        "changing password, and retrieving user information. "
        "Return your output as JSON."
    ),
    output_type=None,  # No strict output schema enforcement
    tools=[
        create_user_action,
        update_user_profile_action,
        get_user_info_action,
        change_password_action,
        remove_account_action,
        disable_account_action,
        enable_account_action,
        add_user_to_group_action,
        remove_user_from_group_action
    ],
)

# ---------------------------
# Orchestration in the API Endpoint
# ---------------------------
class AgentRequest(BaseModel):
    transcript: str

@app.post("/agent")
async def process_agent(request: AgentRequest):
    transcript = request.transcript
    try:
        # Step 1: Extract details from transcript.
        extraction_result = await Runner.run(extraction_agent, input=transcript)
        extraction = extraction_result.final_output
        print("EXTRACTION RESULT:", extraction)
        if isinstance(extraction, dict):
            extraction = EnhancedExtractionOutput(**extraction)
        
        # Step 2: Create a Freshdesk ticket (to capture audit trail later).
        fd_result = await Runner.run(freshdesk_agent, input=f"{extraction.first_name} {extraction.last_name} {extraction.license_type}")
        fd_data = fd_result.final_output
        print("FRESHDESK RESULT:", fd_data)
        # Here we assume fd_data is a string or contains a ticket id string.
        # For simplicity, we convert it to a string.
        ticket_info = str(fd_data)
        
        # Step 3: Perform Azure actions.
        azure_input = f"{extraction.first_name} {extraction.last_name} {extraction.license_type}"
        azure_result = await Runner.run(azure_agent, input=azure_input)
        azure_data = azure_result.final_output
        print("AZURE RESULT:", azure_data)
        
        # Step 4: Compose a human-friendly audit log message.
        audit_lines = []
        audit_lines.append("Hello IT Team,")
        audit_lines.append(f"I have processed the request for {extraction.first_name} {extraction.last_name}.")
        audit_lines.append(f"Action requested: {extraction.action}.")
        if azure_data:
            audit_lines.append("Azure actions performed:")
            audit_lines.append(json.dumps(azure_data, indent=2))
        audit_lines.append("All actions have been successfully completed. Regards, IT Support.")
        audit_log = "\n".join(audit_lines)
        print("AUDIT LOG MESSAGE:\n", audit_log)
        
        # Step 5: Update the Freshdesk ticket with the audit log message.
        update_result = await Runner.run(freshdesk_agent, input=f"log_audit_action {ticket_info} {audit_log}")
        update_data = update_result.final_output
        print("FINAL TICKET UPDATE RESULT:", update_data)
        
        # Combine outputs.
        combined = {
            "ticket_info": ticket_info,
            "extracted": extraction.model_dump(),
            "azure": unwrap_response(azure_data),
            "audit": unwrap_response(update_data)
        }
        final_response = StandardResponse(success=True, data=combined).model_dump()
        return final_response
    except Exception as e:
        print("ERROR:", str(e))
        error_response = StandardResponse(success=False, error=str(e)).model_dump()
        raise HTTPException(status_code=500, detail=error_response)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
