import os
import re
import requests
import logging
from typing import Optional, List
from agents import function_tool
from tenacity import retry, stop_after_attempt, wait_fixed
from app.utils.azure_utils import get_azure_headers
from app.utils.general_utils import standardize_output, escape_odata_value
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# SKU_MAPPING with placeholders for the five most common Microsoft 365 licenses
# https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
SKU_MAPPING = {
    "Business Basic": "3b555118-da6a-4418-894f-7df1e2096870",
    "Business Standard": "acb52b11-74d8-4b04-8b68-31e9c5a3f114",
    "Business Premium": "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",
    "E3": "05e9a617-0261-4cee-bb44-138d3ef5d965",
    "E5": "06ebc4ee-1bb5-47dd-8120-11324bc54e06"
}

def get_sku_id_for_license(license_type: Optional[str]) -> Optional[str]:
    """
    Retrieve the SKU ID for the given license type or the default license SKU ID.

    Args:
        license_type (Optional[str]): The type of license (e.g., 'E3').

    Returns:
        Optional[str]: The SKU ID if found, otherwise None.
    """
    if license_type:
        if license_type in SKU_MAPPING:
            return SKU_MAPPING[license_type]
        else:
            raise ValueError(f"Unknown license_type: {license_type}")
    default_sku = os.environ.get("DEFAULT_LICENSE_SKUID")
    return default_sku if default_sku and default_sku.strip() else None

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def create_user_action(
    first_name: str,
    last_name: str,
    license_type: Optional[str] = None,
    new_password: Optional[str] = None,
    job_title: Optional[str] = None,
    department: Optional[str] = None,
    group_id: Optional[str] = None
) -> dict:
    """
    Create a new user in Azure AD with optional group and license assignments.

    Args:
        first_name (str): User's first name.
        last_name (str): User's last name.
        license_type (Optional[str]): License type (e.g., 'Business Basic').
        new_password (Optional[str]): Password for the new user.
        job_title (Optional[str]): User's job title.
        department (Optional[str]): User's department.
        group_id (Optional[str]): Group ID to add the user to.

    Returns:
        dict: Operation result with status, user_id, etc.

    Raises:
        ValueError: If input validation fails.
        Exception: If API request fails after retries.
    """
    logger.debug("Creating user: %s %s", first_name, last_name)

    # Input validation
    if not first_name or not last_name:
        raise ValueError("First name and last name are required.")
    if not re.match(r"^[a-zA-Z\s-]+$", first_name) or not re.match(r"^[a-zA-Z\s-]+$", last_name):
        raise ValueError("Names must contain only letters, spaces, or hyphens.")
    password = new_password or os.environ.get("DEFAULT_PASSWORD", "SecureRandomPassword123!")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    email_pattern = os.environ.get("EMAIL_PATTERN", "@yourdomain.com")
    user_principal_name = f"{first_name.lower()}.{last_name.lower()}{email_pattern}"
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
    if job_title:
        user_payload["jobTitle"] = job_title
    if department:
        user_payload["department"] = department

    create_user_url = "https://graph.microsoft.com/v1.0/users"
    try:
        response = requests.post(create_user_url, json=user_payload, headers=headers)
        response.raise_for_status()
        user_data = response.json()
        user_id = user_data.get("id")
        logger.info("User created: %s", user_principal_name)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400 and "already exists" in e.response.text:
            raise ValueError(f"User {user_principal_name} already exists.")
        raise Exception(f"Failed to create user: {e}")

    # License assignment
    assigned_license = None
    sku_id = get_sku_id_for_license(license_type)
    if sku_id:
        license_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/assignLicense"
        license_payload = {"addLicenses": [{"skuId": sku_id}], "removeLicenses": []}
        try:
            response = requests.post(license_url, json=license_payload, headers=headers)
            response.raise_for_status()
            assigned_license = license_type or "Default SKU"
            logger.debug("License %s assigned to %s", assigned_license, user_id)
        except requests.exceptions.HTTPError as e:
            logger.error("License assignment failed: %s", e)

    # Group assignment
    assigned_group = None
    if group_id:
        group_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
        group_payload = {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"}
        try:
            response = requests.post(group_url, json=group_payload, headers=headers)
            response.raise_for_status()
            assigned_group = [group_id]
            logger.debug("User added to group %s", group_id)
        except requests.exceptions.HTTPError as e:
            logger.error("Group assignment failed: %s", e)

    return {
        "status": "created",
        "user_id": user_principal_name,
        "display_name": f"{first_name} {last_name}",
        "license_type": assigned_license,
        "group_ids": assigned_group,
        "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "error_message": None
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
    Retrieve user info from Azure AD based on provided criteria.

    Args:
        first_name (Optional[str]): User's first name.
        last_name (Optional[str]): User's last name.
        email (Optional[str]): User's email.
        display_name (Optional[str]): User's display name.

    Returns:
        dict: User details or error.
    """
    logger.debug("Fetching user with: first_name=%s, last_name=%s, email=%s, display_name=%s",
                 first_name, last_name, email, display_name)
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
        raise ValueError("At least one search criterion is required.")

    filter_query = " and ".join(filters)
    get_url = f"https://graph.microsoft.com/v1.0/users?$filter={filter_query}"
    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()
        users = response.json().get("value", [])
        if not users:
            raise ValueError(f"No user found with criteria: {filter_query}")
        if len(users) > 1:
            logger.warning("Multiple users found: %s", len(users))
            raise ValueError("Multiple users found; please refine your search criteria.")
        user = users[0]
        logger.info("User retrieved: %s", user.get("userPrincipalName"))
        return {
            "status": "retrieved",
            "user_id": user.get("userPrincipalName"),
            "display_name": user.get("displayName"),
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        raise Exception(f"Failed to retrieve user: {e}")

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def remove_account_action(user_id: str) -> dict:
    """Remove a user account from Azure AD."""
    logger.debug("Removing user: %s", user_id)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_id):
        raise ValueError("Invalid user_id format; must be an email.")
    headers = get_azure_headers()
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
        logger.info("User %s removed", user_id)
        return {
            "status": "removed",
            "user_id": user_id,
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"User {user_id} not found.")
        raise Exception(f"Failed to remove user: {e}")

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def change_password_action(user_id: str, new_password: str) -> dict:
    """Change a user's password in Azure AD."""
    logger.debug("Changing password for: %s", user_id)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_id):
        raise ValueError("Invalid user_id format; must be an email.")
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    payload = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": new_password
        }
    }
    try:
        response = requests.patch(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info("Password changed for %s", user_id)
        return {
            "status": "password changed",
            "user_id": user_id,
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"User {user_id} not found.")
        raise Exception(f"Failed to change password: {e}")

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def update_user_profile_action(
    user_id: str,
    department: Optional[str] = None,
    job_title: Optional[str] = None
) -> dict:
    """Update a user's profile in Azure AD."""
    logger.debug("Updating profile for: %s", user_id)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_id):
        raise ValueError("Invalid user_id format; must be an email.")
    if not (department or job_title):
        raise ValueError("At least one of department or job_title must be provided.")
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    payload = {}
    if department:
        payload["department"] = department
    if job_title:
        payload["jobTitle"] = job_title
    try:
        response = requests.patch(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info("Profile updated for %s", user_id)
        return {
            "status": "updated",
            "user_id": user_id,
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"User {user_id} not found.")
        raise Exception(f"Failed to update profile: {e}")

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def disable_account_action(user_id: str) -> dict:
    """Disable a user account in Azure AD."""
    logger.debug("Disabling: %s", user_id)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_id):
        raise ValueError("Invalid user_id format; must be an email.")
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    payload = {"accountEnabled": False}
    try:
        response = requests.patch(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info("Account %s disabled", user_id)
        return {
            "status": "disabled",
            "user_id": user_id,
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"User {user_id} not found.")
        raise Exception(f"Failed to disable account: {e}")

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def enable_account_action(user_id: str) -> dict:
    """Enable a user account in Azure AD."""
    logger.debug("Enabling: %s", user_id)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_id):
        raise ValueError("Invalid user_id format; must be an email.")
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    payload = {"accountEnabled": True}
    try:
        response = requests.patch(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info("Account %s enabled", user_id)
        return {
            "status": "enabled",
            "user_id": user_id,
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"User {user_id} not found.")
        raise Exception(f"Failed to enable account: {e}")

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def add_user_to_group_action(user_id: str, group_id: str) -> dict:
    """Add a user to a group in Azure AD."""
    logger.debug("Adding %s to group %s", user_id, group_id)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_id):
        raise ValueError("Invalid user_id format; must be an email.")
    if not re.match(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$", group_id):
        raise ValueError("Invalid group_id format; must be a GUID.")
    headers = get_azure_headers("application/json")
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
    payload = {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"}
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info("User %s added to group %s", user_id, group_id)
        return {
            "status": "added to group",
            "user_id": user_id,
            "group_ids": [group_id],
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"User {user_id} or group {group_id} not found.")
        raise Exception(f"Failed to add user to group: {e}")

@function_tool
@standardize_output
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def remove_user_from_group_action(user_id: str, group_id: str) -> dict:
    """Remove a user from a group in Azure AD."""
    logger.debug("Removing %s from group %s", user_id, group_id)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_id):
        raise ValueError("Invalid user_id format; must be an email.")
    if not re.match(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$", group_id):
        raise ValueError("Invalid group_id format; must be a GUID.")
    headers = get_azure_headers()
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/{user_id}/$ref"
    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
        logger.info("User %s removed from group %s", user_id, group_id)
        return {
            "status": "removed from group",
            "user_id": user_id,
            "group_ids": [group_id],
            "operation_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "error_message": None
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError(f"User {user_id} or group {group_id} not found.")
        raise Exception(f"Failed to remove user from group: {e}")