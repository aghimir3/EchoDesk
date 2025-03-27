import os
import requests
import logging
from typing import Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

@lru_cache(maxsize=1)
def get_azure_access_token() -> str:
    logger.debug("Fetching Azure access token")
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
        logger.error("Failed to acquire Azure access token")
        raise Exception("Failed to acquire Azure access token.")
    logger.debug("Azure access token acquired")
    return access_token

def get_azure_headers(content_type: Optional[str] = None) -> dict:
    logger.debug("Generating Azure headers with content_type: %s", content_type)
    token = get_azure_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    return headers