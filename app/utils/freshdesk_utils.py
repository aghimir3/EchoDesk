import os
import logging

logger = logging.getLogger(__name__)

def get_freshdesk_auth() -> tuple:
    logger.debug("Retrieving Freshdesk authentication")
    api_key = os.environ.get("FRESHDESK_API_KEY")
    if not api_key:
        logger.error("FRESHDESK_API_KEY not found in environment")
        raise ValueError("Freshdesk API key is missing")
    return (api_key, "X")

def get_freshdesk_url(path: str) -> str:
    logger.debug("Generating Freshdesk URL for path: %s", path)
    freshdesk_domain = os.environ.get("FRESHDESK_DOMAIN")
    if not freshdesk_domain:
        logger.error("FRESHDESK_DOMAIN not found in environment")
        raise ValueError("Freshdesk domain is missing")
    return f"https://{freshdesk_domain}/{path}"