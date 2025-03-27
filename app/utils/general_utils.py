import re
import json
import logging
from functools import wraps

logger = logging.getLogger(__name__)

def standardize_output(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger.debug("Standardizing output for function: %s", func.__name__)
        try:
            result = func(*args, **kwargs)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error("Function %s failed: %s", func.__name__, str(e), exc_info=True)
            return {"success": False, "error": str(e)}
    return wrapper

def extract_json_from_text(text: str) -> dict:
    logger.debug("Extracting JSON from text: %s", text[:50] + "..." if len(text) > 50 else text)
    match = re.search(r"```json(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if match:
        json_str = match.group(1).strip()
    else:
        match = re.search(r"({.*})", text, re.DOTALL)
        if match:
            json_str = match.group(1).strip()
        else:
            logger.error("No JSON found in text: %s", text)
            raise Exception("No JSON found in the text output.")
    try:
        parsed_json = json.loads(json_str)
        logger.debug("JSON extracted successfully: %s", parsed_json)
        return parsed_json
    except Exception as e:
        logger.error("Failed to parse JSON: %s", str(e))
        raise Exception(f"Failed to parse JSON: {e}")

def unwrap_response(response):
    logger.debug("Unwrapping response: %s", response)
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

def escape_odata_value(value: str) -> str:
    logger.debug("Escaping OData value: %s", value)
    return value.replace("'", "''")