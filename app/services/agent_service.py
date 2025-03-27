import json
import logging
import asyncio
from typing import Optional, Dict
from fastapi import HTTPException
from app.models.schemas import AgentRequest, StandardResponse
from app.agents.extraction import extraction_agent, ExtractionOutput
from app.agents.validation import validation_agent, ValidationResponse
from app.agents.freshdesk import freshdesk_agent
from app.agents.azure import azure_agent, AzureOutput
from app.utils.general_utils import extract_json_from_text, unwrap_response
from app.config import settings
from agents import Runner
import uuid
from app.services.process_ticket_service import create_process, update_process, add_update, get_process  # Updated import

logger = logging.getLogger(__name__)

async def extract_details(transcript: str) -> ExtractionOutput:
    try:
        logger.info("Starting extraction from transcript: %s", transcript[:50] + "..." if len(transcript) > 50 else transcript)
        logger.debug("Running extraction agent with input: %s", transcript)
        result = await Runner.run(extraction_agent, input=transcript)
        logger.debug("Extraction agent output: %s", result.final_output)
        logger.info("Extraction successful: %s", result.final_output)
        return result.final_output
    except Exception as e:
        logger.error("Extraction failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to extract details from request")

async def validate_details(extraction: ExtractionOutput) -> ValidationResponse:
    try:
        logger.info("Validating extracted details: %s", extraction.model_dump())
        extraction_json = json.dumps(extraction.model_dump())
        logger.debug("Running validation agent with input: %s", extraction_json)
        result = await Runner.run(validation_agent, input=extraction_json)
        
        if isinstance(result.final_output, ValidationResponse):
            validation_output = result.final_output
        else:
            validation_output = ValidationResponse(**extract_json_from_text(result.final_output))
        
        logger.debug("Validation agent output: %s", validation_output.model_dump())
        logger.info("Validation result: success=%s, error=%s", validation_output.success, validation_output.error)
        return validation_output
    except Exception as e:
        logger.error("Validation failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to validate extracted details")

async def create_freshdesk_ticket(extraction: ExtractionOutput, process_id: str) -> str:
    try:
        logger.info("Creating Freshdesk ticket for %s %s", extraction.first_name, extraction.last_name)
        fd_input = json.dumps({"extraction": extraction.model_dump(), "process_id": process_id})
        logger.debug("Running freshdesk agent with input: %s", fd_input)
        fd_result = await Runner.run(freshdesk_agent, input=fd_input)
        logger.debug("Freshdesk agent output: %s", fd_result.final_output)
        ticket_id = fd_result.final_output.ticketId
        if not ticket_id:
            raise ValueError("Ticket ID not found in Freshdesk response")
        logger.info("Freshdesk ticket created: %s", ticket_id)
        return ticket_id
    except Exception as e:
        logger.error("Freshdesk ticket creation failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to create Freshdesk ticket")

async def perform_azure_actions(extraction: ExtractionOutput) -> dict:
    try:
        logger.info("Performing Azure actions for %s %s", extraction.first_name, extraction.last_name)
        azure_input = json.dumps(extraction.model_dump())
        logger.debug("Running azure agent with input: %s", azure_input)
        result = await Runner.run(azure_agent, input=azure_input)
        
        if isinstance(result.final_output, AzureOutput):
            azure_data = result.final_output.model_dump()
        else:
            azure_data = extract_json_from_text(result.final_output)
        
        logger.debug("Azure agent output: %s", azure_data)
        logger.info("Azure actions performed: %s", azure_data)
        return azure_data
    except (ValueError, Exception) as e:
        logger.error("Azure actions failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to perform Azure actions")

async def update_freshdesk_ticket(ticket_id: str, audit_log: str) -> dict:
    try:
        logger.info("Updating Freshdesk ticket %s", ticket_id)
        update_input = json.dumps({"ticket_info": ticket_id, "audit_log": audit_log})
        logger.debug("Running freshdesk agent with input: %s", update_input)
        update_result = await Runner.run(freshdesk_agent, input=update_input)
        logger.debug("Freshdesk agent output for update: %s", update_result.final_output)
        logger.info("Freshdesk ticket updated: %s", update_result.final_output)
        return update_result.final_output
    except Exception as e:
        logger.error("Freshdesk ticket update failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update Freshdesk ticket")

async def process_request_in_background(process_id: str, extraction: ExtractionOutput):
    create_process(process_id, status="started", updates=["Process started"])
    
    try:
        add_update(process_id, f"Processing request: {extraction.transcript}")

        ticket_id = None
        if settings.freshdesk_api_key:
            try:
                ticket_id = await create_freshdesk_ticket(extraction, process_id)
                update_process(process_id, ticket_number=ticket_id)
                add_update(process_id, f"Created Freshdesk ticket {ticket_id}")
            except Exception as e:
                logger.error("Failed to create Freshdesk ticket: %s", str(e))
                add_update(process_id, "Failed to create Freshdesk ticket")

        azure_data = await perform_azure_actions(extraction)
        add_update(process_id, "Performed Azure actions")

        if settings.freshdesk_api_key and ticket_id:
            try:
                audit_lines = [
                    "Hello team,",
                    f"I have processed the request for {extraction.first_name} {extraction.last_name}.",
                    f"Action requested: '{extraction.action}'.",
                    "All actions have been successfully completed.",
                    "Regards, IT Support"
                ]
                if azure_data:
                    audit_lines.extend(["Azure actions performed:", json.dumps(azure_data, indent=2)])
                audit_log = "\n".join(audit_lines)
                update_data = await update_freshdesk_ticket(ticket_id, audit_log)
                add_update(process_id, "Updated Freshdesk ticket with audit log")
            except Exception as e:
                logger.error("Failed to update Freshdesk ticket: %s", str(e))
                add_update(process_id, "Failed to update Freshdesk ticket")

        result = {
            "extracted": extraction.model_dump(),
            "azure": unwrap_response(azure_data),
        }
        if ticket_id:
            result["ticket_info"] = ticket_id
        if 'update_data' in locals():
            result["audit"] = update_data.model_dump() if hasattr(update_data, "model_dump") else update_data
        update_process(process_id, status="completed", result=result)
        logger.info("Background process %s completed successfully", process_id)
    except Exception as e:
        update_process(process_id, status="failed", result={"error": str(e)})
        logger.error("Background process %s failed: %s", process_id, str(e), exc_info=True)

async def process_agent_request(request: AgentRequest) -> StandardResponse:
    transcript = request.transcript
    if not transcript or not isinstance(transcript, str):
        logger.warning("Invalid transcript received: %s", transcript)
        raise HTTPException(status_code=400, detail="Transcript must be a non-empty string")
    
    try:
        extraction = await extract_details(transcript)
        validation = await validate_details(extraction)
        if not validation.success:
            error_message = validation.error or "Validation failed"
            logger.warning("Validation failed for transcript: %s - %s", transcript, error_message)
            raise HTTPException(status_code=400, detail=error_message)

        process_id = str(uuid.uuid4())
        logger.info("Starting agent request with process_id: %s, transcript: %s", process_id, transcript[:50] + "..." if len(transcript) > 50 else transcript)
        asyncio.create_task(process_request_in_background(process_id, extraction))
        
        return StandardResponse(
            success=True,
            data={"process_id": process_id, "message": "Request processing started. Use /process-updates/{process_id} to track progress."}
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error("Failed to process request: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process request")

async def get_process_updates(process_id: str) -> StandardResponse:
    logger.info("Received request for updates on process_id: %s", process_id)
    process = get_process(process_id)
    if process:
        response_data = {
            "updates": process.updates,
            "status": process.status,
            "ticket_number": process.ticket_number
        }
        if process.status == "completed":
            response_data["result"] = process.result
            logger.info("Returning completed process updates for process_id: %s", process_id)
        elif process.status == "failed":
            response_data["error"] = process.result.get("error") if process.result else "Unknown error"
            logger.error("Returning failed process updates for process_id: %s: %s", process_id, response_data["error"])
        else:
            logger.info("Returning in-progress updates for process_id: %s", process_id)
        return StandardResponse(success=True, data=response_data)
    else:
        logger.warning("Process ID %s not found in database", process_id)
        raise HTTPException(status_code=404, detail="Process ID not found in database")