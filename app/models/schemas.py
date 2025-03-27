from pydantic import BaseModel, Field
from typing import Optional, Any

class StandardResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None

class AgentRequest(BaseModel):
    transcript: str = Field(..., description="The user's request transcript")
