import logging
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from app.services.agent_service import process_agent_request, get_process_updates
from app.models.schemas import AgentRequest, StandardResponse
from app.utils.db import engine, Base
from app.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

logging.getLogger("agents").setLevel(logging.INFO)
logging.getLogger("tools").setLevel(logging.INFO)
logging.getLogger("utils").setLevel(logging.INFO)

# Lifespan handler to manage startup and shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic: Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created on startup")
    yield  # Application runs here
    # Shutdown logic (optional): Add cleanup code here if needed
    logger.info("Application shutting down")

# Initialize FastAPI app with the lifespan handler
app = FastAPI(title="Echo Desk Agent API", version="1.0.0", lifespan=lifespan)

# Define API endpoints BEFORE mounting static files
@app.post("/api/agent", response_model=StandardResponse)
async def process_agent(request: AgentRequest):
    return await process_agent_request(request)

@app.get("/api/process-updates/{process_id}", response_model=StandardResponse)
async def process_updates(process_id: str):
    return await get_process_updates(process_id)

@app.get("/api/config")
async def get_config():
    return {"freshdesk_domain": settings.freshdesk_domain}

# Mount static files AFTER defining API endpoints
app.mount("/", StaticFiles(directory="public", html=True), name="static")