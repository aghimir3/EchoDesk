import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # OpenAI API Configuration (Frontend & Backend)
    openai_api_key: str

    # Freshdesk Configuration
    freshdesk_domain: str
    freshdesk_api_key: str
    email_pattern: str = "@company.com"

    # Azure Configuration (App Registration with Helpdesk role)
    azure_tenant_id: str
    azure_client_id: str
    azure_client_secret: str
    default_license_skuid: Optional[str] = None  # Can be empty

    # Default Password for New Users
    default_password: str = "MyVeryStrongDefaultPassword!2!"

    database_url: str
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

settings = Settings()