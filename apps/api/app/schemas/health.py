from typing import Optional
from pydantic import BaseModel, Field

class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Status of the API service")
    service: str = Field(default="agentshield", description="Service identifier")
    environment: Optional[str] = Field(default=None, description="Current application runtime environment")
