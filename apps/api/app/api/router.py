from fastapi import APIRouter
from app.api.health import router as health_router
from app.security.operations import operations_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(operations_router)
