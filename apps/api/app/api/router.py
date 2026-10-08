from fastapi import APIRouter
from app.api.health import router as health_router
from app.security.identity.router import auth_router
from app.security.operations import operations_router
from app.security.approval import approval_router
from app.security.laboratory import laboratory_router
from app.api.dev_router import dev_router
from app.api.gateway_router import gateway_router
from app.api.signing_router import signing_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(auth_router)
api_router.include_router(operations_router)
api_router.include_router(approval_router)
api_router.include_router(laboratory_router)
api_router.include_router(dev_router)
api_router.include_router(gateway_router)
api_router.include_router(signing_router)
