import os
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router as api_router
from backend.api.websockets import router as ws_router
from backend.api.auth_routes import auth_router

app = FastAPI(title="RansomShield API")

# Enable CORS for local frontend dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(ws_router)
app.include_router(auth_router)

@app.on_event("startup")
async def startup_event():
    print("[-] RansomShield Backend started.")

@app.on_event("shutdown")
async def shutdown_event():
    pass
