from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine
from .legacy_router import router as legacy_router
from .router import router
from .threat_hunting_ml_routes import router as threat_hunting_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sentinel Backend")
app.add_middleware(
	CORSMiddleware,
	allow_origins=[
		"http://127.0.0.1:5173",
		"http://localhost:5173",
		"http://127.0.0.1:3000",
		"http://localhost:3000",
	],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)
app.include_router(router)
app.include_router(threat_hunting_router)
app.include_router(legacy_router)
