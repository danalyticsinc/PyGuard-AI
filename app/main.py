"""
PyGuard AI — Enterprise Python Code Security & Quality Audit Agent
FastAPI application entry point.
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.review import router as review_router
from app.models.schemas import HealthResponse

app = FastAPI(
    title="PyGuard AI",
    description=(
        "Enterprise-grade Python code security and quality review agent. "
        "Detects OWASP Top 10 vulnerabilities, code smells, and complexity issues. "
        "Powered by Claude AI for intelligent fix suggestions."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(review_router, prefix="/api/v1", tags=["review"])


@app.get("/health", response_model=HealthResponse, tags=["health"])
def health():
    return HealthResponse(
        status="ok",
        version="1.0.0",
        ai_enabled=bool(os.environ.get("ANTHROPIC_API_KEY")),
    )


@app.get("/", tags=["root"])
def root():
    return {
        "name": "PyGuard AI",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "upload_review": "POST /api/v1/review/upload",
            "snippet_review": "POST /api/v1/review/snippet",
            "demo": "GET /api/v1/review/demo",
            "health": "GET /health",
        },
    }
