"""
FastAPI application — entry point.
Loads model at startup. Fails loudly if artifacts are missing.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import ALLOWED_ORIGINS, STAGES, N_FEATURES, ARTIFACTS_DIR
from .model_loader import artifacts
from .database import init_db
from .schemas import HealthResponse

from .routes import predict, forecast, explain, alerts, ingest, ws

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: load model + init DB. Shutdown: cleanup."""
    logger.info("=" * 60)
    logger.info("Network Attack Forecasting Service — Starting")
    logger.info("=" * 60)

    # ── Load model artifacts (fail loudly) ────────────────────────
    try:
        artifacts.load()
    except Exception as e:
        logger.critical("FATAL: Failed to load model artifacts: %s", e)
        logger.critical("The service CANNOT run without valid artifacts.")
        logger.critical("Expected artifacts in: %s", ARTIFACTS_DIR)
        raise

    # ── Initialize database ───────────────────────────────────────
    await init_db()

    logger.info("=" * 60)
    logger.info("Service ready — all systems operational")
    logger.info("=" * 60)

    yield

    logger.info("Shutting down...")


app = FastAPI(
    title="Network Attack Forecasting API",
    description=(
        "AI-based network attack forecasting from network traffic data. "
        "SIH 2026 — PS26153 (NTRO). LSTM World Model with MITRE ATT&CK stage "
        "classification, infiltration probability forecasting, and feature "
        "attribution explainability."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────
app.include_router(predict.router, tags=["Prediction"])
app.include_router(forecast.router, tags=["Forecasting"])
app.include_router(explain.router, tags=["Explainability"])
app.include_router(alerts.router, tags=["Alerts"])
app.include_router(ingest.router, tags=["Ingestion"])
app.include_router(ws.router, tags=["Live Feed"])


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Honest health check — reports real status, never lies.
    """
    from .database import engine
    db_ok = False
    try:
        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
            db_ok = True
    except Exception:
        pass

    model_ok = artifacts.is_loaded

    return HealthResponse(
        status="ok" if (model_ok and db_ok) else "degraded",
        model_loaded=model_ok,
        db_connected=db_ok,
        artifacts_path=str(ARTIFACTS_DIR),
        features_count=N_FEATURES,
        stages=STAGES,
        device=str(artifacts.device) if model_ok else "unavailable",
    )


@app.get("/")
async def root():
    return {
        "service": "Network Attack Forecasting API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }
