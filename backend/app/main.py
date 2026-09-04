import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import ALLOWED_ORIGINS, ARTIFACTS_DIR, FLOW_FEATURES, N_FEATURES, STAGES
from .database import init_db
from .model_loader import artifacts
from .routes import alerts, explain, forecast, ingest, predict, ws
from .schemas import HealthResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("Network Attack Forecasting Service — Starting")
    logger.info("=" * 60)

    try:
        artifacts.load()
    except Exception as e:
        logger.critical("FATAL: Failed to load model artifacts: %s", e)
        logger.critical("The service CANNOT run without valid artifacts.")
        logger.critical("Expected artifacts in: %s", ARTIFACTS_DIR)
        raise

    await init_db()
    await _migrate_db()

    logger.info("=" * 60)
    logger.info("Service ready — all systems operational")
    logger.info("=" * 60)

    yield

    logger.info("Shutting down...")


async def _migrate_db():
    """Add new columns to existing SQLite databases without dropping tables."""
    from .database import engine
    new_columns = [
        ("flow_records", "source", "VARCHAR(32) DEFAULT 'api'"),
        ("sessions", "source", "VARCHAR(32) DEFAULT 'api'"),
        ("sessions", "direction", "VARCHAR(16) DEFAULT 'unknown'"),
        ("sessions", "max_stage_reached", "VARCHAR(32) DEFAULT 'Benign'"),
    ]
    import sqlalchemy
    async with engine.begin() as conn:
        for table, col, col_def in new_columns:
            try:
                await conn.execute(
                    sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                )
                logger.info("Migration: added column %s.%s", table, col)
            except Exception:
                pass  # column already exists — expected on subsequent starts


app = FastAPI(
    title="Network Attack Forecasting API",
    description=(
        "Network attack forecasting from live traffic data. "
        "LSTM-based stage classification and infiltration probability forecasting "
        "with feature attribution explainability."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(predict.router, tags=["Prediction"])
app.include_router(forecast.router, tags=["Forecasting"])
app.include_router(explain.router, tags=["Explainability"])
app.include_router(alerts.router, tags=["Alerts"])
app.include_router(ingest.router, tags=["Ingestion"])
app.include_router(ws.router, tags=["Live Feed"])


@app.get("/health", response_model=HealthResponse)
async def health_check():
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
        features=FLOW_FEATURES,  # BUG-08: single source of truth for feature order
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
