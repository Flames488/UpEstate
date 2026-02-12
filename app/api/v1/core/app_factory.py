# app/core/app_factory.py
from fastapi import FastAPI
from app.observability.logging import configure_logging
from app.observability.middleware import ObservabilityMiddleware

def create_app() -> FastAPI:
    configure_logging()

    app = FastAPI()

    app.add_middleware(ObservabilityMiddleware)

    return app
