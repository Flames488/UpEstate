from fastapi import FastAPI
import uvicorn

from app.middleware.tenant import TenantMiddleware
from app.middleware.auth_context import AuthContextMiddleware
from app.middleware.subscription import SubscriptionMiddleware

from app.routes import router
from app.observability.logging import setup_logging
from app.observability.metrics import setup_metrics
from app.observability.tracing import setup_tracing


def create_app() -> FastAPI:
    app = FastAPI(title="UpEstate API")

    # Observability (must come first)
    setup_logging(app)
    setup_metrics(app)
    setup_tracing(app)

    # Middleware (ORDER MATTERS)
    app.add_middleware(TenantMiddleware)
    app.add_middleware(AuthContextMiddleware)
    app.add_middleware(SubscriptionMiddleware)

    # Routes
    app.include_router(router)

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "run:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
