# app/observability/middleware.py
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from app.observability.logging import get_logger
from app.observability.metrics import http_requests_total, http_request_duration_seconds
from app.observability.tracing import tracer

logger = get_logger(__name__)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.time()

        with tracer.start_as_current_span(
            "http_request",
            attributes={
                "http.method": request.method,
                "http.url": str(request.url),
                "request.id": request_id,
            },
        ):
            try:
                response = await call_next(request)
                status_code = response.status_code
            except Exception as exc:
                status_code = 500
                logger.exception(
                    "Unhandled exception",
                    extra={"request_id": request_id},
                )
                raise
            finally:
                duration = time.time() - start_time

                http_requests_total.labels(
                    method=request.method,
                    path=request.url.path,
                    status=status_code,
                ).inc()

                http_request_duration_seconds.labels(
                    method=request.method,
                    path=request.url.path,
                ).observe(duration)

                logger.info(
                    "HTTP request completed",
                    extra={
                        "request_id": request_id,
                        "method": request.method,
                        "path": request.url.path,
                        "status": status_code,
                        "duration": duration,
                    },
                )

        response.headers["X-Request-ID"] = request_id
        return response
