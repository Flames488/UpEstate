"""
Observability metrics module.

This module provides a metrics interface that can operate in two modes:
1. No-op mode: All functions exist for API compatibility but do nothing
2. Active mode: When configured with a metrics backend (e.g., Prometheus)

The module is designed to be a drop-in replacement that won't break
existing code regardless of whether metrics are enabled or not.
"""

import functools
import typing as t
from contextlib import contextmanager

from flask import Flask, Response

# Type aliases for better readability
RequestArgs = t.Tuple[t.Any, ...]
RequestKwargs = t.Dict[str, t.Any]
MetricLabels = t.Dict[str, str]


class MetricsManager:
    """Central manager for metrics operations."""
    
    def __init__(self, enabled: bool = False):
        """
        Initialize the metrics manager.
        
        Args:
            enabled: Whether metrics collection is active
        """
        self.enabled = enabled
        self._initialize_metrics()
    
    def _initialize_metrics(self) -> None:
        """Initialize metric objects based on enabled state."""
        if self.enabled:
            from prometheus_client import Counter, Histogram
            
            self.http_requests_total = Counter(
                "http_requests_total",
                "Total HTTP requests",
                ["method", "endpoint", "status_code"]
            )
            
            self.http_request_duration_seconds = Histogram(
                "http_request_duration_seconds",
                "HTTP request latency in seconds",
                ["method", "endpoint"],
                buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0)
            )
            
            self.task_executions_total = Counter(
                "task_executions_total",
                "Total background task executions",
                ["task_name", "status"]
            )
        else:
            # Create dummy metric objects for no-op mode
            self.http_requests_total = _DummyMetric()
            self.http_request_duration_seconds = _DummyMetric()
            self.task_executions_total = _DummyMetric()
    
    def record_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        **kwargs: t.Any
    ) -> None:
        """
        Record an HTTP request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: Request endpoint/path
            status_code: HTTP status code
            **kwargs: Additional metadata
        """
        if self.enabled:
            self.http_requests_total.labels(
                method=method.upper(),
                endpoint=endpoint,
                status_code=str(status_code)
            ).inc()
    
    def record_error(
        self,
        error_type: str,
        endpoint: str,
        exception: t.Optional[Exception] = None,
        **kwargs: t.Any
    ) -> None:
        """
        Record an error occurrence.
        
        Args:
            error_type: Category/type of error
            endpoint: Where the error occurred
            exception: The exception that was raised (optional)
            **kwargs: Additional error context
        """
        # In no-op mode, this intentionally does nothing
        # In active mode, you'd implement error metric recording here
        pass
    
    @contextmanager
    def observe_latency(
        self,
        method: str,
        endpoint: str,
        **labels: str
    ) -> t.Generator[None, None, None]:
        """
        Context manager for measuring operation latency.
        
        Args:
            method: HTTP method or operation type
            endpoint: Endpoint or operation name
            **labels: Additional labels for the metric
            
        Yields:
            None, just provides timing context
        """
        import time
        
        start_time = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start_time
            if self.enabled:
                self.http_request_duration_seconds.labels(
                    method=method.upper(),
                    endpoint=endpoint,
                    **labels
                ).observe(duration)


class _DummyMetric:
    """Dummy metric object that mimics Prometheus metric interface."""
    
    def labels(self, **labels: str) -> "_DummyLabels":
        """Return a dummy labels object."""
        return _DummyLabels()
    
    def inc(self, amount: float = 1) -> None:
        """No-op increment."""
        pass
    
    def observe(self, value: float) -> None:
        """No-op observation."""
        pass
    
    def set(self, value: float) -> None:
        """No-op set."""
        pass


class _DummyLabels:
    """Dummy labels object for no-op metrics."""
    
    def inc(self, amount: float = 1) -> None:
        """No-op increment."""
        pass
    
    def observe(self, value: float) -> None:
        """No-op observation."""
        pass
    
    def set(self, value: float) -> None:
        """No-op set."""
        pass


# Global metrics manager instance
# Configure via environment variable or app config in practice
METRICS_ENABLED = False  # Set to True to activate metrics
_metrics_manager = MetricsManager(enabled=METRICS_ENABLED)


# Public API functions
# These provide backward compatibility with the original interface

def record_request(*args: t.Any, **kwargs: t.Any) -> None:
    """
    Record an HTTP request.
    
    This is a compatibility wrapper around MetricsManager.record_request.
    Prefer using the manager directly for new code.
    """
    # Parse arguments for backward compatibility
    method = kwargs.get("method", args[0] if args else "UNKNOWN")
    endpoint = kwargs.get("path", kwargs.get("endpoint", args[1] if len(args) > 1 else "unknown"))
    status_code = kwargs.get("status", kwargs.get("status_code", args[2] if len(args) > 2 else 200))
    
    _metrics_manager.record_request(method, endpoint, status_code, **kwargs)


def record_error(*args: t.Any, **kwargs: t.Any) -> None:
    """
    Record an error occurrence.
    
    This is a compatibility wrapper around MetricsManager.record_error.
    """
    error_type = kwargs.get("error_type", args[0] if args else "unknown")
    endpoint = kwargs.get("path", kwargs.get("endpoint", args[1] if len(args) > 1 else "unknown"))
    exception = kwargs.get("exception", args[2] if len(args) > 2 else None)
    
    _metrics_manager.record_error(error_type, endpoint, exception, **kwargs)


def observe_latency(*args: t.Any, **kwargs: t.Any) -> t.Any:
    """
    Measure operation latency.
    
    This function can be used as a decorator or context manager.
    For new code, use MetricsManager.observe_latency directly.
    """
    method = kwargs.get("method", args[0] if args else "UNKNOWN")
    endpoint = kwargs.get("path", kwargs.get("endpoint", args[1] if len(args) > 1 else "unknown"))
    
    if kwargs.get("as_decorator", False) or (args and callable(args[0])):
        # Used as decorator
        func = args[0] if callable(args[0]) else None
        
        @functools.wraps(func)
        def wrapper(*func_args: t.Any, **func_kwargs: t.Any) -> t.Any:
            with _metrics_manager.observe_latency(method, endpoint, **kwargs):
                return func(*func_args, **func_kwargs)
        
        return wrapper
    else:
        # Used as context manager
        return _metrics_manager.observe_latency(method, endpoint, **kwargs)


def register_metrics(app: Flask) -> None:
    """
    Register metrics endpoints and middleware with Flask application.
    
    Args:
        app: Flask application instance
    """
    if METRICS_ENABLED:
        # Add request timing middleware
        @app.before_request
        def before_request() -> None:
            """Record request start time."""
            from flask import request
            request._request_start_time = time.perf_counter()  # type: ignore
        
        @app.after_request
        def after_request(response: Response) -> Response:
            """Record request metrics after response."""
            from flask import request
            
            # Calculate duration
            start_time = getattr(request, '_request_start_time', None)
            if start_time:
                duration = time.perf_counter() - start_time
                _metrics_manager.http_request_duration_seconds.labels(
                    method=request.method,
                    endpoint=request.endpoint or request.path
                ).observe(duration)
            
            # Record request count
            _metrics_manager.http_requests_total.labels(
                method=request.method,
                endpoint=request.endpoint or request.path,
                status_code=str(response.status_code)
            ).inc()
            
            return response
    
    # Always register metrics endpoint (returns empty in no-op mode)
    @app.route("/metrics")
    def metrics_endpoint() -> Response:
        """
        Metrics endpoint for Prometheus scraping.
        
        Returns empty response in no-op mode, actual metrics when enabled.
        """
        if METRICS_ENABLED:
            from prometheus_client import generate_latest
            return Response(
                generate_latest(),
                mimetype="text/plain",
                headers={'Cache-Control': 'no-cache'}
            )
        return Response("", mimetype="text/plain")


# Export metric objects for direct access (maintains backward compatibility)
http_requests_total = _metrics_manager.http_requests_total
http_request_duration_seconds = _metrics_manager.http_request_duration_seconds
task_executions_total = _metrics_manager.task_executions_total