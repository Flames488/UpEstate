# app/observability/tracing.py
"""
OpenTelemetry Tracing Configuration

This module provides centralized tracing configuration for the application.
Supports multiple exporters: OTLP (Tempo, Honeycomb, Datadog), Jaeger, and Console.

Environment Variables:
    OTEL_EXPORTER_OTLP_ENDPOINT: OTLP collector endpoint
    OTEL_EXPORTER_JAEGER_ENDPOINT: Jaeger collector endpoint
    OTEL_TRACES_EXPORTER: Comma-separated list of exporters (otlp, jaeger, console)
    SERVICE_NAME: Service name for traces
    SERVICE_VERSION: Service version
    DEPLOYMENT_ENVIRONMENT: Deployment environment (dev, staging, production)
"""

import os
import logging
from typing import List, Optional, Dict, Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

# Conditional imports for optional exporters
try:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    OTLP_AVAILABLE = True
except ImportError:
    OTLP_AVAILABLE = False
    logging.warning("OTLP exporter not available. Install 'opentelemetry-exporter-otlp'")

try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    JAEGER_AVAILABLE = True
except ImportError:
    JAEGER_AVAILABLE = False
    logging.warning("Jaeger exporter not available. Install 'opentelemetry-exporter-jaeger'")

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPSpanExporterGRPC
    OTLP_GRPC_AVAILABLE = True
except ImportError:
    OTLP_GRPC_AVAILABLE = False

# Instrumentation imports
try:
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    INSTRUMENTATION_AVAILABLE = True
except ImportError:
    INSTRUMENTATION_AVAILABLE = False
    logging.warning("Instrumentation packages not available. Some auto-instrumentation may not work.")

# Configure logging
logger = logging.getLogger(__name__)


class TracingConfig:
    """Configuration for OpenTelemetry tracing"""
    
    def __init__(self):
        self.service_name = os.getenv("SERVICE_NAME", "upestate-api")
        self.service_version = os.getenv("SERVICE_VERSION", "1.0.0")
        self.environment = os.getenv("DEPLOYMENT_ENVIRONMENT", os.getenv("FLASK_ENV", "production"))
        self.trace_exporters = os.getenv("OTEL_TRACES_EXPORTER", "console").split(",")
        
        # Endpoint configurations
        self.otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        self.jaeger_endpoint = os.getenv("OTEL_EXPORTER_JAEGER_ENDPOINT")
        
        # Sampling configuration
        self.sample_rate = float(os.getenv("OTEL_TRACES_SAMPLER_RATIO", "1.0"))


class TracingManager:
    """
    Manages OpenTelemetry tracing configuration and exporters.
    
    Example usage:
        from app.observability.tracing import tracing_manager
        
        # Initialize tracing
        tracing_manager.setup_tracing()
        
        # Get tracer
        tracer = tracing_manager.get_tracer(__name__)
    """
    
    def __init__(self):
        self.config = TracingConfig()
        self.provider: Optional[TracerProvider] = None
        self.tracer: Optional[trace.Tracer] = None
        self.initialized = False
        
    def _create_resource(self) -> Resource:
        """Create OpenTelemetry resource with service attributes"""
        attributes = {
            "service.name": self.config.service_name,
            "service.version": self.config.service_version,
            "deployment.environment": self.config.environment,
            "telemetry.sdk.name": "opentelemetry",
            "telemetry.sdk.language": "python",
        }
        
        # Add optional attributes
        if os.getenv("HOSTNAME"):
            attributes["host.name"] = os.getenv("HOSTNAME")
        if os.getenv("POD_NAME"):
            attributes["k8s.pod.name"] = os.getenv("POD_NAME")
            
        return Resource.create(attributes)
    
    def _setup_otlp_exporter(self, processors: List) -> None:
        """Setup OTLP exporter (HTTP)"""
        if not OTLP_AVAILABLE:
            logger.warning("OTLP exporter requested but not available")
            return
            
        if not self.config.otlp_endpoint:
            logger.warning("OTLP exporter requested but OTEL_EXPORTER_OTLP_ENDPOINT not set")
            return
            
        try:
            exporter = OTLPSpanExporter(endpoint=self.config.otlp_endpoint)
            processor = BatchSpanProcessor(exporter)
            processors.append(processor)
            logger.info(f"OTLP exporter configured for endpoint: {self.config.otlp_endpoint}")
        except Exception as e:
            logger.error(f"Failed to setup OTLP exporter: {e}")
    
    def _setup_jaeger_exporter(self, processors: List) -> None:
        """Setup Jaeger exporter"""
        if not JAEGER_AVAILABLE:
            logger.warning("Jaeger exporter requested but not available")
            return
            
        if not self.config.jaeger_endpoint:
            logger.warning("Jaeger exporter requested but OTEL_EXPORTER_JAEGER_ENDPOINT not set")
            return
            
        try:
            exporter = JaegerExporter(
                collector_endpoint=self.config.jaeger_endpoint,
            )
            processor = BatchSpanProcessor(exporter)
            processors.append(processor)
            logger.info(f"Jaeger exporter configured for endpoint: {self.config.jaeger_endpoint}")
        except Exception as e:
            logger.error(f"Failed to setup Jaeger exporter: {e}")
    
    def _setup_console_exporter(self, processors: List) -> None:
        """Setup Console exporter for debugging"""
        try:
            exporter = ConsoleSpanExporter()
            processor = SimpleSpanProcessor(exporter)  # Use simple for immediate visibility
            processors.append(processor)
            logger.info("Console exporter configured")
        except Exception as e:
            logger.error(f"Failed to setup Console exporter: {e}")
    
    def setup_tracing(self, app=None, db_engine=None) -> Optional[trace.Tracer]:
        """
        Initialize OpenTelemetry tracing with configured exporters.
        
        Args:
            app: Flask application instance (optional, for auto-instrumentation)
            db_engine: SQLAlchemy engine (optional, for auto-instrumentation)
            
        Returns:
            Tracer instance if successful, None otherwise
        """
        if self.initialized:
            logger.warning("Tracing already initialized")
            return self.tracer
        
        try:
            # Create resource
            resource = self._create_resource()
            
            # Create provider
            self.provider = TracerProvider(resource=resource)
            
            # Setup exporters based on configuration
            processors = []
            
            for exporter_name in self.config.trace_exporters:
                exporter_name = exporter_name.strip().lower()
                
                if exporter_name == "otlp" and "otlp" in self.config.trace_exporters:
                    self._setup_otlp_exporter(processors)
                elif exporter_name == "jaeger" and "jaeger" in self.config.trace_exporters:
                    self._setup_jaeger_exporter(processors)
                elif exporter_name == "console" and "console" in self.config.trace_exporters:
                    self._setup_console_exporter(processors)
                else:
                    logger.warning(f"Unknown exporter: {exporter_name}")
            
            # Register processors
            for processor in processors:
                self.provider.add_span_processor(processor)
            
            # Set global provider
            trace.set_tracer_provider(self.provider)
            
            # Auto-instrumentation
            if INSTRUMENTATION_AVAILABLE and app:
                self._setup_auto_instrumentation(app, db_engine)
            
            # Create tracer
            self.tracer = trace.get_tracer(
                name=self.config.service_name,
                version=self.config.service_version
            )
            
            self.initialized = True
            logger.info(f"Tracing initialized with exporters: {self.config.trace_exporters}")
            
            return self.tracer
            
        except Exception as e:
            logger.error(f"Failed to initialize tracing: {e}")
            # Fallback to no-op tracer
            self.tracer = trace.get_tracer(__name__)
            return self.tracer
    
    def _setup_auto_instrumentation(self, app, db_engine=None) -> None:
        """Setup auto-instrumentation for frameworks"""
        try:
            FlaskInstrumentor().instrument_app(app)
            RequestsInstrumentor().instrument()
            
            if db_engine:
                SQLAlchemyInstrumentor().instrument(engine=db_engine)
                
            logger.info("Auto-instrumentation configured")
        except Exception as e:
            logger.error(f"Failed to setup auto-instrumentation: {e}")
    
    def get_tracer(self, module_name: str = None) -> trace.Tracer:
        """
        Get a tracer instance.
        
        Args:
            module_name: Name of the module requesting the tracer
            
        Returns:
            Tracer instance
        """
        if not self.initialized:
            logger.warning("Tracing not initialized. Call setup_tracing() first.")
            # Return a no-op tracer if not initialized
            return trace.get_tracer(module_name or __name__)
        
        if module_name:
            return trace.get_tracer(module_name)
        
        return self.tracer or trace.get_tracer(__name__)
    
    def get_current_span(self) -> Optional[trace.Span]:
        """Get the current active span"""
        return trace.get_current_span()
    
    def get_current_context(self):
        """Get the current trace context"""
        return trace.get_current_span().get_span_context()
    
    def shutdown(self) -> None:
        """Shutdown tracing"""
        if self.provider:
            self.provider.shutdown()
            self.initialized = False
            logger.info("Tracing shutdown complete")


# Global tracing manager instance
tracing_manager = TracingManager()


# Convenience functions for easier access
def setup_tracing(app=None, db_engine=None) -> Optional[trace.Tracer]:
    """Convenience function to setup tracing"""
    return tracing_manager.setup_tracing(app, db_engine)


def get_tracer(module_name: str = None) -> trace.Tracer:
    """Convenience function to get a tracer"""
    return tracing_manager.get_tracer(module_name)


def get_current_span() -> Optional[trace.Span]:
    """Get the current active span"""
    return tracing_manager.get_current_span()


def get_current_context():
    """Get the current trace context"""
    return tracing_manager.get_current_context()


# Export public interface
__all__ = [
    'tracing_manager',
    'setup_tracing',
    'get_tracer',
    'get_current_span',
    'get_current_context',
    'TracingManager',
    'TracingConfig',
]