"""Tracing: pydantic-ai OTel spans exported to Langfuse (or any OTLP endpoint).

Enabled when langfuse_host + langfuse_public_key + langfuse_secret_key are
set. Langfuse ingests OTLP natively at /api/public/otel, so the "pluggable
logging" seam is just OTLP — pointing at another backend needs no code change.
"""

import base64

from sleeper_service.config import get_settings

_configured = False


def setup_tracing() -> bool:
    global _configured
    if _configured:
        return True
    s = get_settings()
    if not (s.langfuse_host and s.langfuse_public_key and s.langfuse_secret_key):
        return False

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from pydantic_ai import Agent

    auth = base64.b64encode(f"{s.langfuse_public_key}:{s.langfuse_secret_key}".encode()).decode()
    exporter = OTLPSpanExporter(
        endpoint=f"{s.langfuse_host.rstrip('/')}/api/public/otel/v1/traces",
        headers={"Authorization": f"Basic {auth}"},
    )
    provider = TracerProvider(resource=Resource.create({"service.name": "sleeper-service"}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    Agent.instrument_all(True)
    _configured = True
    return True
