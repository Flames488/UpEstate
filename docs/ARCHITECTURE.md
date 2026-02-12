# System Architecture

## Overview

This system is a multi-tenant SaaS backend for real-estate lead automation.

Components:

- Flask API (Gunicorn)
- PostgreSQL
- Redis
- Celery workers
- Stripe billing
- JWT auth
- Audit logging
- Feature flags
- Metrics

## Service Diagram

Client → Load Balancer → API → DB
                   → Redis → Workers

## Design Principles

- Twelve-factor app
- Domain-driven errors
- Idempotent jobs
- Observability first
- Least privilege security
