Failure Recovery & Automation Safety Layer
==========================================

This module adds:
- Automation state machine
- Safe retries with backoff
- Failure marking
- Double-execution prevention

How it works:
PENDING → RUNNING → COMPLETED
                ↘ FAILED

You can drop these files into your existing Flask project.