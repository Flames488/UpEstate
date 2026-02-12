import os
import sys

REQUIRED_VARS = [
    "DATABASE_URL",
    "JWT_SECRET",
    "PAYSTACK_SECRET_KEY",
    "FRONTEND_URL",
]

missing = [v for v in REQUIRED_VARS if not os.getenv(v)]

if missing:
    print(f"❌ Missing required env vars: {missing}")
    sys.exit(1)
