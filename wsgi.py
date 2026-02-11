import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

config = os.getenv("FLASK_CONFIG", "production")

app = create_app(config)

print(f"[BOOT] Running in {config} mode")
