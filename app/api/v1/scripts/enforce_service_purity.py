import os

FORBIDDEN = ("flask", "request", "jwt", "current_app")

for root, _, files in os.walk("app/services"):
    for f in files:
        if f.endswith(".py"):
            path = os.path.join(root, f)
            with open(path) as file:
                content = file.read()
                for word in FORBIDDEN:
                    if word in content:
                        raise SystemExit(f"❌ Forbidden import in {path}")
