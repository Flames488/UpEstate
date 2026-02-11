
from app.tasks.base import TaskRunner

class InMemoryTaskRunner(TaskRunner):
    def enqueue(self, name: str, payload: dict):
        print(f"Queued task {name} with payload {payload}")
