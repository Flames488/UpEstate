import time

def retry(operation, max_attempts=3, base_delay=2):
    attempt = 0
    while attempt < max_attempts:
        try:
            return operation()
        except Exception as e:
            attempt += 1
            if attempt >= max_attempts:
                raise
            time.sleep(base_delay ** attempt)