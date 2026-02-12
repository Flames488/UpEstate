# Option 1: Using the configurable class-based middleware
from fastapi import FastAPI

app = FastAPI()
app.add_middleware(CorrelationMiddleware)

# Option 2: Using the simple middleware function
from fastapi import FastAPI
from fastapi.middleware import Middleware

app = FastAPI(middleware=[
    Middleware(simple_correlation_middleware)
])

# Accessing correlation ID in endpoints
from fastapi import FastAPI, Request

@app.get("/example")
async def example_endpoint(request: Request):
    correlation_id = request.state.correlation_id
    return {"correlation_id": correlation_id}