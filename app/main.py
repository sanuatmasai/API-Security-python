# ===============================
# app/main.py
# ===============================
# This is the main entry point for the FastAPI application.
# It sets up middleware, exception handlers, and includes all routers.

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.auth.routes import router as auth_router
from app.users.routes import router as users_router
from app.health.routes import router as health_router

# ===============================
# Database Table Creation
# ===============================
# Create the database tables based on the models if they don't exist.
Base.metadata.create_all(bind=engine)

# ===============================
# FastAPI App Initialization
# ===============================
# Initialize the FastAPI app instance with a title.
app = FastAPI(title="Secure FastAPI Auth System")

# ===============================
# Middleware Configuration
# ===============================
# 1. CORS (Cross-Origin Resource Sharing) Middleware
#    Allows the frontend (e.g., React app) to communicate with the backend API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your frontend's domain.
    allow_credentials=True,
    allow_methods=["*"],  # Allows all standard HTTP methods.
    allow_headers=["*"],  # Allows all headers.
)

# 2. Security Headers Middleware
# @app.middleware("http")
# async def add_security_headers(request: Request, call_next):
#     """
#     Adds security-related headers to every HTTP response.
#     Helps protect against common web vulnerabilities.
#     """
#     response = await call_next(request)
#     response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
#     response.headers["X-Content-Type-Options"] = "nosniff"
#     response.headers["X-Frame-Options"] = "DENY"
#     response.headers["Content-Security-Policy"] = "default-src 'self'"
#     return response

# ===============================
# Custom Exception Handler
# ===============================
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catches any unhandled exceptions and returns a generic 500 error.
    Prevents leaking sensitive stack traces to the client.
    """
    # In a real app, you would log the full error here.
    print(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."},
    )

# ===============================
# API Routers
# ===============================
# Include all the different parts of our API.
app.include_router(auth_router, prefix="/auth")
app.include_router(users_router)
app.include_router(health_router)

# ===============================
# Root Endpoint
# ===============================
@app.get("/", tags=["Root"])
def read_root():
    """
    A simple root endpoint to confirm the API is running.
    Returns a welcome message.
    """
    return {"message": "Welcome to the Secure FastAPI Authentication System!"} 