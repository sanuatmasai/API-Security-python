# ===============================
# app/health/routes.py
# ===============================
# This file defines a simple health check endpoint for the API.
# Used to verify that the API and database are running.

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db

# Create a router for health check endpoints
router = APIRouter(prefix="/health", tags=["Health"])

@router.get("/")
def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint.
    - Returns a success message if the API and database are working.
    - Tries to connect to the database to ensure it's available.
    - Returns HTTP 503 if the database connection fails.
    """
    try:
        # Simple query to check database connectivity
        db.execute('SELECT 1')
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connection failed: {e}"
        ) 