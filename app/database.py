# ===============================
# app/database.py
# ===============================
# This file sets up the database connection and session management for the app.
# It uses SQLAlchemy to interact with a SQLite database file.

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# The URL for the SQLite database file (stored locally as secure_app.db)
SQLALCHEMY_DATABASE_URL = "sqlite:///./secure_app.db"

# Create the SQLAlchemy engine, which is the main entry point to the database.
# 'connect_args' is needed for SQLite to allow multi-threaded access.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# SessionLocal is a factory for creating new database sessions.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the base class for all SQLAlchemy models (tables) in the app.
Base = declarative_base()

def get_db():
    """
    Dependency for FastAPI endpoints to get a database session.
    Ensures the session is closed after the request is done.
    Usage: pass 'db: Session = Depends(get_db)' to your endpoint.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 