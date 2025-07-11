# ===============================
# app/models.py
# ===============================
# This file defines the database models (tables) using SQLAlchemy ORM.
# Each class represents a table in the database.

from sqlalchemy import Column, String
from .database import Base

class User(Base):
    """
    User model represents the 'users' table in the database.
    Each instance of this class is a row in the table.
    """
    __tablename__ = "users"  # Name of the table in the database

    # Unique ID for each user (primary key)
    id = Column(String, primary_key=True, index=True)
    # Username (must be unique)
    username = Column(String, unique=True, index=True)
    # Email address (must be unique)
    email = Column(String, unique=True, index=True)
    # Hashed password (never store plain-text passwords!)
    password_hash = Column(String)
    # Role of the user (e.g., 'user' or 'admin'), default is 'user'
    role = Column(String, default="user") 