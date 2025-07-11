# ===============================
# app/schemas.py
# ===============================
# This file defines Pydantic models (schemas) for data validation and serialization.
# These schemas define the expected shape of API request and response bodies.

from pydantic import BaseModel, EmailStr, validator
import re

# --- User Schemas ---
class UserBase(BaseModel):
    """
    Base schema for user, includes common fields.
    Used as a base for other user-related schemas.
    """
    username: str  # The user's username
    email: EmailStr  # The user's email (validated as a real email)

class UserCreate(UserBase):
    """
    Schema for creating a new user. Includes password.
    Also includes validation for username and password strength.
    """
    password: str  # The user's password (plain text, will be hashed)

    @validator("username")
    def validate_username(cls, v):
        """
        Ensures username is alphanumeric and strips whitespace.
        Prevents injection attacks and keeps data clean.
        """
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric.")
        return v.strip()

    @validator("password")
    def validate_password_strength(cls, v):
        """
        Enforces password strength requirements.
        Prevents weak passwords for better security.
        """
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character.")
        return v

class UserOut(UserBase):
    """
    Schema for user data returned by the API. Excludes password.
    Used for responses to the client.
    """
    id: str  # User's unique ID
    role: str  # User's role (e.g., 'user' or 'admin')

    class Config:
        # Allows Pydantic to work with SQLAlchemy ORM objects
        from_attributes = True

# --- Token Schemas ---
class Token(BaseModel):
    """
    Schema for the JWT access and refresh tokens.
    Used for authentication responses.
    """
    access_token: str  # The JWT access token
    refresh_token: str  # The JWT refresh token
    token_type: str = "bearer"  # The type of token (always 'bearer')

class TokenData(BaseModel):
    """
    Schema for the data encoded within the JWT.
    Used for extracting user info from tokens.
    """
    user_id: str | None = None  # The user's ID (optional)

# --- Admin Schemas ---
class RoleUpdate(BaseModel):
    """
    Schema for updating a user's role (admin only).
    Used by admin endpoints to change user roles.
    """
    role: str  # The new role for the user

    @validator('role')
    def validate_role(cls, v):
        """
        Ensures the role is one of the allowed values ('user' or 'admin').
        """
        if v not in ['user', 'admin']:
            raise ValueError('Role must be either "user" or "admin"')
        return v

# --- Password Reset Schemas ---
class PasswordResetRequest(BaseModel):
    """
    Schema for the password reset request email.
    Used when a user requests a password reset link.
    """
    email: EmailStr  # The user's email address

class PasswordReset(BaseModel):
    """
    Schema for resetting the password with a token.
    Used when a user submits a new password with their reset token.
    """
    token: str  # The password reset token
    new_password: str  # The new password to set 