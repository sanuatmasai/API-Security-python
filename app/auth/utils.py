# ===============================
# app/auth/utils.py
# ===============================
# This file contains utility functions for authentication and security.
# Includes password hashing, JWT creation/validation, and user retrieval.

from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from itsdangerous import URLSafeTimedSerializer
from fastapi import HTTPException, status, Depends

from app.models import User
from app.schemas import TokenData
from app.config import settings
from app.database import get_db
from app.auth.blocklist import is_blocklisted
import uuid

# Password hashing context using bcrypt (a secure hashing algorithm)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for extracting the token from requests
# Used for OpenAPI docs and as a dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(password: str) -> str:
    """
    Hash a plain-text password using bcrypt.
    Returns the hashed password (never store plain-text passwords).
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a hashed password.
    Returns True if they match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    """
    Create a new JWT access token with an expiration and unique ID (jti).
    The token contains user data and is signed with the secret key.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,  # Expiration time
        "jti": str(uuid.uuid4())  # Unique token ID
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: dict):
    """
    Create a new JWT refresh token with a longer expiration.
    Used to obtain new access tokens without re-authenticating.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

# Serializer for generating secure, timed tokens for password resets
password_reset_serializer = URLSafeTimedSerializer(settings.PASSWORD_RESET_TOKEN_SECRET)

def generate_password_reset_token(email: str) -> str:
    """
    Generate a secure, timed token for password reset.
    The token encodes the user's email and is valid for a limited time.
    """
    return password_reset_serializer.dumps(email, salt='password-reset-salt')

def verify_password_reset_token(token: str) -> str | None:
    """
    Verify the password reset token and return the email if valid.
    Returns None if the token is invalid or expired.
    """
    try:
        email = password_reset_serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES * 60
        )
        return email
    except Exception:
        return None

def get_user_by_email(db: Session, email: str):
    """
    Fetch a user from the database by their email address.
    Returns the User object or None if not found.
    """
    return db.query(User).filter(User.email == email).first()

def get_user_by_id(db: Session, user_id: str):
    """
    Fetch a user from the database by their unique ID.
    Returns the User object or None if not found.
    """
    return db.query(User).filter(User.id == user_id).first()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Decode the JWT, validate it, and return the current user.
    Checks if the token is revoked (blocklisted) or expired.
    Raises HTTP 401 if invalid. Used as a dependency to protect endpoints.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")  # User ID from token
        jti: str = payload.get("jti")      # Token unique ID

        if user_id is None:
            raise credentials_exception
        if jti is None or is_blocklisted(jti):
            # Token has been revoked (e.g., user logged out)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception

    user = get_user_by_email(db, email=token_data.user_id)
    if user is None:
        raise credentials_exception
    return user 