# ===============================
# app/auth/routes.py
# ===============================
# This file defines all authentication-related API endpoints.
# Handles registration, login, logout, token refresh, password reset, and user info.

from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from uuid import uuid4

from app import schemas, models
from app.database import get_db
from app.auth.utils import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    get_user_by_email, get_current_user, generate_password_reset_token,
    verify_password_reset_token
)
from app.auth.blocklist import add_to_blocklist
from jose import jwt
from app.config import settings
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Create a router for authentication endpoints
router = APIRouter(tags=["Authentication"])

# OAuth2 scheme for extracting the token from requests
# Used for OpenAPI docs and as a dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ===============================
# User Registration Endpoint
# ===============================
@router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
    - Checks if the email is already registered.
    - Hashes the password before saving.
    - Creates and saves the new user in the database.
    Returns the created user (without password).
    """
    if get_user_by_email(db, user.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    hashed_pw = hash_password(user.password)
    new_user = models.User(id=str(uuid4()), username=user.username, email=user.email, password_hash=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# ===============================
# User Login Endpoint
# ===============================
@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Log in a user.
    - Verifies email and password.
    - Returns a new access token and refresh token if successful.
    """
    # OAuth2PasswordRequestForm uses 'username' field for email here
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # Data to encode in the tokens
    token_data = {"sub": user.email, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

# ===============================
# User Logout Endpoint
# ===============================
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(token: str = Depends(oauth2_scheme)):
    """
    Log out the current user.
    - Invalidates the current access token by adding its JTI to the blocklist in Redis.
    - The token cannot be used again after logout.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp:
            # Calculate seconds until token expiry for Redis key expiration
            import time
            exp_seconds = max(1, int(exp - time.time()))
            add_to_blocklist(jti, exp_seconds=exp_seconds)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token for logout")

# ===============================
# Token Refresh Endpoint
# ===============================
@router.post("/refresh", response_model=schemas.Token)
def refresh_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get a new access token using a refresh token.
    - Decodes the refresh token and issues new tokens if valid.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        user = get_user_by_email(db, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        # Create new tokens
        token_data = {"sub": user.email, "role": user.role}
        new_access_token = create_access_token(token_data)
        new_refresh_token = create_refresh_token(token_data)
        return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

# ===============================
# Get Current User Endpoint
# ===============================
@router.get("/me", response_model=schemas.UserOut)
def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get details of the currently authenticated user.
    Manually calls get_current_user with the extracted token and db session.
    """
    # Now, explicitly call get_current_user, passing the token and the db session
    current_user: models.User = get_current_user(token=token, db=db)
    return current_user

# ===============================
# Password Reset Request Endpoint
# ===============================
def send_reset_email(to_email: str, reset_token: str):
    """
    Sends a password reset email with the reset link to the user.
    Uses SMTP settings from config.
    """
    from app.config import settings
    # Construct the password reset link (customize the URL as needed)
    reset_link = f"http://localhost:8000/reset-password?token={reset_token}"
    subject = "Password Reset Request"
    body = f"""
    <p>Hello,</p>
    <p>You requested a password reset. Click the link below to reset your password:</p>
    <p><a href='{reset_link}'>{reset_link}</a></p>
    <p>If you did not request this, please ignore this email.</p>
    """
    msg = MIMEMultipart()
    msg['From'] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.EMAIL_FROM, to_email, msg.as_string())
    except Exception as e:
        print(f"Failed to send email: {e}")

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(request: schemas.PasswordResetRequest, db: Session = Depends(get_db)):
    """
    Request a password reset link.
    - Finds the user by email.
    - Generates a secure token.
    - Sends an email with the reset link.
    - Always returns a generic message to prevent email enumeration.
    """
    user = get_user_by_email(db, email=request.email)
    if user:
        reset_token = generate_password_reset_token(email=request.email)
        send_reset_email(request.email, reset_token)
    return {"message": "If an account with that email exists, a password reset link has been sent."}

# ===============================
# Password Reset Endpoint
# ===============================
@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(request: schemas.PasswordReset, db: Session = Depends(get_db)):
    """
    Reset the user's password using the token from the email.
    - Verifies the token and finds the user.
    - Validates the new password.
    - Updates the user's password in the database.
    """
    email = verify_password_reset_token(token=request.token)
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")
    user = get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    # Validate the new password using the same rules as registration
    try:
        schemas.UserCreate.validate_password_strength(request.new_password)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    user.password_hash = hash_password(request.new_password)
    db.commit()
    return {"message": "Password has been reset successfully."} 