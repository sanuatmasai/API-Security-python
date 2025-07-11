# ===============================
# app/config.py
# ===============================
# This file manages all configuration settings for the application.
# It loads secrets and settings from environment variables or a .env file.
# Using Pydantic's BaseSettings ensures type validation and easy access.

from pydantic_settings import BaseSettings
import os

# Build the path to the .env file relative to this config file.
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')

class Settings(BaseSettings):
    """
    Settings class holds all application configuration values.
    It reads from environment variables or a .env file automatically.
    """
    # Secret key for signing JWT tokens (keep this secret!)
    SECRET_KEY: str = "mysecretkey"
    # Algorithm used for JWT encoding (HS256 is a common choice)
    ALGORITHM: str = "HS256"
    # How long access tokens are valid (in minutes)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    # How long refresh tokens are valid (in days)
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # Secret key for password reset tokens (should be different from SECRET_KEY)
    PASSWORD_RESET_TOKEN_SECRET: str = "mysecretpasswordresetkey"
    # How long password reset tokens are valid (in minutes)
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # --- Redis Settings ---
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB: int = int(os.getenv("REDIS_DB", 0))

    # --- Email/SMTP Settings ---
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER: str = os.getenv("SMTP_USER", "your_email@gmail.com")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "your_email_password")
    EMAIL_FROM: str = os.getenv("EMAIL_FROM", "your_email@gmail.com")
    EMAIL_FROM_NAME: str = os.getenv("EMAIL_FROM_NAME", "Secure App")

    class Config:
        # Specify the .env file to load environment variables from
        env_file = env_path

# Create a single instance of Settings to be used throughout the app
settings = Settings() 