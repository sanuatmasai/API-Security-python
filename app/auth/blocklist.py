# ===============================
# app/auth/blocklist.py
# ===============================
# This file manages a blocklist for revoked JWTs to handle logouts.
# Now uses Redis for persistent, fast-access storage.

import redis
import os

# Redis connection settings (customize as needed or use environment variables)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

# Create a Redis client instance
redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

# Key prefix for blocklisted JWTs in Redis
BLOCKLIST_PREFIX = "jwt_blocklist:"

def add_to_blocklist(jti: str, exp_seconds: int = 3600):
    """
    Add a token's JTI (unique identifier) to the Redis blocklist.
    Optionally set an expiration (in seconds) to auto-remove after token expiry.
    """
    redis_client.setex(BLOCKLIST_PREFIX + jti, exp_seconds, "revoked")

def is_blocklisted(jti: str) -> bool:
    """
    Check if a token's JTI is in the Redis blocklist.
    Returns True if the token is revoked, False otherwise.
    """
    return redis_client.exists(BLOCKLIST_PREFIX + jti) == 1 