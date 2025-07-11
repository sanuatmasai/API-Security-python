# ===============================
# app/users/routes.py
# ===============================
# This file defines endpoints for user management (admin-only).
# Only admin users can access these endpoints.

from fastapi import APIRouter, Depends, HTTPException, status, Response
from typing import List
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.auth.utils import get_current_user, get_user_by_id

# Create a router for user management endpoints
router = APIRouter(prefix="/users", tags=["Users"])

def get_current_admin_user(current_user: models.User = Depends(get_current_user)):
    """
    Dependency to check if the current user is an admin.
    Raises HTTP 403 if not an admin.
    Used to protect admin-only endpoints.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user

# ===============================
# List All Users (Admin Only)
# ===============================
@router.get("/", response_model=List[schemas.UserOut], dependencies=[Depends(get_current_admin_user)])
def list_users(db: Session = Depends(get_db)):
    """
    List all users in the database.
    Only accessible by admin users.
    Returns a list of user objects.
    """
    return db.query(models.User).all()

# ===============================
# Update User Role (Admin Only)
# ===============================
@router.put("/{user_id}/role", response_model=schemas.UserOut, dependencies=[Depends(get_current_admin_user)])
def update_user_role(user_id: str, data: schemas.RoleUpdate, db: Session = Depends(get_db)):
    """
    Update a user's role (e.g., promote to admin).
    Only accessible by admin users.
    Returns the updated user object.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.role = data.role
    db.commit()
    db.refresh(user)
    return user

# ===============================
# Delete User (Admin Only)
# ===============================
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(get_current_admin_user)])
def delete_user(user_id: str, db: Session = Depends(get_db)):
    """
    Delete a user from the database.
    Only accessible by admin users.
    Returns HTTP 204 on success.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(user)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)