from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from typing import List

from database import get_db
from models.user_model import User, LoginHistory
from schemas.user_schema import UserResponse, LoginHistoryResponse, TrackLoginRequest
from utils.auth_util import get_current_admin_user

router = APIRouter()

# Retrieve all users at once instead of querying one by one
@router.get("/admin-list-users", response_model=List[UserResponse])
async def admin_list_users(
    current_admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve a list of all users in the system. 
    Accessible only to admin users.
    """
    try:
        result = await db.execute(select(User))  # Single query to fetch all users
        users = result.scalars().all()

        if not users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No users found in the system.",
            )

        return [
            UserResponse(
                id=user.id,
                username=user.username,
                is_admin=user.is_admin
            )
            for user in users
        ]
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error occurred: {str(e)}"
        )


# Admin track login: fetching login history in batches rather than individually
@router.post("/admin-track-login", response_model=List[LoginHistoryResponse])
async def admin_track_login(
    track_request: TrackLoginRequest,
    current_admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(select(User).where(User.username == track_request.username))
        user = result.scalars().first()

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Optimize: Using selectinload for fetching related login history efficiently
        result = await db.execute(
            select(LoginHistory).options(selectinload(LoginHistory.user)).where(LoginHistory.user_id == user.id)
        )
        login_history = result.scalars().all()

        if not login_history:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No login history found for this user.",
            )

        return [
            LoginHistoryResponse(
                id=lh.id,
                username=user.username,
                timestamp=lh.timestamp
            )
            for lh in login_history
        ]
    
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error occurred: {str(e)}"
        )


# Delete user: Checking integrity error with a single batch query
@router.delete("/delete-user", status_code=status.HTTP_200_OK)
async def delete_user(
    request: TrackLoginRequest,  # Expecting "username" in the request body
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """
    Delete a user account by username.
    Accessible only to admin users.
    """
    try:
        # Use a single query to check and retrieve user by username
        result = await db.execute(select(User).where(User.username == request.username))
        user_to_delete = result.scalar_one_or_none()

        if not user_to_delete:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with username '{request.username}' not found."
            )

        if user_to_delete.id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot delete your own account."
            )

        if user_to_delete.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin accounts cannot be deleted."
            )

        try:
            await db.delete(user_to_delete)  # Only one database operation for delete
            await db.commit()
            return {"message": f"User '{request.username}' has been successfully deleted."}
        except IntegrityError as e:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unable to delete user due to database constraints: {str(e)}"
            )
    
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error occurred: {str(e)}"
        )


# Downgrade user: Update the user's role in a single transaction
@router.put("/downgrade-to-normal-user", status_code=status.HTTP_200_OK)
async def downgrade_to_normal_user(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """
    Downgrade the current admin user to a normal user.
    Accessible only to logged-in admin users.
    """
    try:
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not an admin and cannot perform this action."
            )

        current_user.is_admin = False  # Change role in a single query
        db.add(current_user)
        await db.commit()
        return {"message": "You have been successfully downgraded to a normal user."}
    
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to downgrade your account due to database constraints: {str(e)}"
        )
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error occurred: {str(e)}"
        )
