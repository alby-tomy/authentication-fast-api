from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List

from database import get_db
from models.user_model import User, LoginHistory
from schemas.user_schema import UserCreate, UserLogin, Token, LoginHistoryResponse, TrackLoginRequest, UserResponse
from utils.auth_util import hash_password, verify_password, create_access_token, get_current_user, get_current_admin_user

router = APIRouter()

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check if the user already exists
    result = await db.execute(
        select(User).filter(User.username == user.username)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists.")

    # Hash the password before saving
    hashed_password = hash_password(user.password)

    # Insert new user with hashed password and is_admin flag
    new_user = User(
        username=user.username,
        password=hashed_password,
        is_admin=user.is_admin  # Use the is_admin field from the request
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Return success message and user data (excluding password)
    return {
        "message": "User registered successfully",
        "user": {"id": new_user.id, "username": new_user.username, "is_admin": new_user.is_admin}
    }



@router.post("/login", response_model=Token)
async def login_user(user: UserLogin, db: AsyncSession = Depends(get_db)):
    # Use ORM to fetch the user by username
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar_one_or_none()

    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if the user is already logged in
    if db_user.is_logged_in:
        raise HTTPException(status_code=400, detail="User is already logged in.")

    # Mark the user as logged in
    db_user.is_logged_in = True
    await db.commit()

    # Create the access token
    access_token = create_access_token(data={"sub": db_user.username})

    # Log the login history
    login_history = LoginHistory(user_id=db_user.id, username=db_user.username)
    db.add(login_history)
    await db.commit()

    return {"access_token": access_token, "token_type": "bearer"}






@router.post("/logout")
async def logout_user(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    current_user.is_logged_in = False
    await db.commit()
    return {"message": "Logged out successfully."}

@router.get("/admin-list-users", response_model=List[UserResponse])
async def admin_list_users(
    current_admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve a list of all users in the system. 
    Accessible only to admin users.
    """
    # Fetch all users from the database
    result = await db.execute(select(User))
    users = result.scalars().all()

    if not users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No users found in the system.",
        )

    # Return the list of users
    return [
        UserResponse(
            id=user.id,
            username=user.username,
            is_admin=user.is_admin
        )
        for user in users
    ]

@router.get("/list-users", response_model=List[UserResponse])
async def list_users(db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    """
    Retrieve a list of non-admin users.
    """
    # Fetch non-admin users from the database
    result = await db.execute(select(User).where(User.is_admin == False))
    users = result.scalars().all()

    if not users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No non-admin users found in the system.",
        )

    # Return the list of non-admin users
    return [
        UserResponse(
            id=user.id,
            username=user.username,
            is_admin=user.is_admin
        )
        for user in users
    ]


@router.get("/user-track-login", response_model=List[LoginHistoryResponse])
async def user_track_login(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Fetch login history for the current user
    result = await db.execute(
        select(LoginHistory)
        .options(selectinload(LoginHistory.user))
        .where(LoginHistory.user_id == current_user.id)
    )
    login_history = result.scalars().all()

    if not login_history:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No login history found for the current user.",
        )

    # Return the login history as a list of response objects
    return [
        LoginHistoryResponse(
            id=lh.id,
            username=current_user.username,
            timestamp=lh.timestamp
        )
        for lh in login_history
    ]


@router.post("/admin-track-login", response_model=List[LoginHistoryResponse])
async def admin_track_login(
    track_request: TrackLoginRequest,
    current_admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    # Fetch user from the database
    result = await db.execute(select(User).where(User.username == track_request.username))
    user = result.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Fetch login history of the user with related user loaded
    result = await db.execute(
        select(LoginHistory).options(selectinload(LoginHistory.user)).where(LoginHistory.user_id == user.id)
    )
    login_history = result.scalars().all()

    if not login_history:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No login history found for this user.",
        )

    # Return login history
    return login_history


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

    # Check if the user exists in the database
    result = await db.execute(select(User).where(User.username == request.username))
    user_to_delete = result.scalar_one_or_none()

    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with username '{request.username}' not found."
        )

    # Prevent admin from deleting their own account
    if user_to_delete.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot delete your own account."
        )

    # Prevent deletion of other admin accounts
    if user_to_delete.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin accounts cannot be deleted."
        )

    # Attempt to delete the user
    try:
        await db.delete(user_to_delete)
        await db.commit()
        return {"message": f"User '{request.username}' has been successfully deleted."}
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to delete user due to database constraints."
        )


@router.delete("/delete-account", status_code=status.HTTP_200_OK)
async def delete_current_user(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete the currently logged-in user's account.
    Accessible to all users after login.
    """

    # Ensure the user exists in the database
    result = await db.execute(select(User).where(User.id == current_user.id))
    user_to_delete = result.scalar_one_or_none()

    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Current user not found in the database."
        )

    # Prevent deletion if the user is an admin
    if user_to_delete.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot delete their own accounts."
        )

    # Attempt to delete the user's account
    try:
        await db.delete(user_to_delete)
        await db.commit()
        return {"message": "Your account has been successfully deleted."}
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to delete your account due to database constraints."
        )


@router.put("/downgrade-to-normal-user", status_code=status.HTTP_200_OK)
async def downgrade_to_normal_user(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Downgrade the current admin user to a normal user.
    Accessible only to logged-in admin users.
    """

    # Ensure the current user is an admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not an admin and cannot perform this action."
        )

    # Update the user's role to normal user
    try:
        current_user.is_admin = False
        db.add(current_user)
        await db.commit()
        return {"message": "You have been successfully downgraded to a normal user."}
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to downgrade your account due to database constraints."
        )


