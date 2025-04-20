from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from typing import List

from database import get_db
from models.user_model import User, LoginHistory
from schemas.user_schema import UserCreate, UserLogin, Token, LoginHistoryResponse, TrackLoginRequest, UserResponse, UserResponsePublic
from utils.auth_util import hash_password, verify_password, create_access_token, get_current_user

router = APIRouter()

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(User).filter(User.username == user.username))
        existing_user = result.scalar_one_or_none()

        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists.")

        hashed_password = hash_password(user.password)

        new_user = User(
            username=user.username,
            password=hashed_password,
            is_admin=user.is_admin  # is_admin will default to False if not provided
        )

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        return {
            "message": "User registered successfully",
            "user": {"id": new_user.id, "username": new_user.username, "is_admin": new_user.is_admin}
        }
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")



@router.post("/login", response_model=Token)
async def login_user(user: UserLogin, db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(User).filter(User.username == user.username))
        db_user = result.scalar_one_or_none()

        if not db_user or not verify_password(user.password, db_user.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if db_user.is_logged_in:
            raise HTTPException(status_code=400, detail="User is already logged in.")

        db_user.is_logged_in = True
        await db.commit()

        access_token = create_access_token(data={"sub": db_user.username})

        login_history = LoginHistory(user_id=db_user.id, username=db_user.username)
        db.add(login_history)
        await db.commit()

        return {"access_token": access_token, "token_type": "bearer"}
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.post("/logout")
async def logout_user(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    try:
        current_user.is_logged_in = False
        await db.commit()
        return {"message": "Logged out successfully."}
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/list-users", response_model=List[str])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Fetch only non-admin users
        result = await db.execute(select(User).where(User.is_admin == False))
        users = result.scalars().all()

        if not users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No non-admin users found in the system."
            )

        # Replace current user's username with "you"
        user_list = [
            "you" if user.username == current_user.username else user.username
            for user in users
        ]

        return user_list
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")




@router.get("/user-track-login", response_model=List[LoginHistoryResponse])
async def user_track_login(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(
            select(LoginHistory)
            .where(LoginHistory.user_id == current_user.id)
        )
        login_history = result.scalars().all()

        if not login_history:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No login history found for the current user.",
            )

        return [
            LoginHistoryResponse(
                id=lh.id,
                username=current_user.username,
                timestamp=lh.timestamp
            )
            for lh in login_history
        ]
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
