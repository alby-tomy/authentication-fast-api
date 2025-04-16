from fastapi import FastAPI, status, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import timedelta
from auth import verify_password, create_access_token, get_current_user
from models import User
from database import engine, get_db, Base
from pydantic import BaseModel

app = FastAPI()

# Initialize database
@app.on_event("startup")
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Pydantic model for token response
class TokenResponse(BaseModel):
    access_token: str
    token_type: str


# User registration
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(username: str, password: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter_by(username=username))
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    new_user = User(username=username)
    new_user.set_password(password)
    db.add(new_user)
    await db.commit()
    return {"message": "User created successfully"}


# Generate token
@app.post("/token", response_model=TokenResponse)
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter_by(username=form_data.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=15))
    return {"access_token": access_token, "token_type": "bearer"}


# Protected route
@app.get("/users/me")
async def read_users_me(current_user: str = Depends(get_current_user)):
    return {"username": current_user}
