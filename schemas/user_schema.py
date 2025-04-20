from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str
    is_admin:bool= False

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginHistoryResponse(BaseModel):
    id: int
    username: str
    timestamp: datetime

    class Config:
        orm_mode = True

class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: Optional[bool]
    # login_history: Optional[List[LoginHistoryResponse]] = None

    class Config:
        orm_mode = True

class UserResponsePublic(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class TrackLoginRequest(BaseModel):
    username: str
