from database import Base
from sqlalchemy import Column, Integer, String
from auth import get_password_hash


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    def set_password(self, password:str):
        self.hashed_password = get_password_hash(password)