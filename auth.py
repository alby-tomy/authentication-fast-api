from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from  fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer


#configuration for JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

#password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#OAuth2 password bearer
oauth2_acheme = OAuth2PasswordBearer(tokenUrl="token")

#verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

#hash password
def get_password_hash(password):
    return pwd_context.hash(password)

#create access token
def create_access_token(data:dict, expires_delta:timedelta | None=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow()+expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=5)
    to_encode.update({"exp":expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# decode token and get current usr
def get_current_user(token:str = Depends(oauth2_acheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload("sub")
        if username is None:
            raise HTTPException(
                status_code = status.HTTP_401_UNAUTHORIZED,
                detail = "Could not validate credentials",
                headers={"WWW-AUthenticate":"Bearer"},
            )
            
            return username
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            details="Could not avlidate credentials",
            headers={"WWW-Authenticate" : "Bearer"},
        )