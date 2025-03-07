from typing import Optional
from datetime import datetime, timedelta, timezone
from config import Config
from postgres import PostgresDB
from passlib.context import CryptContext
from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated
from pydantic import BaseModel, EmailStr, field_validator, ValidationError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from logger import Logger
import re
import jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
router = APIRouter()

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: int | None = None

class User:      
    
    def __init__(self, id: int, username: str, firstname: str, lastname: str, email: str, is_admin: bool, password: str, created_at: datetime, modified_at: datetime, last_login: Optional[datetime] = None):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin
        self.firstname = firstname
        self.lastname = lastname
        self._password = password
        self.created_at = created_at
        self.modified_at = modified_at
        self.last_login = last_login
    
    @property
    def password(self):
        return self._password 
        
    @password.setter
    def password(self, password: str):        
        self._password = User.hash_password(password)

    @staticmethod
    async def get_by_email(email: str) -> Optional['User']:
        query = "SELECT * FROM users WHERE email = $1"
        data = await (await PostgresDB.get_instance()).fetch_one(query, email)
        return User(*data) if data else None
    
    @staticmethod
    async def get_by_id(id: int) -> Optional['User']:
        query = "SELECT * FROM users WHERE id = $1"
        data = await (await PostgresDB.get_instance()).fetch_one(query, id)
        return User(*data) if data else None
    
    @staticmethod
    async def get_by_username(username: str) -> Optional['User']:
        query = "SELECT * FROM users WHERE username = $1"
        data = await (await PostgresDB.get_instance()).fetch_one(query, username)
        return User(*data) if data else None
    
    @staticmethod
    async def create(username: str, firstname: str, lastname: str, email: str, is_admin: bool, password: str) -> 'User':
        query = "INSERT INTO users (username, firstname, lastname, email, is_admin, pw) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at, modified_at, last_login"
        password = User.hash_password(password)
        data = await (await PostgresDB.get_instance()).fetch_one(query, username, firstname, lastname, email, is_admin, password)
        return User(data[0], username, firstname, lastname, email, is_admin, password, data[1], data[2], data[3]) if data else None
    
    async def update(self):
        query = "UPDATE users SET username = $1, firstname = $2, lastname = $3, email = $4, is_admin = $5, pw = $6, modified_at = $7, last_login = $8 WHERE id = $9"
        await (await PostgresDB.get_instance()).execute(query, self.username, self.firstname, self.lastname, self.email, self.is_admin, self._password, datetime.now(timezone.utc), self.last_login, self.id)

    async def delete(self):
        query = "DELETE FROM users WHERE id = $1"
        await (await PostgresDB.get_instance()).execute(query, self.id)

    @staticmethod
    def hash_password(password: str)-> str:
        return pwd_context.hash(password)
    
    def is_password_valid(self, password: str) -> bool:
        return pwd_context.verify(password, self._password)
    
    @staticmethod
    async def login(token: Annotated[str, Depends(oauth2_scheme)])-> 'User':
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, Config.get_instance().oauth2['secret_key'], algorithms=[Config.get_instance().oauth2['algorithm']])
            user_id = payload.get("user_id")
            if user_id is None:
                raise credentials_exception
            token_data = TokenData(user_id=user_id)
        except InvalidTokenError:
            raise credentials_exception
        user = await User.get_by_id(token_data.user_id)
        if user is None:
            raise credentials_exception
        user.last_login = datetime.now(timezone.utc)
        await user.update()
        return user
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, Config.get_instance().oauth2['secret_key'], algorithm=Config.get_instance().oauth2['algorithm'])
        return encoded_jwt
    
    async def has_permission(self, permission_key: str) -> int:
        if self.is_admin:
            return True
        query = "SELECT COUNT(id) FROM users_permissions WHERE user_id = $1 AND permission_key = $2 LIMIT 1"
        data = await (await PostgresDB.get_instance()).fetch_one(query, self.id, permission_key)
        return data[0] > 0

class Validate:
    @staticmethod
    def username(value: str) -> str:
        if not re.fullmatch(r"^[a-zA-Z0-9_]{3,20}$", value):
            raise ValueError("Username must be 3-20 characters and contain only letters, numbers, and underscores.")
        return value
    @staticmethod
    def firstname(value: str) -> str:
        value = value.strip().capitalize()
        if not re.fullmatch(r"^[A-Za-z]{2,30}$", value):
            raise ValueError("Firstname must be 2-30 characters and contain only letters.")
        return value
    @staticmethod
    def lastname(value: str) -> str:
        value = value.strip().capitalize()
        if not re.fullmatch(r"^[A-Za-z]{2,30}$", value):
            raise ValueError("Lastname must be 2-30 characters and contain only letters.")
        return value
    @staticmethod
    def email(value: str) -> str:   
        if len(value) > 255:
            raise ValueError("Email must be at most 255 characters long.")       
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.fullmatch(email_regex, value):
            raise ValueError("Invalid email format.")
        return value
    @staticmethod
    def password(value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one number.")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in value):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in value):
            raise ValueError("Password must contain at least one special character.")        
        return value

@router.put("/user")
async def create_user(req_user: Annotated[User, Depends(User.login)], username: str, firstname: str, lastname: str, email: str, is_admin: bool, password: str):
    try:     
        if req_user.has_permission("usermanagement") == False:
            raise HTTPException(status_code=403, detail="Permission denied")   
        username = Validate.username(username)
        firstname = Validate.firstname(firstname)
        lastname = Validate.lastname(lastname)
        email = Validate.email(email)
        password = Validate.password(password)
        check_username = await User.get_by_username(username)
        if check_username:
            raise HTTPException(status_code=400, detail="Username already exists")        
        check_email = await User.get_by_email(email)
        if check_email:
            raise HTTPException(status_code=400, detail="Email already exists")        
        user = await User.create(username, firstname, lastname, email, is_admin, password)
        return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "is_admin": user.is_admin, "created_at": user.created_at, "modified_at": user.modified_at, "last_login": user.last_login}
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@router.patch("/user")
async def update_user(req_user: Annotated[User, Depends(User.login)], user_id: Optional[int] = None, username: Optional[str] = None, firstname: Optional[str] = None, lastname: Optional[str] = None, email: Optional[str] = None, is_admin: Optional[bool] = None, password: Optional[str] = None):    
    if user_id == None:
        user = req_user
    else:
        if req_user.has_permission("usermanagement") == False:
            raise HTTPException(status_code=403, detail="Permission denied")
        user = await User.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")    
    if username:
        username = Validate.username(username)
        check_username = await User.get_by_username(username)
        if check_username:
            raise HTTPException(status_code=400, detail="Username already exists")
        user.username = username        
    if firstname:
        user.firstname = Validate.firstname(firstname)        
    if lastname:
        user.lastname = Validate.lastname(lastname)        
    if email:
        email = Validate.email(email)
        check_email = await User.get_by_email(email)
        if check_email:
            raise HTTPException(status_code=400, detail="Email already exists")
        user.email = email        
    if password:
        user.password = Validate.password(password)
    if is_admin is not None and (is_admin == True or is_admin == False):
        user.is_admin = is_admin
    user.modified_at = datetime.now(timezone.utc)        
    await user.update()
    return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "is_admin": user.is_admin, "created_at": user.created_at, "modified_at": user.modified_at, "last_login": user.last_login}
    

@router.get("/user/me")
async def get_my_user(user: Annotated[User, Depends(User.login)]):
    return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "is_admin": user.is_admin, "created_at": user.created_at, "modified_at": user.modified_at, "last_login": user.last_login}

@router.get("/user/{user_id}")
async def get_user(req_user: Annotated[User, Depends(User.login)], user_id: int):
    if req_user.has_permission("usermanagement") == False:
        raise HTTPException(status_code=403, detail="Permission denied")
    user = await User.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "is_admin": user.is_admin, "created_at": user.created_at, "modified_at": user.modified_at, "last_login": user.last_login}

@router.get("/users")
async def get_list_of_all_users(req_user: Annotated[User, Depends(User.login)]):
    if req_user.has_permission("usermanagement") == False:
        raise HTTPException(status_code=403, detail="Permission denied")
    users = await (await PostgresDB.get_instance()).fetch("SELECT id, username, firstname, lastname, email, is_admin, created_at, modified_at, last_login FROM users ORDER BY id ASC")
    return users

@router.delete("/user/{user_id}")
async def delete_user(req_user: Annotated[User, Depends(User.login)], user_id: int):
    if req_user.has_permission("usermanagement") == False:
        raise HTTPException(status_code=403, detail="Permission denied")
    user = await User.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await user.delete()
    return {"message": "User deleted successfully"}

@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await User.get_by_username(form_data.username)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    if not user.is_password_valid(form_data.password):
        raise HTTPException(
            status_code=403,
            detail="Invalid username or password"
        )    
    access_token_expires = timedelta(minutes=Config.get_instance().oauth2['access_token_expire_minutes'])
    access_token = User.create_access_token(data={"user_id": user.id}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")

@router.get("/permissions")
async def get_permissions(user: Annotated[User, Depends(User.login)]):
    data = await (await PostgresDB.get_instance()).fetch("SELECT permission_key FROM users_permissions WHERE user_id = $1", user.id)
    return [row[0] for row in data]

@router.get("/permission/{permission_key}")
async def check_permission(user: Annotated[User, Depends(User.login)], permission_key: str):
    return await user.has_permission(permission_key)