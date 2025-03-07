from typing import Optional
from datetime import datetime
from postgres import PostgresDB
from passlib.context import CryptContext
from fastapi import APIRouter, HTTPException, Depends
from typing import Annotated
from pydantic import BaseModel, EmailStr, field_validator, ValidationError
import re

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User:    
    
    def __init__(self, id: int, username: str, firstname: str, lastname: str, email: str, password: str, created_at: datetime, last_seen: Optional[datetime] = None):
        self.id = id
        self.username = username
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self._password = password
        self.created_at = created_at
        self.last_seen = last_seen

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
    async def create(username: str, firstname: str, lastname: str, email: str, password: str) -> 'User':
        query = "INSERT INTO users (username, firstname, lastname, email, pw) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, last_seen"
        password = User.hash_password(password)
        data = await (await PostgresDB.get_instance()).fetch_one(query, username, firstname, lastname, email, password)
        return User(data[0], username, firstname, lastname, email, password, data[1], data[2]) if data else None
    
    async def update(self):
        query = "UPDATE users SET username = $1, email = $2, pw = $3 WHERE id = $4"
        await (await PostgresDB.get_instance()).execute(query, self.username, self.email, self._password, self.id)

    async def delete(self):
        query = "DELETE FROM users WHERE id = $1"
        await (await PostgresDB.get_instance()).execute(query, self.id)

    @staticmethod
    def hash_password(password: str)-> str:
        return pwd_context.hash(password)
    
    def validate_password(self, password: str) -> bool:
        return pwd_context.verify(password, self._password)
    
    def login(self, username: str, password: str) -> Optional['User']:
        user = User.get_by_username(username)
        if isinstance(user, User) and user.validate_password(password):
            return user
        return None
    
router = APIRouter()

def validate_username(value: str) -> str:
        if not re.fullmatch(r"^[a-zA-Z0-9_]{3,20}$", value):
            raise ValueError("Username must be 3-20 characters and contain only letters, numbers, and underscores.")
        return value
        
def validate_firstname(value: str) -> str:
        value = value.strip().capitalize()
        if not re.fullmatch(r"^[A-Za-z]{2,30}$", value):
            raise ValueError("Firstname must be 2-30 characters and contain only letters.")
        return value

def validate_lastname(value: str) -> str:
        value = value.strip().capitalize()
        if not re.fullmatch(r"^[A-Za-z]{2,30}$", value):
            raise ValueError("Lastname must be 2-30 characters and contain only letters.")
        return value

def validate_email(value: str) -> str:   
        if len(value) > 255:
            raise ValueError("Email must be at most 255 characters long.")       
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.fullmatch(email_regex, value):
            raise ValueError("Invalid email format.")
        return value

def validate_password(value: str) -> str:
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
async def create_user(username: str, firstname: str, lastname: str, email: str, password: str):
    try:
        
        username = validate_username(username)
        firstname = validate_firstname(firstname)
        lastname = validate_lastname(lastname)
        email = validate_email(email)
        password = validate_password(password)

        check_username = await User.get_by_username(username)
        if check_username:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        check_email = await User.get_by_email(email)
        if check_email:
            raise HTTPException(status_code=400, detail="Email already exists")
        
        user = await User.create(username, firstname, lastname, email, password)
        return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "created_at": user.created_at, "last_seen": user.last_seen}
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@router.patch("/user/{user_id}")
async def update_user(user_id: int, username: Optional[str] = None, firstname: Optional[str] = None, lastname: Optional[str] = None, email: Optional[str] = None, password: Optional[str] = None):
    user = await User.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if username:
        username = validate_username(username)
        check_username = await User.get_by_username(username)
        if check_username:
            raise HTTPException(status_code=400, detail="Username already exists")
        user.username = username
        
    if firstname:
        user.firstname = validate_firstname(firstname)
        
    if lastname:
        user.lastname = validate_lastname(lastname)
        
    if email:
        email = validate_email(email)
        check_email = await User.get_by_email(email)
        if check_email:
            raise HTTPException(status_code=400, detail="Email already exists")
        user.email = email
        
    if password:
        user.password = validate_password(password)
        
    await user.update()
    return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "created_at": user.created_at, "last_seen": user.last_seen}
    
@router.get("/users")
async def get_users():
    users = await (await PostgresDB.get_instance()).fetch("SELECT id, username, firstname, lastname, email, created_at, last_seen FROM users")
    return users

@router.get("/user/{user_id}")
async def get_user(user_id: int):
    user = await User.get_by_id(user_id)
    return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "email": user.email, "created_at": user.created_at, "last_seen": user.last_seen}