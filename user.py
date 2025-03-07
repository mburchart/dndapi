from typing import Optional
from datetime import datetime
from postgres import PostgresDB
import hashlib
import os
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User:    
    
    def __init__(self, id: int, username: str, email: str, password: str, created_at: datetime):
        self.id = id
        self.username = username
        self.email = email
        self._password = password
        self.created_at = created_at

    @property
    def password(self):
        return self._password 
    
    @password.setter
    def password(self, password: str):        
        self._password = User.hash_password(password)

    @staticmethod
    async def get_by_email(email: str) -> Optional['User']:
        query = "SELECT id, username, email, pw, created_at FROM users WHERE email = $1"
        data = PostgresDB.get_instance().fetch_one(query, email)
        return User(*data) if data else None
    
    @staticmethod
    async def get_by_id(id: int) -> Optional['User']:
        query = "SELECT id, username, email, pw, created_at FROM users WHERE id = $1"
        data = PostgresDB.get_instance().fetch_one(query, id)
        return User(*data) if data else None
    
    @staticmethod
    async def get_by_username(username: str) -> Optional['User']:
        query = "SELECT id, username, email, pw, created_at FROM users WHERE username = $1"
        data = PostgresDB.get_instance().fetch_one(query, username)
        return User(*data) if data else None
    
    @staticmethod
    async def create(username: str, email: str, password: str) -> 'User':
        query = "INSERT INTO users (username, email, pw) VALUES ($1, $2, $3) RETURNING id, created_at"
        password = User.hash_password(password)
        data = PostgresDB.get_instance().fetch_one(query, username, email, password)
        return User(data[0], username, email, password, data[1]) if data else None
    
    async def update(self):
        query = "UPDATE users SET username = $1, email = $2, pw = $3 WHERE id = $4"
        await PostgresDB.get_instance().execute(query, self.username, self.email, self._password, self.id)

    async def delete(self):
        query = "DELETE FROM users WHERE id = $1"
        await PostgresDB.get_instance().execute(query, self.id)

    @staticmethod
    def hash_password(password: str)-> str:
        return pwd_context.hash(password)
    
    def validate_password(self, password: str) -> bool:
        return pwd_context.verify(password, self._password)