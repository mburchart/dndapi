from typing import Optional
from datetime import datetime
from postgres import PostgresDB
import hashlib
import os

class User:
    
    def __init__(self, id: int, username: str, email: str, password: str, salt: str, created_at: datetime):
        self.id = id
        self.username = username
        self.email = email
        self._password = password
        self._salt = salt
        self.created_at = created_at

    @property
    def password(self):
        return self._password
    
    @property
    def salt(self):
        return self._salt
    
    @password.setter
    def password(self, password: str):
        self._salt = User.generate_salt()
        self._password = User.hash_password(password, self._salt)

    @staticmethod
    async def get_by_email(email: str) -> Optional['User']:
        query = "SELECT id, username, email, pw, salt, created_at FROM users WHERE email = $1"
        data = PostgresDB.fetch_one(query, email)
        return User(*data) if data else None
    
    @staticmethod
    async def get_by_id(id: int) -> Optional['User']:
        query = "SELECT id, username, email, pw, salt, created_at FROM users WHERE id = $1"
        data = PostgresDB.fetch_one(query, id)
        return User(*data) if data else None
    
    @staticmethod
    async def get_by_username(username: str) -> Optional['User']:
        query = "SELECT id, username, email, pw, salt, created_at FROM users WHERE username = $1"
        data = PostgresDB.fetch_one(query, username)
        return User(*data) if data else None
    
    @staticmethod
    async def create(username: str, email: str, password: str) -> 'User':
        query = "INSERT INTO users (username, email, pw, salt) VALUES ($1, $2, $3, $4) RETURNING id, created_at"
        salt = User.generate_salt()
        password = User.hash_password(password, salt)
        data = PostgresDB.fetch_one(query, username, email, password, salt)
        return User(data[0], username, email, password, salt, data[1]) if data else None
    
    async def update(self):
        query = "UPDATE users SET username = $1, email = $2, pw = $3, salt = $4 WHERE id = $5"
        await PostgresDB.execute(query, self.username, self.email, self._password, self._salt, self.id)

    async def delete(self):
        query = "DELETE FROM users WHERE id = $1"
        await PostgresDB.execute(query, self.id)

    @staticmethod
    def generate_salt()-> str:
        return hashlib.sha512(os.urandom(16)).hexdigest()

    @staticmethod
    def hash_password(password: str, salt: str)-> str:
        return hashlib.sha512((password + salt).encode()).hexdigest()