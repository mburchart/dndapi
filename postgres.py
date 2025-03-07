import asyncpg
import os

class PostgresDB:

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, "_config"):  # Damit `__init__` nur einmal ausgeführt wird
            self._config = {
                "host": os.getenv("DB_HOST", "localhost"),
                "port": os.getenv("DB_PORT", "5432"),
                "user": os.getenv("DB_USER", "postgres"),
                "password": os.getenv("DB_PASSWORD", "password"),
                "database": os.getenv("DB_NAME", "mydatabase")
            }
        if not hasattr(self, "_pool"):
            self._pool = None
    
    async def connect(self):
        if self._pool is None:
            self._pool = await asyncpg.create_pool(**self._config, min_size=1, max_size=10)
    
    async def disconnect(self):
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def fetch(self, query: str, *args):
        async with self._pool.acquire() as connection:
            return await connection.fetch(query, *args)
        
    async def fetch_one(self, query: str, *args):
        async with self._pool.acquire() as connection:
            return await connection.fetchrow(query, *args)
        
    async def execute(self, query: str, *args):
        async with self._pool.acquire() as connection:
            return await connection.execute(query, *args)
        
    @staticmethod
    def get_instance():
        if PostgresDB._instance is None:
            PostgresDB._instance = PostgresDB()
        return PostgresDB._instance