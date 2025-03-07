import asyncpg

class PostgresDB:
    
    def __init__(self, host: str, port: str, user: str, password: str, database: str):
        self._config = {
            "host": host,
            "port": port,
            "user": user,
            "database": database,
            "password": password
        }
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