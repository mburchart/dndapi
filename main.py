from fastapi import FastAPI
from user import router as user_router
from postgres import PostgresDB

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

app.include_router(user_router, tags=["Users"])