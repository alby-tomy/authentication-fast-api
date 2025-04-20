from fastapi import FastAPI
from routers.admin_router import router as admin_router
from routers.user_router import router as user_router
from database import engine, Base

app = FastAPI()

# Include routers
app.include_router(admin_router, prefix="/admin", tags=["admin"])
app.include_router(user_router, prefix="/user", tags=["user"])

# Database initialization
@app.on_event("startup")
async def startup_event():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.on_event("shutdown")
async def shutdown_event():
    await engine.dispose()
