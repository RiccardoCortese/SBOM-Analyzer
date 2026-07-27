# main.py
import uvicorn
from config import app
from routers.routes import router as sbom_router

# Includiamo le rotte definite nel router
app.include_router(sbom_router)

if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)