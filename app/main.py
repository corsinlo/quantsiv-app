"""
Quantsiv MVP - Main FastAPI Application
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Quantsiv", description="Quantum Risk Management Platform")

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

@app.get("/")
async def root():
    return {"message": "Quantsiv MVP - Quantum Risk Management Platform"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}