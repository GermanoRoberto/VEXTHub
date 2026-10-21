# VextHub Development Launcher
# Starts both Next.js frontend and FastAPI backend

Write-Host "--- Iniciando VextHub Dev Environment ---" -ForegroundColor Cyan

# 1. Start FastAPI Backend in a new window
Write-Host "[1/2] Iniciando Python Backend (FastAPI)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'services/api'; pip install -r requirements.txt; uvicorn app.main:app --reload --port 8000"

# 2. Start Next.js Frontend
Write-Host "[2/2] Iniciando Next.js Frontend..." -ForegroundColor Yellow
npm run dev
