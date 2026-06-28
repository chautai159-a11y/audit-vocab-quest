@echo off
chcp 65001 >nul
title Audit Vocab Quest

echo.
echo  ================================================
echo    AUDIT VOCAB QUEST - Server Launcher
echo  ================================================
echo.

where node >nul 2>nul
if %errorlevel% neq 0 (
  echo  [LOI] Chua cai dat Node.js!
  echo  Vui long tai tai: https://nodejs.org
  pause
  exit /b
)

if not exist "node_modules" (
  echo  Dang cai dat dependencies lan dau...
  echo.
  npm install
  echo.
)

echo  App dang chay tai: http://localhost:3000
echo  Nhan Ctrl+C de dung server.
echo.

node server.js
pause
