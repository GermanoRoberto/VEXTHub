@echo off
color 0d
title VextHub Agent Installer

echo ========================================================
echo  __     __        _     _   _ _   _ ____  
echo  \ \   / /____  _^| ^|_  ^| ^| ^| ^| ^| ^| ^| __ ) 
echo   \ \ / / _ \ \/ / __^| ^| ^|_^| ^| ^| ^| ^|  _ \ 
echo    \ V /  __/^>  ^<^| ^|_  ^|  _  ^| ^|_^| ^| ^|_) ^|
echo     \_/ \___/_/\_\\__^| ^|_^| ^|_^|\___/^|____/ 
echo.
echo           VextHub Defensive Agent
echo ========================================================
echo.

:: Verifica se está rodando como Administrador
net session >nul 2>&1
if %errorLevel% == 0 goto :run

echo [!] Solicitando privilegios de Administrador...
powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File ".\install.ps1"
pause
