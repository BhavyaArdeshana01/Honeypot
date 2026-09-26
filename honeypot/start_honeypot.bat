@echo off
title PHANTOM GRID - Honeypot System
color 0B

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║          P H A N T O M   G R I D  v2.0                      ║
echo  ║          Advanced Honeypot Security System                   ║
echo  ╠══════════════════════════════════════════════════════════════╣
echo  ║  Protocols: HTTP FTP SSH SNMP SMB Telnet SMTP               ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

:: Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

:: Check if running as administrator (required for ports below 1024)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Not running as Administrator!
    echo [WARNING] Ports below 1024 ^(21,22,23,25,80,161,445^) require Admin rights.
    echo [WARNING] Right-click this .bat file and "Run as administrator"
    echo.
    echo Press any key to continue anyway ^(some protocols may fail^)...
    pause >nul
)

:: Install requirements
echo [*] Checking dependencies...
pip install flask flask-socketio flask-login werkzeug paramiko eventlet >nul 2>&1
echo [*] Dependencies OK

:: Create logs directory
if not exist "logs" mkdir logs

echo.
echo [*] Starting PHANTOM GRID...
echo [*] Web Dashboard: http://localhost:5000
echo [*] First run: Create admin account at http://localhost:5000/setup
echo.
echo [*] Press Ctrl+C to stop all services
echo.

:: Start the honeypot
python app.py

pause
