@echo off
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File ".\run_usb_autofetch.ps1"
