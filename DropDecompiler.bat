@echo off
rem Double-click to start DropDecompiler, or drag files onto this icon to decompile them right away.
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js is required: https://nodejs.org & pause & exit /b 1)
if not exist node_modules (
  echo First run: installing dependencies...
  call npm install || (pause & exit /b 1)
)
node launch.js --detach %*
