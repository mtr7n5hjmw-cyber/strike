@echo off
setlocal

where cl.exe >nul 2>nul
if errorlevel 1 (
    echo Run this from a Visual Studio Developer Command Prompt.
    exit /b 1
)

cl /std:c++17 /EHsc /DUNICODE /D_UNICODE Hwid.cpp StrikeMenuHelper.cpp /Fe:StrikeMenuHelper.exe advapi32.lib bcrypt.lib winhttp.lib ws2_32.lib user32.lib
if errorlevel 1 exit /b 1

echo Built StrikeMenuHelper.exe