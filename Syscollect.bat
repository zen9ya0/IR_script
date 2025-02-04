@echo off
:: Check administrative privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrative privileges...
) else (
    echo This script requires administrative privileges.
    echo Please run this script as Administrator.
    pause
    exit /b 1
)

setlocal enabledelayedexpansion
chcp 65001 >nul

echo ========================================
echo System Environment Check
echo ========================================

:: Check OS Type
for /f "tokens=2 delims==" %%a in ('wmic os get Caption /value') do (
    set "OS_TYPE=%%a"
)
echo OS Type: %OS_TYPE%

:: Check if Server Version
echo %OS_TYPE% | findstr /i "server" >nul
if %errorLevel% equ 0 (
    echo System Type: Windows Server
) else (
    echo System Type: Windows PC
)

:: Check System Architecture
for /f "tokens=2 delims==" %%a in ('wmic os get OSArchitecture /value') do (
    set "OS_ARCH=%%a"
)
echo System Architecture: %OS_ARCH%

echo ========================================
echo Start Collecting System Information
echo ========================================

:: Create temporary directory (clean if exists)
set tempDir=%temp%\audit
if exist "%tempDir%" (
    rd /s /q "%tempDir%"
)
mkdir "%tempDir%"
if exist "%tempDir%" (
    echo Temporary directory created: %tempDir%
) else (
    echo Failed to create temporary directory: %tempDir%
    exit /b 1
)

:: Get hostname
set "hostName="
for /f "tokens=*" %%i in ('hostname') do set "hostName=%%i"

:: System Information and Patches
echo [Running] Collecting system information and patches...
systeminfo > "%tempDir%\systeminfo.txt" 2>nul
echo [Done] System information and patches collected

:: Hostname and IP
echo [Running] Collecting hostname and IP information...
hostname > "%tempDir%\hostname.txt"
ipconfig /all > "%tempDir%\ipconfig.txt"
echo [Done] Hostname and IP information collected

:: User Accounts and Groups
echo [Running] Collecting user accounts and groups...
net user > "%tempDir%\net_user.txt" 2>nul
net localgroup > "%tempDir%\net_localgroup.txt" 2>nul
echo [Done] User accounts and groups collected

:: Login History (modified for compatibility)
echo [Running] Collecting login history...
powershell -Command "$ErrorActionPreference = 'SilentlyContinue'; Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 | Select-Object TimeGenerated,EventID,Message | Format-List" > "%tempDir%\login_history.txt" 2>nul
echo [Done] Login history collected

:: Current Processes
echo [Running] Collecting current processes...
tasklist /v > "%tempDir%\tasklist.txt" 2>nul
echo [Done] Current processes collected

:: Startup Items (modified for compatibility)
echo [Running] Checking startup items...
powershell -Command "$ErrorActionPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List" > "%tempDir%\startup_hklm.txt" 2>nul
powershell -Command "$ErrorActionPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List" > "%tempDir%\startup_hkcu.txt" 2>nul
echo [Done] Startup items checked

:: Running Services
echo [Running] Collecting running services...
net start > "%tempDir%\net_start.txt" 2>nul
echo [Done] Running services collected

:: Current Connections and Ports
echo [Running] Collecting network connections...
netstat -ano > "%tempDir%\netstat.txt" 2>nul
echo [Done] Network connections collected

:: Routes and ARP Table
echo [Running] Collecting routes and ARP table...
route print > "%tempDir%\route.txt" 2>nul
arp -a > "%tempDir%\arp.txt" 2>nul
echo [Done] Routes and ARP table collected

:: DNS Cache
echo [Running] Collecting DNS cache...
ipconfig /displaydns > "%tempDir%\dns_cache.txt" 2>nul
echo [Done] DNS cache collected

:: Suspicious Files (modified for compatibility)
echo [Running] Checking suspicious files...
powershell -Command "$ErrorActionPreference = 'SilentlyContinue'; Get-ChildItem -Path C:\ -Recurse | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName,LastWriteTime,Length | Format-List" > "%tempDir%\suspicious_files.txt" 2>nul
echo [Done] Suspicious files checked

:: System Logs (modified for compatibility)
echo [Running] Collecting system logs...
powershell -Command "$ErrorActionPreference = 'SilentlyContinue'; Get-EventLog -LogName System -Newest 50 | Format-List" > "%tempDir%\system_log.txt" 2>nul
powershell -Command "$ErrorActionPreference = 'SilentlyContinue'; Get-EventLog -LogName Application -Newest 50 | Format-List" > "%tempDir%\application_log.txt" 2>nul
echo [Done] System logs collected

:: ProcessName, PATH, HASH (modified for compatibility)
echo [Running] Collecting process information and hashes...
powershell -Command "$ErrorActionPreference = 'SilentlyContinue'; $processes = Get-Process | Where-Object { $_.Path }; foreach ($p in $processes) { try { $hash = (Get-FileHash -Path $p.Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $hash = 'Unable to calculate hash' }; Write-Output \"Process ID: $($p.Id)`nProcess Name: $($p.ProcessName)`nPath: $($p.Path)`nSHA256: $hash`n-------------------\" }" > "%tempDir%\process_hash.txt" 2>nul
echo [Done] Process information and hashes collected

:: Generate JSON Report
echo [Running] Generating JSON report...
set "currentDate=%date%"
set "currentTime=%time%"

:: Ensure hostname is set
if not defined hostName (
    for /f "tokens=*" %%i in ('hostname') do set "hostName=%%i"
)

(
    echo {
    echo    "hostname": "%hostName%",
    echo    "timestamp": "%currentDate% %currentTime%",
) > "%~dp0%hostName%_%currentDate:/=-%_%currentTime::=-%.json"

:: Process all text files into JSON
set firstFile=true
for %%f in ("%tempDir%\*.txt") do (
    if not "!firstFile!"=="true" echo    , >> "%~dp0%hostName%_%currentDate:/=-%_%currentTime::=-%.json"
    set firstFile=false
    
    set "fileName=%%~nf"
    echo    "!fileName!": [ >> "%~dp0%hostName%_%currentDate:/=-%_%currentTime::=-%.json"
    
    set firstLine=true
    for /f "usebackq tokens=*" %%l in ("%%f") do (
        if not "!firstLine!"=="true" echo        , >> "%~dp0%hostName%_%currentDate:/=-%_%currentTime::=-%.json"
        set firstLine=false
        echo        "%%l" >> "%~dp0%hostName%_%currentDate:/=-%_%currentTime::=-%.json"
    )
    echo    ] >> "%~dp0%hostName%_%currentDate:/=-%_%currentTime::=-%.json"
)

(
    echo }
) >> "%~dp0%hostName%_%currentDate:/=-%_%currentTime::=-%.json"
echo [Done] JSON report generated

:: Clean up temporary directory
echo [Running] Cleaning up temporary files...
rd /s /q "%tempDir%"
echo [Done] Cleanup completed

echo ========================================
echo All Tasks Completed
echo ========================================

endlocal