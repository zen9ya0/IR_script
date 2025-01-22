@echo off
setlocal EnableDelayedExpansion

:: Get hostname
for /f "tokens=*" %%a in ('hostname') do set "hostName=%%a"

:: Create timestamp
set "timestamp=%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "timestamp=!timestamp: =0!"

:: Create output directory with hostname and timestamp
set "outputDir=%hostName%_SystemAnalysis_%timestamp%"
mkdir %outputDir%

:: Start JSON structure
echo { > "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   "timestamp": "%timestamp%", >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: System Information
echo   "systemInfo": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
systeminfo > "%outputDir%\temp.txt"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent.Substring(1, $jsonContent.Length-2)" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   }, >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Hostname and IP
echo   "networkInfo": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
hostname > "%outputDir%\temp.txt"
echo     "hostname": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

ipconfig /all > "%outputDir%\temp.txt"
echo     "ipConfig": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   }, >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Users and Groups
echo   "userGroups": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
net user > "%outputDir%\temp.txt"
echo     "users": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

net localgroup > "%outputDir%\temp.txt"
echo     "localGroups": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   }, >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Login History
echo   "loginHistory": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "Get-EventLog -LogName Security -InstanceId 4624 | Select-Object -First 20 | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Current Processes
echo   "processes": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
tasklist /v /fo csv | powershell -Command "$input | ConvertFrom-Csv | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Startup Items
echo   "startupItems": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     "HKLM": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     "HKCU": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   }, >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Services
echo   "services": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
net start | powershell -Command "$input | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Network Connections
echo   "networkConnections": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
netstat -anob > "%outputDir%\temp.txt"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Route and ARP
echo   "routeAndArp": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
route print > "%outputDir%\temp.txt"
echo     "routeTable": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

arp -a > "%outputDir%\temp.txt"
echo     "arpTable": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   }, >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: DNS Cache
echo   "dnsCache": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
ipconfig /displaydns > "%outputDir%\temp.txt"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Recent Files
echo   "recentFiles": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName, LastWriteTime, Length | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: System and Application Logs
echo   "eventLogs": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     "system": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "Get-EventLog -LogName System -Newest 50 | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     , >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo     "application": >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "Get-EventLog -LogName Application -Newest 50 | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   } >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Close JSON structure
echo } >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: Clean up temporary files
del "%outputDir%\temp.txt"

echo Analysis complete. Results saved in %outputDir%\%hostName%_%timestamp%_analysis.json
