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

:: Memory Analysis Section
echo   "memoryAnalysis": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
powershell -Command "$t=\"$env:TEMP\sysTools\"; mkdir $t -Force; Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Procdump.zip' -OutFile \"$t\pd.zip\"; Expand-Archive \"$t\pd.zip\" $t -Force; $pd=\"$t\procdump.exe\"; $ts='%timestamp%'; $o=\"%outputDir%\%hostName%_memory_$ts.dmp\"; if (Test-Path $pd) { Start-Process -FilePath $pd -ArgumentList \"-ma $PID $o\" -Wait -NoNewWindow; if (Test-Path $o) { $hash = (Get-FileHash -Path $o -Algorithm SHA256).Hash; @{ 'dumpFile' = $o; 'hash' = $hash } | ConvertTo-Json } else { @{ 'error' = 'Dump file not created' } | ConvertTo-Json } } else { @{ 'error' = 'Procdump.exe not found' } | ConvertTo-Json }" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   }, >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: System Information
echo   "systemInfo": { >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
systeminfo > "%outputDir%\temp.txt"
powershell -Command "$content = Get-Content '%outputDir%\temp.txt' -Raw; $jsonContent = $content | ConvertTo-Json; $jsonContent.Substring(1, $jsonContent.Length-2)" >> "%outputDir%\%hostName%_%timestamp%_analysis.json"
echo   }, >> "%outputDir%\%hostName%_%timestamp%_analysis.json"

:: [Rest of the original script remains unchanged...]

:: Clean up temporary files
del "%outputDir%\temp.txt"
powershell -Command "Remove-Item \"$env:TEMP\sysTools\" -Recurse -Force -ErrorAction SilentlyContinue"

echo Analysis complete. Results saved in %outputDir%\%hostName%_%timestamp%_analysis.json
