param (
    [switch]$nomem,  # 是否跳過記憶體分析
    [string]$out     # 日誌文件輸出位置
)

# 定義日誌文件路徑
if ($out) {
    $logFile = "$out\System_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
} else {
    $logFile = "$PSScriptRoot\System_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}

# 函數：將輸出寫入日誌文件
function Write-Log {
    param ([string]$message)
    Add-Content -Path $logFile -Value $message
    Add-Content -Path $logFile -Value "`n"
}

# 開始執行
Write-Log "===== 系統資訊與補丁 ====="
systeminfo | Out-String | Write-Log

Write-Log "`n===== 主機名稱與IP地址 ====="
hostname | Out-String | Write-Log
ipconfig /all | Out-String | Write-Log

Write-Log "`n===== 用戶與群組資訊 ====="
net user | Out-String | Write-Log
net localgroup | Out-String | Write-Log

Write-Log "`n===== 登入歷史 ====="
Get-EventLog -LogName Security -InstanceId 4624 | Select-Object -First 20 | Out-String | Write-Log

Write-Log "`n===== 查看當前進程 ====="
tasklist /v | Out-String | Write-Log

Write-Log "`n===== 檢查啟動項目 ====="
Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | Out-String | Write-Log
Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | Out-String | Write-Log

Write-Log "`n===== 啟動的服務 ====="
net start | Out-String | Write-Log

Write-Log "`n===== 當前連線與端口 ====="
netstat -anob | Out-String | Write-Log

Write-Log "`n===== 路由與ARP表 ====="
route print | Out-String | Write-Log
arp -a | Out-String | Write-Log

Write-Log "`n===== DNS快取 ====="
ipconfig /displaydns | Out-String | Write-Log

Write-Log "`n===== 檢查可疑檔案 ====="
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Out-String | Write-Log

Write-Log "`n===== 系統日誌 ====="
Get-EventLog -LogName System -Newest 50 | Out-String | Write-Log
Get-EventLog -LogName Application -Newest 50 | Out-String | Write-Log

Write-Log "`n===== ProcessName, PATH, HASH ====="
Get-Process | Select-Object Id, ProcessName, Path, @{Name='Hash'; Expression={if ($_.Path) { (Get-FileHash -Path $_.Path -Algorithm SHA256).Hash } else {'Path not found'}}} | Out-String | Write-Log

# 檢查是否需要執行記憶體分析
if (-not $nomem) {
    Write-Log "`n===== 記憶體分析 ====="
    $tempDir = "$env:TEMP\sysTools"
    mkdir $tempDir -Force | Out-Null
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Procdump.zip' -OutFile "$tempDir\pd.zip"
    Expand-Archive "$tempDir\pd.zip" $tempDir -Force
    $procdumpPath = "$tempDir\procdump.exe"
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputFile = "$tempDir\$env:COMPUTERNAME`_$timestamp.dmp"

    if (Test-Path $procdumpPath) {
        Start-Process -FilePath $procdumpPath -ArgumentList "-ma $PID $outputFile" -Wait -NoNewWindow
        if (Test-Path $outputFile) {
            $hash = (Get-FileHash -Path $outputFile -Algorithm SHA256).Hash
            Write-Log "Dump file created. Hash: $hash"
        } else {
            Write-Log "Dump file not created"
        }
    } else {
        Write-Log "Procdump.exe not found"
    }
} else {
    Write-Log "`n===== 記憶體分析已跳過 ====="
}

Write-Log "`n===== 腳本執行完成 ====="
Write-Host "審計完成，日誌文件已保存到: $logFile"
