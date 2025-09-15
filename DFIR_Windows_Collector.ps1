<#
.SYNOPSIS
    Windows DFIR Evidence Collection Script - Enhanced Edition
.DESCRIPTION
    Collects volatile and non-volatile forensic evidence from Windows host.
    Enhanced with login history, process hashes, and flexible memory analysis options.
    Output saved in current working directory with filename: <EvidenceID>_<Hostname>_<YYYYMMDD_HHMMSS>.zip
    
.PARAMETER EvidenceID
    Unique identifier for the evidence collection case
    
.PARAMETER DumpMem
    Optional switch to enable memory dump collection in addition to standard evidence collection
    
.PARAMETER OnlyMem
    Switch to collect only memory dump without other forensic evidence
    
.EXAMPLE
    .\DFIR_Windows_Collector.ps1 -EvidenceID "CASE001"
    Collects standard forensic evidence without memory dump
    
.EXAMPLE
    .\DFIR_Windows_Collector.ps1 -EvidenceID "CASE001" -DumpMem
    Collects forensic evidence including full memory dump
    
.EXAMPLE
    .\DFIR_Windows_Collector.ps1 -EvidenceID "CASE001" -OnlyMem
    Collects only memory dump without other evidence
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceID,
    
    [Parameter(Mandatory = $false)]
    [switch]$DumpMem,
    
    [Parameter(Mandatory = $false)]
    [switch]$OnlyMem
)

# Function to perform memory dump collection
function Invoke-MemoryDump {
    param(
        [string]$OutputPath,
        [string]$Hostname,
        [string]$TimeStamp
    )
    
    Write-Host "[*] Starting memory analysis..."
    $MemoryDir = Join-Path $OutputPath "Memory"
    New-Item -ItemType Directory -Path $MemoryDir -Force | Out-Null
    
    try {
        # Check for local Procdump first
        $ScriptDir = Split-Path -Parent $MyInvocation.PSCommandPath
        $LocalProcdumpZip = Join-Path $ScriptDir "DFIR_tools\procdump.zip"
        
        # Prepare temp directory
        $TempDir = "$env:TEMP\DFIR_Tools"
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
        
        if (Test-Path $LocalProcdumpZip) {
            Write-Host "[*] Found local Procdump, using existing file..."
            $ProcdumpZip = Join-Path $TempDir "procdump.zip"
            Copy-Item -Path $LocalProcdumpZip -Destination $ProcdumpZip -Force
            $ProcdumpDir = Join-Path $TempDir "procdump"
            Expand-Archive -Path $ProcdumpZip -DestinationPath $ProcdumpDir -Force
        } else {
            Write-Host "[*] Local Procdump not found, downloading from internet..."
            $ProcdumpUrl = "https://download.sysinternals.com/files/Procdump.zip"
            $ProcdumpZip = Join-Path $TempDir "procdump.zip"
            $ProcdumpDir = Join-Path $TempDir "procdump"
            
            Invoke-WebRequest -Uri $ProcdumpUrl -OutFile $ProcdumpZip -UseBasicParsing
            
            # Save downloaded file locally for future use
            $LocalToolsDir = Join-Path $ScriptDir "DFIR_tools"
            New-Item -ItemType Directory -Path $LocalToolsDir -Force | Out-Null
            Copy-Item -Path $ProcdumpZip -Destination $LocalProcdumpZip -Force
            Write-Host "[+] Procdump saved locally for future use: $LocalProcdumpZip"
            
            Expand-Archive -Path $ProcdumpZip -DestinationPath $ProcdumpDir -Force
        }
        
        $ProcdumpExe = Join-Path $ProcdumpDir "procdump.exe"
        
        if (Test-Path $ProcdumpExe) {
            Write-Host "[*] Creating memory dump..."
            $DumpFile = Join-Path $MemoryDir "${Hostname}_${TimeStamp}.dmp"
            
            # Create full memory dump
            $Process = Start-Process -FilePath $ProcdumpExe -ArgumentList "-ma", $PID, $DumpFile -Wait -PassThru -NoNewWindow
            
            if ($Process.ExitCode -eq 0 -and (Test-Path $DumpFile)) {
                # Calculate hash of dump file
                $DumpHash = Get-FileHash -Path $DumpFile -Algorithm SHA256
                $DumpInfo = [PSCustomObject]@{
                    DumpFile = $DumpFile
                    FileSize = (Get-Item $DumpFile).Length
                    SHA256 = $DumpHash.Hash
                    Created = (Get-Item $DumpFile).CreationTime
                }
                $DumpInfo | Export-Csv "$MemoryDir\dump_info.csv" -NoTypeInformation
                Write-Host "[+] Memory dump created: $DumpFile"
                Write-Host "[+] Dump size: $([math]::Round((Get-Item $DumpFile).Length / 1MB, 2)) MB"
                Write-Host "[+] Dump hash: $($DumpHash.Hash)"
                return $true
            } else {
                Write-Host "[-] Failed to create memory dump. Exit code: $($Process.ExitCode)"
                "Memory dump failed. Exit code: $($Process.ExitCode)" | Out-File "$MemoryDir\dump_error.txt"
                return $false
            }
        } else {
            Write-Host "[-] Procdump.exe not found after download"
            "Procdump.exe not found" | Out-File "$MemoryDir\dump_error.txt"
            return $false
        }
        
        # Cleanup temp files
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "[-] Memory analysis failed: $($_.Exception.Message)"
        "Memory analysis failed: $($_.Exception.Message)" | Out-File "$MemoryDir\memory_error.txt"
        return $false
    }
}

# Prepare output folder
$OutputPath = (Get-Location).Path
$Hostname = $env:COMPUTERNAME
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CaseFolder = "${EvidenceID}_${Hostname}_${TimeStamp}"
$FullCasePath = Join-Path $OutputPath $CaseFolder
New-Item -ItemType Directory -Path $FullCasePath -Force | Out-Null

# Check if only memory collection is requested
if ($OnlyMem) {
    Write-Host "[*] Memory-only collection mode for $Hostname..."
    $MemorySuccess = Invoke-MemoryDump -OutputPath $FullCasePath -Hostname $Hostname -TimeStamp $TimeStamp
    
    if ($MemorySuccess) {
        Write-Host "[+] Memory collection completed successfully!"
    } else {
        Write-Host "[-] Memory collection failed!"
        exit 1
    }
    
    # Compress only memory data
    $ZipFile = "$FullCasePath.zip"
    Compress-Archive -Path $FullCasePath -DestinationPath $ZipFile -Force
    Write-Host "[+] Memory dump saved: $ZipFile"
    exit 0
}

Write-Host "[*] Collecting DFIR evidence for $Hostname..."

# === 1. System Info ===
systeminfo > "$FullCasePath\systeminfo.txt"
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' | Out-File "$FullCasePath\os_version.txt"

# Installed programs
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Out-File "$FullCasePath\installed_programs.txt"

# === 2. Network Info ===
ipconfig /all > "$FullCasePath\network_config.txt"
ipconfig /displaydns > "$FullCasePath\dns_cache.txt"
netstat -anob > "$FullCasePath\netstat_anob.txt"
Get-NetTCPConnection | Out-File "$FullCasePath\Get-NetTCPConnection.txt"
arp -a > "$FullCasePath\arp_table.txt"

# === 3. User / Logon Info ===
query user > "$FullCasePath\loggedon_users.txt"

# Login History
Write-Host "[*] Collecting login history..."
try {
    Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 -ErrorAction SilentlyContinue | 
        Select-Object TimeGenerated, EventID, Message | 
        Out-File "$FullCasePath\login_history.txt"
    Write-Host "[+] Login history collected"
} catch {
    Write-Host "[-] Failed to collect login history: $($_.Exception.Message)"
    "Login history collection failed: $($_.Exception.Message)" | Out-File "$FullCasePath\login_history_error.txt"
}

# === 4. Processes & Services ===
tasklist /v > "$FullCasePath\tasklist.txt"
Get-Process | Sort-Object CPU -Descending | Out-File "$FullCasePath\Get-Process.txt"
Get-Service | Out-File "$FullCasePath\services.txt"

# Process Hashes
Write-Host "[*] Collecting process hashes..."
$ProcessHashes = @()
$ProcessErrors = @()

Get-Process | Where-Object { $_.Path } | ForEach-Object {
    try {
        $hash = Get-FileHash -Path $_.Path -Algorithm SHA256 -ErrorAction Stop
        $ProcessHashes += [PSCustomObject]@{
            ProcessID = $_.Id
            ProcessName = $_.ProcessName
            Path = $_.Path
            SHA256 = $hash.Hash
        }
    } catch {
        $ProcessErrors += [PSCustomObject]@{
            ProcessID = $_.Id
            ProcessName = $_.ProcessName
            Path = $_.Path
            Error = $_.Exception.Message
        }
    }
}

$ProcessHashes | Export-Csv "$FullCasePath\process_hashes.csv" -NoTypeInformation
if ($ProcessErrors.Count -gt 0) {
    $ProcessErrors | Export-Csv "$FullCasePath\process_hash_errors.csv" -NoTypeInformation
}
Write-Host "[+] Process hashes collected: $($ProcessHashes.Count) successful, $($ProcessErrors.Count) errors"

# === 5. Persistence (Startup & Scheduled Tasks) ===
schtasks /query /fo LIST /v > "$FullCasePath\scheduled_tasks.txt"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Out-File "$FullCasePath\startup_hklm.txt"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Out-File "$FullCasePath\startup_hkcu.txt"

# === 6. Event Logs ===
wevtutil epl Security "$FullCasePath\Security.evtx"
wevtutil epl System "$FullCasePath\System.evtx"
wevtutil epl Application "$FullCasePath\Application.evtx"

# === 7. Registry Hives (Full Export) ===
reg save HKLM\SYSTEM "$FullCasePath\SYSTEM.hiv" /y
reg save HKLM\SOFTWARE "$FullCasePath\SOFTWARE.hiv" /y
reg save HKLM\SAM "$FullCasePath\SAM.hiv" /y
reg save HKLM\SECURITY "$FullCasePath\SECURITY.hiv" /y
reg save HKCU "$FullCasePath\NTUSER.DAT" /y

# === 8. Shortcuts (no recursion into .lnk targets) ===
$ShortcutPaths = @(
    "$env:APPDATA\Microsoft\Windows\Recent",
    "$env:APPDATA\Microsoft\Office\Recent",
    "$env:USERPROFILE\Links",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
)
foreach ($path in $ShortcutPaths) {
    if (Test-Path $path) {
        Copy-Item -Path $path -Destination "$FullCasePath\Shortcuts" -Recurse -Force -ErrorAction SilentlyContinue -Container
    }
}

# === 9. Browser Artifacts ===
$BrowserPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default",
    "$env:APPDATA\Mozilla\Firefox\Profiles",
    "$env:APPDATA\Opera Software\Opera Stable",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default",
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"  # IE / Legacy Edge
)
foreach ($path in $BrowserPaths) {
    if (Test-Path $path) {
        Copy-Item -Path $path -Destination "$FullCasePath\Browsers" -Recurse -Force -ErrorAction SilentlyContinue -Container
    }
}

# === 10. Modified Files in Last 7 Days (including hidden) ===
Get-ChildItem -Path C:\ -Recurse -Force -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
    Select-Object FullName, LastWriteTime, Length, Attributes |
    Sort-Object LastWriteTime -Descending |
    Export-Csv "$FullCasePath\modified_files_last7days.csv" -NoTypeInformation

# === 11. System32 Hashes (Safe Mode - Skip Locked Files) ===
$HashResults = @()
$ErrorFiles = @()

Get-ChildItem "$env:windir\System32" -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction Stop
        $HashResults += $hash
    }
    catch {
        $ErrorFiles += $_.FullName
    }
}

$HashResults | Export-Csv "$FullCasePath\system32_hashes.csv" -NoTypeInformation
$ErrorFiles | Out-File "$FullCasePath\system32_unreadable_files.txt"

# === 12. Memory Analysis (Optional) ===
if ($DumpMem) {
    $MemorySuccess = Invoke-MemoryDump -OutputPath $FullCasePath -Hostname $Hostname -TimeStamp $TimeStamp
    if ($MemorySuccess) {
        Write-Host "[+] Memory analysis completed successfully!"
    } else {
        Write-Host "[-] Memory analysis failed!"
    }
} else {
    Write-Host "[*] Memory analysis skipped (use -DumpMem parameter to enable)"
}

# === Safe Compress & Cleanup ===
$TempPath = Join-Path $OutputPath "${CaseFolder}_Temp"
New-Item -ItemType Directory -Path $TempPath -Force | Out-Null

# Copy all collected files without following junctions
Get-ChildItem -Path $FullCasePath -Force -Recurse -Attributes !ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object {
    $targetFile = $_.FullName.Replace($FullCasePath, $TempPath)
    $targetDir = Split-Path $targetFile -Parent
    if (!(Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
    try { Copy-Item -LiteralPath $_.FullName -Destination $targetFile -Force -ErrorAction Stop } catch {}
}

# Fix timestamps that break ZIP (< 1980)
Get-ChildItem -Path $TempPath -Recurse -Force | ForEach-Object {
    try {
        if ($_.LastWriteTime -lt (Get-Date -Year 1980 -Month 1 -Day 1)) {
            $_.LastWriteTime = (Get-Date -Year 1980 -Month 1 -Day 1)
        }
    } catch {}
}

# Compress
$ZipFile = "$FullCasePath.zip"
Compress-Archive -Path $TempPath -DestinationPath $ZipFile -Force

# Cleanup
if (Test-Path $TempPath) { Remove-Item $TempPath -Recurse -Force }
if (Test-Path $FullCasePath) { Remove-Item $FullCasePath -Recurse -Force }

Write-Host "[+] Evidence collection completed!"
Write-Host "[+] Output file: $ZipFile"
