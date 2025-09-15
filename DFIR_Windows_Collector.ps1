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
    [switch]$OnlyMem,
    
    [Parameter(Mandatory = $false)]
    [switch]$DetailedOutput
)

# Global variables for tracking
$Global:CollectionStartTime = Get-Date
$Global:CollectionStages = @()
$Global:TotalStages = 0
$Global:CurrentStage = 0

# Function to display stage information
function Write-StageInfo {
    param(
        [string]$StageName,
        [string]$Description,
        [string]$Status = "STARTING"
    )
    
    $Global:CurrentStage++
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $color = switch ($Status) {
        "STARTING" { "Yellow" }
        "COMPLETED" { "Green" }
        "FAILED" { "Red" }
        "WARNING" { "Magenta" }
        default { "White" }
    }
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "[$timestamp] STAGE $Global:CurrentStage/$Global:TotalStages: $StageName" -ForegroundColor $color
    Write-Host "Description: $Description" -ForegroundColor Gray
    Write-Host "Status: $Status" -ForegroundColor $color
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    # Track stage information
    $Global:CollectionStages += [PSCustomObject]@{
        StageNumber = $Global:CurrentStage
        StageName = $StageName
        Description = $Description
        Status = $Status
        StartTime = Get-Date
        EndTime = if ($Status -eq "COMPLETED" -or $Status -eq "FAILED") { Get-Date } else { $null }
        Duration = if ($Status -eq "COMPLETED" -or $Status -eq "FAILED") { (Get-Date) - $Global:CollectionStartTime } else { $null }
    }
}

# Function to display progress bar
function Write-ProgressBar {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$Current,
        [int]$Total,
        [int]$PercentComplete
    )
    
    $ProgressBar = "[" + ("#" * [math]::Floor($PercentComplete / 2)) + ("-" * (50 - [math]::Floor($PercentComplete / 2))) + "]"
    Write-Progress -Activity $Activity -Status $Status -CurrentOperation $ProgressBar -PercentComplete $PercentComplete
}

# Function to perform memory dump collection
function Invoke-MemoryDump {
    param(
        [string]$OutputPath,
        [string]$Hostname,
        [string]$TimeStamp
    )

    Write-StageInfo -StageName "Memory Analysis" -Description "Creating full memory dump using Procdump" -Status "STARTING"
    
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
            Write-Host "  [*] Found local Procdump, using existing file..." -ForegroundColor Green
            $ProcdumpZip = Join-Path $TempDir "procdump.zip"
            Copy-Item -Path $LocalProcdumpZip -Destination $ProcdumpZip -Force
            $ProcdumpDir = Join-Path $TempDir "procdump"
            Expand-Archive -Path $ProcdumpZip -DestinationPath $ProcdumpDir -Force
        } else {
            Write-Host "  [*] Local Procdump not found, downloading from internet..." -ForegroundColor Yellow
            $ProcdumpUrl = "https://download.sysinternals.com/files/Procdump.zip"
            $ProcdumpZip = Join-Path $TempDir "procdump.zip"
            $ProcdumpDir = Join-Path $TempDir "procdump"
            
            Write-ProgressBar -Activity "Downloading Procdump" -Status "Downloading from Microsoft Sysinternals" -Current 0 -Total 100 -PercentComplete 0
            Invoke-WebRequest -Uri $ProcdumpUrl -OutFile $ProcdumpZip -UseBasicParsing
            Write-ProgressBar -Activity "Downloading Procdump" -Status "Download completed" -Current 100 -Total 100 -PercentComplete 100
            
            # Save downloaded file locally for future use
            $LocalToolsDir = Join-Path $ScriptDir "DFIR_tools"
            New-Item -ItemType Directory -Path $LocalToolsDir -Force | Out-Null
            Copy-Item -Path $ProcdumpZip -Destination $LocalProcdumpZip -Force
            Write-Host "  [+] Procdump saved locally for future use: $LocalProcdumpZip" -ForegroundColor Green
            
            Expand-Archive -Path $ProcdumpZip -DestinationPath $ProcdumpDir -Force
        }
        
        $ProcdumpExe = Join-Path $ProcdumpDir "procdump.exe"
        
        if (Test-Path $ProcdumpExe) {
            Write-Host "  [*] Creating memory dump..." -ForegroundColor Yellow
            $DumpFile = Join-Path $MemoryDir "${Hostname}_${TimeStamp}.dmp"
            
            # Create full memory dump with progress indication
            Write-ProgressBar -Activity "Memory Dump" -Status "Creating full memory dump (this may take several minutes)" -Current 0 -Total 100 -PercentComplete 0
            $Process = Start-Process -FilePath $ProcdumpExe -ArgumentList "-ma", $PID, $DumpFile -Wait -PassThru -NoNewWindow
            
            if ($Process.ExitCode -eq 0 -and (Test-Path $DumpFile)) {
                # Calculate hash of dump file
                Write-Host "  [*] Calculating dump file hash..." -ForegroundColor Yellow
                $DumpHash = Get-FileHash -Path $DumpFile -Algorithm SHA256
                $DumpInfo = [PSCustomObject]@{
                    DumpFile = $DumpFile
                    FileSize = (Get-Item $DumpFile).Length
                    SHA256 = $DumpHash.Hash
                    Created = (Get-Item $DumpFile).CreationTime
                }
                $DumpInfo | Export-Csv "$MemoryDir\dump_info.csv" -NoTypeInformation
                Write-Host "  [+] Memory dump created: $DumpFile" -ForegroundColor Green
                Write-Host "  [+] Dump size: $([math]::Round((Get-Item $DumpFile).Length / 1MB, 2)) MB" -ForegroundColor Green
                Write-Host "  [+] Dump hash: $($DumpHash.Hash)" -ForegroundColor Green
                Write-StageInfo -StageName "Memory Analysis" -Description "Creating full memory dump using Procdump" -Status "COMPLETED"
                return $true
            } else {
                Write-Host "  [-] Failed to create memory dump. Exit code: $($Process.ExitCode)" -ForegroundColor Red
                "Memory dump failed. Exit code: $($Process.ExitCode)" | Out-File "$MemoryDir\dump_error.txt"
                Write-StageInfo -StageName "Memory Analysis" -Description "Creating full memory dump using Procdump" -Status "FAILED"
                return $false
            }
        } else {
            Write-Host "  [-] Procdump.exe not found after download" -ForegroundColor Red
            "Procdump.exe not found" | Out-File "$MemoryDir\dump_error.txt"
            Write-StageInfo -StageName "Memory Analysis" -Description "Creating full memory dump using Procdump" -Status "FAILED"
            return $false
        }
        
        # Cleanup temp files
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "  [-] Memory analysis failed: $($_.Exception.Message)" -ForegroundColor Red
        "Memory analysis failed: $($_.Exception.Message)" | Out-File "$MemoryDir\memory_error.txt"
        Write-StageInfo -StageName "Memory Analysis" -Description "Creating full memory dump using Procdump" -Status "FAILED"
        return $false
    }
}

# Calculate total stages based on parameters
$Global:TotalStages = 10  # Base stages
if ($DumpMem -or $OnlyMem) { $Global:TotalStages++ }
if ($OnlyMem) { $Global:TotalStages = 1 }

# Prepare output folder
$OutputPath = (Get-Location).Path
$Hostname = $env:COMPUTERNAME
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CaseFolder = "${EvidenceID}_${Hostname}_${TimeStamp}"
$FullCasePath = Join-Path $OutputPath $CaseFolder
New-Item -ItemType Directory -Path $FullCasePath -Force | Out-Null

Write-Host ""
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "DFIR WINDOWS EVIDENCE COLLECTOR - ENHANCED EDITION" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Evidence Collection Configuration:" -ForegroundColor Yellow
Write-Host "  - Evidence ID: $EvidenceID" -ForegroundColor White
Write-Host "  - Hostname: $Hostname" -ForegroundColor White
Write-Host "  - Output Path: $FullCasePath" -ForegroundColor White
Write-Host "  - Memory Dump: $(if ($DumpMem -or $OnlyMem) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
Write-Host "  - Collection Mode: $(if ($OnlyMem) { 'Memory Only' } else { 'Full Collection' })" -ForegroundColor White
Write-Host "  - Detailed Output: $(if ($DetailedOutput) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
Write-Host ""

# Check if only memory collection is requested
if ($OnlyMem) {
    Write-Host "[*] Starting memory-only collection mode..." -ForegroundColor Yellow
    $MemorySuccess = Invoke-MemoryDump -OutputPath $FullCasePath -Hostname $Hostname -TimeStamp $TimeStamp
    
    if ($MemorySuccess) {
        Write-Host "[+] Memory collection completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "[-] Memory collection failed!" -ForegroundColor Red
        exit 1
    }
    
    # Compress only memory data
    Write-Host "[*] Compressing memory dump..." -ForegroundColor Yellow
    $ZipFile = "$FullCasePath.zip"
    Compress-Archive -Path $FullCasePath -DestinationPath $ZipFile -Force
    Write-Host "[+] Memory dump saved: $ZipFile" -ForegroundColor Green
    exit 0
}

Write-Host "[*] Starting full evidence collection for $Hostname..." -ForegroundColor Yellow

# === 1. System Info ===
Write-StageInfo -StageName "System Information" -Description "Collecting system information, installed programs, and OS details" -Status "STARTING"

try {
    Write-Host "  [*] Collecting system information..." -ForegroundColor Yellow
    systeminfo > "$FullCasePath\systeminfo.txt"
    
    Write-Host "  [*] Collecting OS version details..." -ForegroundColor Yellow
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' | Out-File "$FullCasePath\os_version.txt"

    Write-Host "  [*] Collecting installed programs..." -ForegroundColor Yellow
    $installedPrograms = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $installedPrograms | Out-File "$FullCasePath\installed_programs.txt"
    
    Write-Host "  [+] System information collected successfully" -ForegroundColor Green
    Write-StageInfo -StageName "System Information" -Description "Collecting system information, installed programs, and OS details" -Status "COMPLETED"
} catch {
    Write-Host "  [-] System information collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "System Information" -Description "Collecting system information, installed programs, and OS details" -Status "FAILED"
}

# === 2. Network Info ===
Write-StageInfo -StageName "Network Information" -Description "Collecting network configuration, connections, and DNS cache" -Status "STARTING"

try {
    Write-Host "  [*] Collecting network configuration..." -ForegroundColor Yellow
    ipconfig /all > "$FullCasePath\network_config.txt"
    
    Write-Host "  [*] Collecting DNS cache..." -ForegroundColor Yellow
    ipconfig /displaydns > "$FullCasePath\dns_cache.txt"
    
    Write-Host "  [*] Collecting network connections..." -ForegroundColor Yellow
    netstat -anob > "$FullCasePath\netstat_anob.txt"
    Get-NetTCPConnection | Out-File "$FullCasePath\Get-NetTCPConnection.txt"
    
    Write-Host "  [*] Collecting ARP table..." -ForegroundColor Yellow
    arp -a > "$FullCasePath\arp_table.txt"
    
    Write-Host "  [+] Network information collected successfully" -ForegroundColor Green
    Write-StageInfo -StageName "Network Information" -Description "Collecting network configuration, connections, and DNS cache" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Network information collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Network Information" -Description "Collecting network configuration, connections, and DNS cache" -Status "FAILED"
}

# === 3. User / Logon Info ===
Write-StageInfo -StageName "User & Logon Information" -Description "Collecting user sessions, login history, and authentication data" -Status "STARTING"

try {
    Write-Host "  [*] Collecting logged on users..." -ForegroundColor Yellow
    query user > "$FullCasePath\loggedon_users.txt"

    Write-Host "  [*] Collecting login history..." -ForegroundColor Yellow
    try {
        Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 -ErrorAction SilentlyContinue | 
            Select-Object TimeGenerated, EventID, Message | 
            Out-File "$FullCasePath\login_history.txt"
        Write-Host "  [+] Login history collected successfully" -ForegroundColor Green
    } catch {
        Write-Host "  [-] Failed to collect login history: $($_.Exception.Message)" -ForegroundColor Red
        "Login history collection failed: $($_.Exception.Message)" | Out-File "$FullCasePath\login_history_error.txt"
    }
    
    Write-Host "  [+] User and logon information collected successfully" -ForegroundColor Green
    Write-StageInfo -StageName "User & Logon Information" -Description "Collecting user sessions, login history, and authentication data" -Status "COMPLETED"
} catch {
    Write-Host "  [-] User information collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "User & Logon Information" -Description "Collecting user sessions, login history, and authentication data" -Status "FAILED"
}

# === 4. Processes & Services ===
Write-StageInfo -StageName "Process & Service Information" -Description "Collecting running processes, services, and process hashes" -Status "STARTING"

try {
    Write-Host "  [*] Collecting process list..." -ForegroundColor Yellow
    tasklist /v > "$FullCasePath\tasklist.txt"
    Get-Process | Sort-Object CPU -Descending | Out-File "$FullCasePath\Get-Process.txt"
    
    Write-Host "  [*] Collecting service information..." -ForegroundColor Yellow
    Get-Service | Out-File "$FullCasePath\services.txt"

    Write-Host "  [*] Collecting process hashes..." -ForegroundColor Yellow
    $ProcessHashes = @()
    $ProcessErrors = @()
    $processes = Get-Process | Where-Object { $_.Path }
    $totalProcesses = $processes.Count
    $currentProcess = 0

    foreach ($process in $processes) {
        $currentProcess++
        $percentComplete = [math]::Round(($currentProcess / $totalProcesses) * 100, 2)
        Write-ProgressBar -Activity "Process Hash Collection" -Status "Processing $($process.ProcessName)" -Current $currentProcess -Total $totalProcesses -PercentComplete $percentComplete
        
        try {
            $hash = Get-FileHash -Path $process.Path -Algorithm SHA256 -ErrorAction Stop
            $ProcessHashes += [PSCustomObject]@{
                ProcessID = $process.Id
                ProcessName = $process.ProcessName
                Path = $process.Path
                SHA256 = $hash.Hash
            }
        } catch {
            $ProcessErrors += [PSCustomObject]@{
                ProcessID = $process.Id
                ProcessName = $process.ProcessName
                Path = $process.Path
                Error = $_.Exception.Message
            }
        }
    }

    $ProcessHashes | Export-Csv "$FullCasePath\process_hashes.csv" -NoTypeInformation
    if ($ProcessErrors.Count -gt 0) {
        $ProcessErrors | Export-Csv "$FullCasePath\process_hash_errors.csv" -NoTypeInformation
    }
    Write-Host "  [+] Process hashes collected: $($ProcessHashes.Count) successful, $($ProcessErrors.Count) errors" -ForegroundColor Green
    
    Write-Host "  [+] Process and service information collected successfully" -ForegroundColor Green
    Write-StageInfo -StageName "Process & Service Information" -Description "Collecting running processes, services, and process hashes" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Process information collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Process & Service Information" -Description "Collecting running processes, services, and process hashes" -Status "FAILED"
}

# === 5. Persistence (Startup & Scheduled Tasks) ===
Write-StageInfo -StageName "Persistence Analysis" -Description "Collecting startup programs, scheduled tasks, and persistence mechanisms" -Status "STARTING"

try {
    Write-Host "  [*] Collecting scheduled tasks..." -ForegroundColor Yellow
    schtasks /query /fo LIST /v > "$FullCasePath\scheduled_tasks.txt"
    
    Write-Host "  [*] Collecting startup programs..." -ForegroundColor Yellow
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
        Out-File "$FullCasePath\startup_hklm.txt"
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
        Out-File "$FullCasePath\startup_hkcu.txt"
    
    Write-Host "  [+] Persistence information collected successfully" -ForegroundColor Green
    Write-StageInfo -StageName "Persistence Analysis" -Description "Collecting startup programs, scheduled tasks, and persistence mechanisms" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Persistence information collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Persistence Analysis" -Description "Collecting startup programs, scheduled tasks, and persistence mechanisms" -Status "FAILED"
}

# === 6. Event Logs ===
Write-StageInfo -StageName "Event Log Collection" -Description "Exporting Security, System, and Application event logs" -Status "STARTING"

try {
    Write-Host "  [*] Exporting Security event log..." -ForegroundColor Yellow
    wevtutil epl Security "$FullCasePath\Security.evtx"
    
    Write-Host "  [*] Exporting System event log..." -ForegroundColor Yellow
    wevtutil epl System "$FullCasePath\System.evtx"
    
    Write-Host "  [*] Exporting Application event log..." -ForegroundColor Yellow
    wevtutil epl Application "$FullCasePath\Application.evtx"
    
    Write-Host "  [+] Event logs exported successfully" -ForegroundColor Green
    Write-StageInfo -StageName "Event Log Collection" -Description "Exporting Security, System, and Application event logs" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Event log collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Event Log Collection" -Description "Exporting Security, System, and Application event logs" -Status "FAILED"
}

# === 7. Registry Hives (Full Export) ===
Write-StageInfo -StageName "Registry Collection" -Description "Exporting critical registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER)" -Status "STARTING"

try {
    $registryHives = @(
        @{Name="SYSTEM"; Path="HKLM\SYSTEM"; File="SYSTEM.hiv"},
        @{Name="SOFTWARE"; Path="HKLM\SOFTWARE"; File="SOFTWARE.hiv"},
        @{Name="SAM"; Path="HKLM\SAM"; File="SAM.hiv"},
        @{Name="SECURITY"; Path="HKLM\SECURITY"; File="SECURITY.hiv"},
        @{Name="NTUSER"; Path="HKCU"; File="NTUSER.DAT"}
    )
    
    $currentHive = 0
    foreach ($hive in $registryHives) {
        $currentHive++
        $percentComplete = [math]::Round(($currentHive / $registryHives.Count) * 100, 2)
        Write-Host "  [*] Exporting $($hive.Name) registry hive..." -ForegroundColor Yellow
        Write-ProgressBar -Activity "Registry Collection" -Status "Exporting $($hive.Name)" -Current $currentHive -Total $registryHives.Count -PercentComplete $percentComplete
        
        reg save $hive.Path "$FullCasePath\$($hive.File)" /y
    }
    
    Write-Host "  [+] Registry hives exported successfully" -ForegroundColor Green
    Write-StageInfo -StageName "Registry Collection" -Description "Exporting critical registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER)" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Registry collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Registry Collection" -Description "Exporting critical registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER)" -Status "FAILED"
}

# === 8. Shortcuts (no recursion into .lnk targets) ===
Write-StageInfo -StageName "Shortcut Collection" -Description "Collecting shortcuts from Recent, Desktop, and Start Menu" -Status "STARTING"

try {
    $ShortcutPaths = @(
        @{Source="$env:APPDATA\Microsoft\Windows\Recent"; Dest="Recent"},
        @{Source="$env:APPDATA\Microsoft\Office\Recent"; Dest="Office_Recent"},
        @{Source="$env:USERPROFILE\Links"; Dest="Links"},
        @{Source="$env:USERPROFILE\Desktop"; Dest="Desktop"},
        @{Source="$env:APPDATA\Microsoft\Windows\Start Menu\Programs"; Dest="Start_Menu_Programs"}
    )
    
    $currentPath = 0
    foreach ($pathInfo in $ShortcutPaths) {
        $currentPath++
        $percentComplete = [math]::Round(($currentPath / $ShortcutPaths.Count) * 100, 2)
        Write-ProgressBar -Activity "Shortcut Collection" -Status "Processing $($pathInfo.Source)" -Current $currentPath -Total $ShortcutPaths.Count -PercentComplete $percentComplete
        
        if (Test-Path $pathInfo.Source) {
            Write-Host "  [*] Collecting shortcuts from: $($pathInfo.Source)" -ForegroundColor Yellow
            $targetPath = Join-Path "$FullCasePath\Shortcuts" $pathInfo.Dest
            
            # Create target directory
            New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            
            # Function to safely copy shortcuts without recursion
            function Copy-ShortcutsSafely {
                param(
                    [string]$SourcePath,
                    [string]$TargetPath,
                    [int]$MaxDepth = 2,
                    [int]$CurrentDepth = 0
                )
                
                if ($CurrentDepth -ge $MaxDepth) {
                    Write-Host "      [!] Max depth reached, stopping recursion" -ForegroundColor Yellow
                    return
                }
                
                try {
                    Get-ChildItem -Path $SourcePath -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            if ($_.PSIsContainer) {
                                # For directories, create subdirectory and copy only .lnk files
                                $subTargetPath = Join-Path $TargetPath $_.Name
                                New-Item -ItemType Directory -Path $subTargetPath -Force | Out-Null
                                
                                # Only copy .lnk files from this directory level
                                Get-ChildItem -Path $_.FullName -Filter "*.lnk" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                                    try {
                                        Copy-Item -Path $_.FullName -Destination $subTargetPath -Force -ErrorAction SilentlyContinue
                                    } catch {
                                        Write-Host "        [-] Skipped .lnk: $($_.Name)" -ForegroundColor DarkYellow
                                    }
                                }
                                
                                # Recursively process subdirectories (with depth limit)
                                Copy-ShortcutsSafely -SourcePath $_.FullName -TargetPath $subTargetPath -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
                            } else {
                                # For files, only copy .lnk files
                                if ($_.Extension -eq ".lnk") {
                                    Copy-Item -Path $_.FullName -Destination $TargetPath -Force -ErrorAction SilentlyContinue
                                }
                            }
                        } catch {
                            Write-Host "      [-] Skipped: $($_.Name)" -ForegroundColor DarkYellow
                        }
                    }
                } catch {
                    Write-Host "    [-] Error processing directory: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            # Use the safe copy function with depth limit
            Copy-ShortcutsSafely -SourcePath $pathInfo.Source -TargetPath $targetPath -MaxDepth 2
        }
    }
    
    Write-Host "  [+] Shortcuts collected successfully" -ForegroundColor Green
    Write-StageInfo -StageName "Shortcut Collection" -Description "Collecting shortcuts from Recent, Desktop, and Start Menu" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Shortcut collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Shortcut Collection" -Description "Collecting shortcuts from Recent, Desktop, and Start Menu" -Status "FAILED"
}

# === 9. Browser Artifacts ===
Write-StageInfo -StageName "Browser Artifacts" -Description "Collecting browser data from Chrome, Edge, Firefox, Opera, and Brave" -Status "STARTING"

try {
    $BrowserPaths = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"},
        @{Name="Edge"; Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"},
        @{Name="Firefox"; Path="$env:APPDATA\Mozilla\Firefox\Profiles"},
        @{Name="Opera"; Path="$env:APPDATA\Opera Software\Opera Stable"},
        @{Name="Brave"; Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"},
        @{Name="IE/Edge Legacy"; Path="$env:LOCALAPPDATA\Microsoft\Windows\WebCache"}
    )
    
    $currentBrowser = 0
    foreach ($browser in $BrowserPaths) {
        $currentBrowser++
        $percentComplete = [math]::Round(($currentBrowser / $BrowserPaths.Count) * 100, 2)
        Write-ProgressBar -Activity "Browser Collection" -Status "Processing $($browser.Name)" -Current $currentBrowser -Total $BrowserPaths.Count -PercentComplete $percentComplete
        
        if (Test-Path $browser.Path) {
            Write-Host "  [*] Collecting $($browser.Name) data..." -ForegroundColor Yellow
            Copy-Item -Path $browser.Path -Destination "$FullCasePath\Browsers" -Recurse -Force -ErrorAction SilentlyContinue -Container
        }
    }
    
    Write-Host "  [+] Browser artifacts collected successfully" -ForegroundColor Green
    Write-StageInfo -StageName "Browser Artifacts" -Description "Collecting browser data from Chrome, Edge, Firefox, Opera, and Brave" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Browser collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Browser Artifacts" -Description "Collecting browser data from Chrome, Edge, Firefox, Opera, and Brave" -Status "FAILED"
}

# === 10. Modified Files in Last 7 Days (including hidden) ===
Write-StageInfo -StageName "Modified Files Analysis" -Description "Scanning for files modified in the last 7 days" -Status "STARTING"

try {
    Write-Host "  [*] Scanning for modified files (this may take several minutes)..." -ForegroundColor Yellow
    Write-ProgressBar -Activity "Modified Files Scan" -Status "Scanning C:\ drive for recent modifications" -Current 0 -Total 100 -PercentComplete 0
    
    $modifiedFiles = Get-ChildItem -Path C:\ -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
        Select-Object FullName, LastWriteTime, Length, Attributes |
        Sort-Object LastWriteTime -Descending
    
    $modifiedFiles | Export-Csv "$FullCasePath\modified_files_last7days.csv" -NoTypeInformation
    
    Write-Host "  [+] Found $($modifiedFiles.Count) files modified in the last 7 days" -ForegroundColor Green
    Write-StageInfo -StageName "Modified Files Analysis" -Description "Scanning for files modified in the last 7 days" -Status "COMPLETED"
} catch {
    Write-Host "  [-] Modified files collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "Modified Files Analysis" -Description "Scanning for files modified in the last 7 days" -Status "FAILED"
}

# === 11. System32 Hashes (Safe Mode - Skip Locked Files) ===
Write-StageInfo -StageName "System32 Hash Collection" -Description "Calculating SHA256 hashes for System32 files" -Status "STARTING"

try {
    Write-Host "  [*] Calculating System32 file hashes (this may take several minutes)..." -ForegroundColor Yellow
    
    $HashResults = @()
    $ErrorFiles = @()
    $system32Files = Get-ChildItem "$env:windir\System32" -File -Recurse -Force -ErrorAction SilentlyContinue
    $totalFiles = $system32Files.Count
    $currentFile = 0

    foreach ($file in $system32Files) {
        $currentFile++
        $percentComplete = [math]::Round(($currentFile / $totalFiles) * 100, 2)
        Write-ProgressBar -Activity "System32 Hash Collection" -Status "Processing $($file.Name)" -Current $currentFile -Total $totalFiles -PercentComplete $percentComplete
        
        try {
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop
            $HashResults += $hash
        }
        catch {
            $ErrorFiles += $file.FullName
        }
    }

    $HashResults | Export-Csv "$FullCasePath\system32_hashes.csv" -NoTypeInformation
    $ErrorFiles | Out-File "$FullCasePath\system32_unreadable_files.txt"
    
    Write-Host "  [+] System32 hashes calculated: $($HashResults.Count) successful, $($ErrorFiles.Count) errors" -ForegroundColor Green
    Write-StageInfo -StageName "System32 Hash Collection" -Description "Calculating SHA256 hashes for System32 files" -Status "COMPLETED"
} catch {
    Write-Host "  [-] System32 hash collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StageInfo -StageName "System32 Hash Collection" -Description "Calculating SHA256 hashes for System32 files" -Status "FAILED"
}

# === 12. Memory Analysis (Optional) ===
if ($DumpMem) {
    $MemorySuccess = Invoke-MemoryDump -OutputPath $FullCasePath -Hostname $Hostname -TimeStamp $TimeStamp
    if ($MemorySuccess) {
        Write-Host "[+] Memory analysis completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "[-] Memory analysis failed!" -ForegroundColor Red
    }
} else {
    Write-Host "[*] Memory analysis skipped (use -DumpMem parameter to enable)" -ForegroundColor Yellow
}

# === Safe Compress & Cleanup ===
Write-Host ""
Write-Host "[*] Preparing final compression..." -ForegroundColor Yellow
Write-StageInfo -StageName "Final Compression" -Description "Compressing all collected evidence into ZIP archive" -Status "STARTING"

$TempPath = Join-Path $OutputPath "${CaseFolder}_Temp"
New-Item -ItemType Directory -Path $TempPath -Force | Out-Null

# Copy all collected files without following junctions
Write-Host "  [*] Copying files for compression..." -ForegroundColor Yellow
Get-ChildItem -Path $FullCasePath -Force -Recurse -Attributes !ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object {
    $targetFile = $_.FullName.Replace($FullCasePath, $TempPath)
    $targetDir = Split-Path $targetFile -Parent
    if (!(Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
    try { Copy-Item -LiteralPath $_.FullName -Destination $targetFile -Force -ErrorAction Stop } catch {}
}

# Fix timestamps that break ZIP (< 1980)
Write-Host "  [*] Fixing file timestamps..." -ForegroundColor Yellow
Get-ChildItem -Path $TempPath -Recurse -Force | ForEach-Object {
    try {
        if ($_.LastWriteTime -lt (Get-Date -Year 1980 -Month 1 -Day 1)) {
            $_.LastWriteTime = (Get-Date -Year 1980 -Month 1 -Day 1)
        }
    } catch {}
}

# Compress
Write-Host "  [*] Creating ZIP archive..." -ForegroundColor Yellow
$ZipFile = "$FullCasePath.zip"
Compress-Archive -Path $TempPath -DestinationPath $ZipFile -Force

# Cleanup
Write-Host "  [*] Cleaning up temporary files..." -ForegroundColor Yellow
if (Test-Path $TempPath) { Remove-Item $TempPath -Recurse -Force }
if (Test-Path $FullCasePath) { Remove-Item $FullCasePath -Recurse -Force }

Write-StageInfo -StageName "Final Compression" -Description "Compressing all collected evidence into ZIP archive" -Status "COMPLETED"

Write-Host ""
Write-Host ("=" * 80) -ForegroundColor Green
Write-Host "EVIDENCE COLLECTION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host ("=" * 80) -ForegroundColor Green
Write-Host "Output file: $ZipFile" -ForegroundColor White
Write-Host "File size: $([math]::Round((Get-Item $ZipFile).Length / 1MB, 2)) MB" -ForegroundColor White
Write-Host ("=" * 80) -ForegroundColor Green
