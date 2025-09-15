# DFIR Windows Collector - Enhanced Edition

A comprehensive Windows Digital Forensics and Incident Response (DFIR) evidence collection script with enhanced memory analysis capabilities.

## 🚀 Features

### Core Evidence Collection
- **System Information**: Complete system details, OS version, and installed programs
- **Network Information**: Network configuration, connections, DNS cache, and ARP tables
- **User & Authentication**: Logged-on users and login history
- **Processes & Services**: Running processes with detailed information and SHA256 hashes
- **Persistence Mechanisms**: Startup items, scheduled tasks, and registry run keys
- **Event Logs**: Complete Security, System, and Application event logs (.evtx format)
- **Registry Hives**: Full backup of all major registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)
- **Browser Artifacts**: Data from Chrome, Edge, Firefox, Opera, Brave, and IE/Edge WebCache
- **File System**: Recently modified files and System32 directory hashes
- **Shortcuts**: Collection of .lnk files from various system locations

### Memory Analysis (Optional)
- **Flexible Memory Collection**: Three modes for different scenarios
- **Procdump Integration**: Automatic download and local caching of Procdump tool
- **Hash Verification**: SHA256 hashing of memory dump files
- **Smart Caching**: Reuses previously downloaded Procdump for faster execution

## 📋 Requirements

- Windows PowerShell 5.0 or later
- Administrative privileges (required for registry access and memory dumps)
- Internet connection (only for initial Procdump download)

## 🛠️ Installation

1. Download the `DFIR_Windows_Collector.ps1` script
2. Place it in your desired directory
3. Ensure you have administrative privileges

## 📖 Usage

### Basic Syntax
```powershell
.\DFIR_Windows_Collector.ps1 -EvidenceID <CaseID> [-DumpMem] [-OnlyMem]
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-EvidenceID` | String | Yes | Unique identifier for the evidence collection case |
| `-DumpMem` | Switch | No | Enable memory dump collection in addition to standard evidence |
| `-OnlyMem` | Switch | No | Collect only memory dump without other forensic evidence |

### Usage Examples

#### Standard Evidence Collection
```powershell
.\DFIR_Windows_Collector.ps1 -EvidenceID "CASE001"
```
Collects all standard forensic evidence without memory analysis.

#### Complete Evidence Collection with Memory
```powershell
.\DFIR_Windows_Collector.ps1 -EvidenceID "CASE001" -DumpMem
```
Collects all forensic evidence including full memory dump.

#### Memory-Only Collection
```powershell
.\DFIR_Windows_Collector.ps1 -EvidenceID "CASE001" -OnlyMem
```
Collects only memory dump for quick memory analysis.

## 📁 Output Structure

### File Naming Convention
```
{EvidenceID}_{Hostname}_{YYYYMMDD_HHMMSS}.zip
```

### Directory Structure
```
{EvidenceID}_{Hostname}_{YYYYMMDD_HHMMSS}/
├── systeminfo.txt                    # System information
├── os_version.txt                    # OS version details
├── installed_programs.txt            # Installed software list
├── network_config.txt                # Network configuration
├── dns_cache.txt                     # DNS cache
├── netstat_anob.txt                  # Network connections
├── Get-NetTCPConnection.txt          # PowerShell network connections
├── arp_table.txt                     # ARP table
├── loggedon_users.txt                # Currently logged users
├── login_history.txt                 # Login history (Security events)
├── tasklist.txt                      # Process list
├── Get-Process.txt                   # PowerShell process list
├── process_hashes.csv                # Process SHA256 hashes
├── process_hash_errors.csv           # Process hash errors
├── services.txt                      # Service list
├── scheduled_tasks.txt               # Scheduled tasks
├── startup_hklm.txt                  # HKLM startup items
├── startup_hkcu.txt                  # HKCU startup items
├── Security.evtx                     # Security event log
├── System.evtx                       # System event log
├── Application.evtx                  # Application event log
├── SYSTEM.hiv                        # Registry SYSTEM hive
├── SOFTWARE.hiv                      # Registry SOFTWARE hive
├── SAM.hiv                          # Registry SAM hive
├── SECURITY.hiv                     # Registry SECURITY hive
├── NTUSER.DAT                       # Current user registry
├── Shortcuts/                        # Shortcut files
├── Browsers/                         # Browser artifacts
├── modified_files_last7days.csv     # Recently modified files
├── system32_hashes.csv              # System32 file hashes
├── system32_unreadable_files.txt    # Unreadable files
└── Memory/                          # Memory analysis (if enabled)
    ├── {Hostname}_{Timestamp}.dmp   # Memory dump file
    └── dump_info.csv                # Dump file information
```

## 🔧 Memory Analysis Details

### Procdump Tool Management
- **Local Priority**: Script first checks for `DFIR_tools\procdump.zip` in the script directory
- **Automatic Download**: Downloads Procdump from Sysinternals if not found locally
- **Local Caching**: Saves downloaded Procdump for future use
- **Version**: Uses the latest version from Microsoft Sysinternals

### Memory Dump Information
- **Format**: Full memory dump (.dmp)
- **Hash**: SHA256 hash of the dump file
- **Metadata**: File size, creation time, and hash stored in CSV format
- **Compression**: Included in the final ZIP archive

## ⚡ Performance Considerations

### Execution Time
- **Standard Mode**: 5-15 minutes (depending on system size)
- **Memory Mode**: Additional 10-30 minutes (depending on RAM size)
- **Memory-Only Mode**: 10-30 minutes (memory dump only)

### Storage Requirements
- **Standard Evidence**: 50-500 MB (depending on system)
- **Memory Dump**: 1-8 GB (depending on installed RAM)
- **Compression**: Reduces total size by 20-50%

## 🛡️ Security Features

### Hash Verification
- All collected files include SHA256 hashes
- Process executables are hashed for integrity verification
- Memory dump files include hash verification
- System32 files are hashed for baseline comparison

### Safe Collection
- Junction point avoidance to prevent infinite loops
- Error handling for locked files
- Timestamp normalization for ZIP compatibility
- Automatic cleanup of temporary files

## 🚨 Troubleshooting

### Common Issues

#### Permission Errors
```
Error: Access denied
Solution: Run PowerShell as Administrator
```

#### Memory Dump Failures
```
Error: Procdump.exe not found
Solution: Check internet connection for initial download
```

#### Registry Access Issues
```
Error: Cannot access registry hive
Solution: Ensure administrative privileges
```

### Log Files
- All errors are logged to respective error files
- Process hash errors: `process_hash_errors.csv`
- System32 errors: `system32_unreadable_files.txt`
- Memory analysis errors: `Memory\memory_error.txt`

## 📊 Output Analysis

### Key Files for Analysis
1. **`process_hashes.csv`**: Analyze running processes and their integrity
2. **`login_history.txt`**: Review authentication events
3. **`modified_files_last7days.csv`**: Identify recent file system changes
4. **`system32_hashes.csv`**: Baseline for system file integrity
5. **Memory dump**: For advanced memory forensics

### Recommended Tools
- **Registry Analysis**: Registry Explorer, RegRipper
- **Memory Analysis**: Volatility, Rekall
- **Log Analysis**: Event Log Explorer, Splunk
- **Hash Verification**: HashMyFiles, HashCalc

## 🔄 Updates and Maintenance

### Version History
- **v2.0**: Enhanced with memory analysis and flexible collection modes
- **v1.0**: Initial release with standard evidence collection

### Future Enhancements
- Additional browser support
- Cloud storage integration
- Automated analysis reports
- Network artifact collection

## 📞 Support

For issues, questions, or feature requests:
1. Check the troubleshooting section
2. Review error logs in the output
3. Ensure all requirements are met
4. Verify administrative privileges

## ⚖️ Legal Notice

This tool is designed for authorized digital forensics and incident response activities only. Users are responsible for ensuring compliance with applicable laws and regulations. Always obtain proper authorization before collecting evidence from any system.

## 📄 License

This script is provided as-is for educational and professional use in digital forensics and incident response. Use at your own risk and ensure compliance with applicable laws and regulations.

---

**Version**: 2.0 Enhanced Edition  
**Last Updated**: December 2024  
**Compatibility**: Windows PowerShell 5.0+
