<#
.DESCRIPTION
    This is a Security Operations DFIR Script is a tool to perform incident response via PowerShell on compromised devices running Windows. 
    The collected information is saved in an output directory in the current folder, this is by creating a folder named 'DFIR-_hostname_-_year_-_month_-_date_'. 
    This folder is zipped at the end to enable easy collection.
    
    This script is to be integrated with Defender For Endpoint via Live Response sessions.But can be run on its own
	
	The script outputs the results as CSV.
#>

param(
        [Parameter(Mandatory=$false)][int]$sw = 1 # Defines the custom search window, this is done in days.
    )
    $ASCIIBanner = @"
  ____  _ _ _    _____          _ _    ____  _____ ___ ____  
 / ___|(_) | | _|_   _| __ __ _(_) |  |  _ \|  ___|_ _|  _ \ 
 \___ \| | | |/ / | || '__/ _` | | |  | | | | |_   | || |_) |
  ___) | | |   <  | || | | (_| | | |  | |_| |  _|  | ||  _ < 
 |____/|_|_|_|\_\ |_||_|  \__,_|_|_|  |____/|_|   |___|_| \_\
                                                               
                                               Windows Edition
                                                              `n
"@
Write-Host $ASCIIBanner

$ExecutionTime = $(get-date -f yyyy-MM-dd)
$FolderCreation = "C:\Support\DFIR-$env:computername-$ExecutionTime"
mkdir -Force $FolderCreation | Out-Null
$currentUsername = (Get-WmiObject Win32_Process -f 'Name="explorer.exe"').GetOwner().User

#CSV Output for import in SIEM
$CSVOutputFolder = "$FolderCreation\CSV Results (SIEM Import Data)"
mkdir -Force $CSVOutputFolder | Out-Null

#Search Window

function Get-IPInfo {
    $Ipinfoutput = "$FolderCreation\ipinfo.txt"
    Get-NetIPAddress | Out-File -Force -FilePath $Ipinfoutput
	$CSVExportLocation = "$CSVOutputFolder\IPConfiguration.csv"
	Get-NetIPAddress | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}
function Get-ShadowCopies {
    $ShadowCopy = "$FolderCreation\ShadowCopies.txt"
    Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ShadowCopy
	$CSVExportLocation = "$CSVOutputFolder\ShadowCopy.csv"
	Get-CimInstance Win32_ShadowCopy | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-OpenConnections {
    $ConnectionFolder = "$FolderCreation\Connections"
    mkdir -Force $ConnectionFolder | Out-Null
    $Ipinfoutput = "$ConnectionFolder\OpenConnections.txt"
    Get-NetTCPConnection -State Established | Out-File -Force -FilePath $Ipinfoutput
	$CSVExportLocation = "$CSVOutputFolder\OpenTCPConnections.csv"
	Get-NetTCPConnection -State Established | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-AutoRunInfo {
    $AutoRunFolder = "$FolderCreation\Persistence"
    mkdir -Force $AutoRunFolder | Out-Null
    $RegKeyOutput = "$AutoRunFolder\AutoRunInfo.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $RegKeyOutput
	$CSVExportLocation = "$CSVOutputFolder\AutoRun.csv"
	Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-InstalledDrivers {
    $AutoRunFolder = "$FolderCreation\Persistence"
    $RegKeyOutput = "$AutoRunFolder\InstalledDrivers.txt"
    driverquery | Out-File -Force -FilePath $RegKeyOutput
	$CSVExportLocation = "$CSVOutputFolder\Drivers.csv"
	(driverquery) -split "\n" -replace '\s\s+', ','  | Out-File -Force $CSVExportLocation -Encoding UTF8
}

function Get-ActiveUsers {
    $UserFolder = "$FolderCreation\UserInformation"
    mkdir -Force $UserFolder | Out-Null
    $ActiveUserOutput = "$UserFolder\ActiveUsers.txt"
    query user /server:$server | Out-File -Force -FilePath $ActiveUserOutput
	$CSVExportLocation = "$CSVOutputFolder\ActiveUsers.csv"
	(query user /server:$server) -split "\n" -replace '\s\s+', ','  | Out-File -Force -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-LocalUsers {
    $UserFolder = "$FolderCreation\UserInformation"
    $ActiveUserOutput = "$UserFolder\LocalUsers.txt"
    Get-LocalUser | Format-Table | Out-File -Force -FilePath $ActiveUserOutput
	$CSVExportLocation = "$CSVOutputFolder\LocalUsers.csv"
	Get-LocalUser | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ActiveProcesses {
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
	$CSVExportLocation = "$CSVOutputFolder\Processes.csv"

    $processes_list = @()
    foreach ($process in (Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($null -ne $process.ExecutablePath)
        {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash 
            $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
            $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
            $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $process.ExecutablePath
            $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
            $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
            $process_obj | Add-Member -NotePropertyName Proc_ProcessId -NotePropertyValue $process.ProcessId
            $processes_list += $process_obj
        }   
    }

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
	($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $CSVExportLocation
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
	
}

function Get-SecurityEventCount {
    param(
        [Parameter(Mandatory=$true)][String]$sw
    )
    $SecurityEvents = "$FolderCreation\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\EventCount.txt"
    $SecurityEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-$sw)
    $SecurityEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $ProcessOutput
}

function Get-SecurityEvents {
    param(
        [Parameter(Mandatory=$true)][String]$sw
    )
    $SecurityEvents = "$FolderCreation\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\SecurityEvents.txt"
    get-eventlog security -After (Get-Date).AddDays(-$sw) | Format-List * | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\SecurityEvents.csv"
	get-eventlog security -After (Get-Date).AddDays(-$sw) | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-EventViewerFiles {
    $EventViewer = "$FolderCreation\Event Viewer"
    mkdir -Force $EventViewer | Out-Null
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" | Where-Object{$_.BaseName -in $channels} | ForEach-Object{
        Copy-Item  -Path $_.FullName -Destination "$($EventViewer)\$($_.Name)"
    }
}

function Get-OfficeConnections {
    param(
        [Parameter(Mandatory = $false)][String]$UserSid
    )

    $ConnectionFolder = "$FolderCreation\Connections"
    $OfficeConnection = "$ConnectionFolder\ConnectionsMadeByOffice.txt"
    $CSVExportLocation = "$CSVOutputFolder\OfficeConnections.csv"

    # Determine registry key to query
    $regPath = if ($UserSid) {
        "HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache"
    } else {
        "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache"
    }

    # Run reg query (Live Response compatible)
    $regData = cmd /c "reg query `"$regPath`" 2>&1"

    # Save raw output
    $regData | Out-File -FilePath $OfficeConnection -Encoding UTF8 -Force

    # Parse to simple CSV if possible (extract subkeys)
    $parsed = $regData | Where-Object { $_ -match "^HKEY" } | ForEach-Object {
        [PSCustomObject]@{ RegistryKey = $_.Trim() }
    }

    $parsed | Export-Csv -NoTypeInformation -Path $CSVExportLocation -Encoding UTF8
}

function Get-NetworkShares {
    param(
        [Parameter(Mandatory = $false)][String]$UserSid
    )

    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\NetworkShares.txt"
    $CSVExportLocation = "$CSVOutputFolder\NetworkShares.csv"

    # Define the registry path
    $regPath = if ($UserSid) {
        "HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    } else {
        "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    }

    # Run reg query command
    $regOutput = cmd /c "reg query `"$regPath`" 2>&1"

    # Save raw output
    $regOutput | Out-File -FilePath $ProcessOutput -Encoding UTF8 -Force

    # Extract and convert subkeys to CSV format
    $parsed = $regOutput | Where-Object { $_ -match "^HKEY" } | ForEach-Object {
        [PSCustomObject]@{ RegistryKey = $_.Trim() }
    }

    $parsed | Export-Csv -Path $CSVExportLocation -NoTypeInformation -Encoding UTF8
}


function Get-SMBShares {
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\SMBShares.txt"
    Get-SmbShare | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\SMBShares.csv"
	Get-SmbShare | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-RDPSessions {
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RDPSessions.txt"
	$CSVExportLocation = "$CSVOutputFolder\RDPSessions.csv"
    qwinsta /server:localhost | Out-File -Force -FilePath $ProcessOutput
	(qwinsta /server:localhost) -split "\n" -replace '\s\s+', ',' | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-RemotelyOpenedFiles {

    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RemotelyOpenedFiles.txt"
	$CSVExportLocation = "$CSVOutputFolder\RemotelyOpenedFiles.csv"
    openfiles | Out-File -Force -FilePath $ProcessOutput
	(openfiles) -split "\n" -replace '\s\s+', ',' | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-DNSCache {
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\DNSCache.txt"
    Get-DnsClientCache | Format-List | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\DNSCache.csv"
	Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-PowershellHistoryCurrentUser {
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    mkdir -Force $PowershellConsoleHistory | Out-Null
    $PowershellHistoryOutput = "$PowershellConsoleHistory\PowershellHistoryCurrentUser.txt"
    history | Out-File -Force -FilePath $PowershellHistoryOutput
    $CSVExportLocation = "$CSVOutputFolder\PowerShellHistory.csv"
	history | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-PowershellConsoleHistory-AllUsers {
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    # Specify the directory where user profiles are stored
    $usersDirectory = "C:\Users"
    # Get a list of all user directories in C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = "$PowershellConsoleHistory\$userDir.Name"
            mkdir -Force $outputDirectory | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
            }
        }
}    


function Get-RecentlyInstalledSoftwareEventLogs {
    $ApplicationFolder = "$FolderCreation\Applications"
    mkdir -Force $ApplicationFolder | Out-Null
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | FL *| Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\InstalledSoftware.csv"
	Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-RunningServices {
    $ApplicationFolder = "$FolderCreation\Services"
    New-Item -Path $ApplicationFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = "$ApplicationFolder\RunningServices.txt"
    Get-Service | Where-Object {$_.Status -eq "Running"} | format-list | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\RunningServices.csv"
	Get-Service | Where-Object {$_.Status -eq "Running"} | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ScheduledTasks {
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    mkdir -Force $ScheduledTaskFolder| Out-Null
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksList.txt"
    Get-ScheduledTask | Where-Object {($_.State -ne 'Disabled') -and (($_.LastRunTime -eq $null) -or ($_.LastRunTime -gt (Get-Date).AddDays(-7)))} | Format-List | Out-File -Force -FilePath $ProcessOutput
	$CSVExportLocation = "$CSVOutputFolder\ScheduledTasks.csv"
	Get-ScheduledTask | Where-Object {($_.State -ne 'Disabled') -and (($_.LastRunTime -eq $null) -or ($_.LastRunTime -gt (Get-Date).AddDays(-7)))} | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ScheduledTasksRunInfo {
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksListRunInfo.txt"
	$CSVExportLocation = "$CSVOutputFolder\ScheduledTasksRunInfo.csv"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ProcessOutput
	Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ConnectedDevices {
    $DeviceFolder = "$FolderCreation\ConnectedDevices"
    New-Item -Path $DeviceFolder -ItemType Directory -Force | Out-Null
    $ConnectedDevicesOutput = "$DeviceFolder\ConnectedDevices.csv"
    Get-PnpDevice | Export-Csv -NoTypeInformation -Path $ConnectedDevicesOutput
	$CSVExportLocation = "$CSVOutputFolder\ConnectedDevices.csv"
	Get-PnpDevice | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Get-ChromiumFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    $HistoryFolder = "$FolderCreation\Browsers\Chromium"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

    $filesToCopy = @(
        'Preferences',
        'History'
    )

    Get-ChildItem "C:\Users\$Username\AppData\Local\*\*\User Data\*\" | Where-Object { `
        (Test-Path "$_\History") -and `
        [char[]](Get-Content "$($_.FullName)\History" -Encoding byte -TotalCount 'SQLite format'.Length) -join ''
    } | Where-Object { 
        $srcpath = $_.FullName
        $destpath = $_.FullName -replace "^C:\\Users\\$Username\\AppData\\Local",$HistoryFolder -replace "User Data\\",""
        New-Item -Path $destpath -ItemType Directory -Force | Out-Null

        $filesToCopy | ForEach-Object{
            $filesToCopy | Where-Object{ Test-Path "$srcpath\$_" } | ForEach-Object{ Copy-Item -Path "$srcpath\$_" -Destination "$destpath\$_" }
        }
    }
}

function Get-FirefoxFiles {
    param(
        [Parameter(Mandatory = $true)][String]$Username
    )

    $profilePath = "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $profilePath) {
        $HistoryFolder = "$FolderCreation\Browsers\Firefox"
        New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

        $filesToCopy = @(
            'places.sqlite',
            'permissions.sqlite',
            'content-prefs.sqlite',
            'extensions'
        )

        # Enumerate Firefox profile folders
        Get-ChildItem -Path $profilePath -Directory | ForEach-Object {
            $srcpath = $_.FullName
            $destpath = $srcpath -replace [regex]::Escape($profilePath), $HistoryFolder
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null

            foreach ($file in $filesToCopy) {
                $sourceFile = Join-Path $srcpath $file
                if (Test-Path $sourceFile) {
                    Copy-Item -Path $sourceFile -Destination (Join-Path $destpath $file) -Force
                }
            }
        }
    } else {
        Write-Host "Firefox profile path does not exist: $profilePath"
    }
}


function Get-MPLogs {
    $MPLogFolder = "$FolderCreation\MPLogs"
    New-Item -Path $MPLogFolder -ItemType Directory -Force | Out-Null
    $MPLogLocation = "C:\ProgramData\Microsoft\Windows Defender\Support\"
    $MPListFiles = Get-ChildItem -Path $MPLogLocation -Name "*.log"
    foreach ($file in $MPListFiles){
    Copy-Item -Path $MPLogLocation$file -Destination $MPLogFolder
    }
}

function Get-DefenderExclusions {
	$DefenderExclusionFolder = "$FolderCreation\DefenderExclusions"
	New-Item -Path $DefenderExclusionFolder -ItemType Directory -Force | Out-Null
	Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionPath.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionExtension.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionIpAddress.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionProcess.txt"
	
	$CSVExportLocation = "$CSVOutputFolder\DefenderExclusions.csv"
	$ExclusionPaths = (Get-MpPreference | Select-Object -ExpandProperty ExclusionPath) -join "`n"
	$ExclusionExtensions = (Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension) -join "`n"
	$ExclusionIPAddresses = (Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress) -join "`n"
	$ExclusionProcesses = (Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess) -join "`n"

	# Combine all results into a single array
	$combinedData = $ExclusionPaths, $ExclusionExtensions, $ExclusionIPAddresses, $ExclusionProcesses
	$combinedData -split "\n" -replace '\s\s+', ',' | Out-File -FilePath $CSVExportLocation -Encoding UTF8
}

function Zip-Results {
    Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
}

#Run all functions that do not require admin priviliges
function Run-WithoutAdminPrivilege {
    param(
        [Parameter(Mandatory=$false)][String]$UserSid,
        [Parameter(Mandatory=$false)][String]$Username
    )

    Get-IPInfo
    Get-OpenConnections
    Get-AutoRunInfo
    Get-ActiveUsers
    Get-LocalUsers
    Get-ActiveProcesses
    Get-OfficeConnections -UserSid $UserSid
    Get-NetworkShares -UserSid $UserSid
    Get-SMBShares
    Get-RDPSessions
    Get-PowershellHistoryCurrentUser
    Get-DNSCache
    Get-InstalledDrivers    
    Get-RecentlyInstalledSoftwareEventLogs
    Get-RunningServices
    Get-ScheduledTasks
    Get-ScheduledTasksRunInfo
    Get-ConnectedDevices
    if($Username) {
        Get-ChromiumFiles -Username $Username
        Get-FirefoxFiles -Username $Username
    }
}

#Run all functions that do require admin priviliges
function Run-WithAdminPrivilges {
    Get-SecurityEventCount $sw
    Get-SecurityEvents $sw
    Get-RemotelyOpenedFiles
    Get-ShadowCopies
    Get-EventViewerFiles
	Get-MPLogs
	Get-DefenderExclusions
    Get-PowershellConsoleHistory-AllUsers
}

Run-WithoutAdminPrivilege -Username $currentUsername
if ($IsAdmin) {
    Run-WithAdminPrivilges
}

Zip-Results
