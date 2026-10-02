#Requires -RunAsAdministrator
<#
==============================================================================
 BLUE TEAM WINDOWS SERVER CHEAT SHEET   (PowerShell 5.1, Server 2016/2019/2022)
==============================================================================
 HOW TO USE
  - Open PowerShell AS ADMINISTRATOR (ISE or VS Code makes it easy to run selections).
  - Load the helper functions once:   . .\blueteam_cheatsheet.ps1
    (the file then exits on purpose - it is NOT meant to be run top to bottom)
  - Then copy / select-and-run ONE BLOCK at a time, in tier order.
  - [!] marks anything that can break scored services or lock you out. Read it first.
  - [DC]  = needs the ActiveDirectory module (Domain Controller only)
  - [EX]  = run in Exchange Management Shell
  - After EVERY change, run:  Test-Scored    and send/receive a test email.
  - If the shell blocks scripts:  Set-ExecutionPolicy Bypass -Scope Process -Force
==============================================================================
#>

#region HELPER FUNCTIONS (these load when you dot-source the file)

function New-Pw { param([int]$Length = 16)
    $chars = ([char[]](48..57)) + ([char[]](65..90)) + ([char[]](97..122)) + ([char[]]'!#$%*+-=?')
    -join (1..$Length | ForEach-Object { $chars | Get-Random })
}

function Set-Reg { param($Path, $Name, $Value, $Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    "set $Path : $Name = $Value"
}

# Run every 15-30 minutes: shows what changed / what looks wrong
function Sweep {
    $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
    "`n=== LOGGED-ON USERS ==="; query user 2>$null
    "`n=== SMB SESSIONS ==="; Get-SmbSession | Select-Object ClientComputerName,ClientUserName,NumOpens | Format-Table -AutoSize
    "`n=== ADMIN GROUP MEMBERS ==="
    if ($isDC) { 'Domain Admins','Enterprise Admins','Schema Admins','Administrators' | ForEach-Object { "-- $_"; (Get-ADGroupMember $_ -Recursive).SamAccountName } }
    else { (Get-LocalGroupMember Administrators).Name }
    "`n=== NEW USERS (LAST 24H) / LOCAL USERS ==="
    if ($isDC) { $d = (Get-Date).AddHours(-24); Get-ADUser -Filter {whenCreated -gt $d} -Properties whenCreated | Select-Object SamAccountName,whenCreated }
    else { Get-LocalUser | Select-Object Name,Enabled,LastLogon }
    "`n=== NON-MICROSOFT SCHEDULED TASKS ==="
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskPath,TaskName,State,@{n='Run';e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ';'}} | Format-Table -AutoSize -Wrap
    "`n=== SERVICES FROM ODD PATHS ==="
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'powershell|cmd\.exe|\\Temp\\|\\Users\\|ProgramData|\\Public\\' } | Select-Object Name,StartName,PathName | Format-List
    "`n=== NEW LISTENERS (not in baseline) ==="
    $base = if (Test-Path C:\Blue\baseline_ports.txt) { Get-Content C:\Blue\baseline_ports.txt } else { @() }
    Get-NetTCPConnection -State Listen | Where-Object { "$($_.LocalPort)" -notin $base } |
        Select-Object LocalPort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA 0).Name}} -Unique | Format-Table -AutoSize
    "`n=== ESTABLISHED (non-loopback) ==="
    Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } |
        Select-Object LocalPort,RemoteAddress,RemotePort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Sort-Object Proc | Format-Table -AutoSize
    "`n=== SECURITY EVENTS, LAST 15 MIN (new user/group change/task/service/log cleared) ==="
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720,4722,4724,4728,4732,4756,4698,4697,1102;StartTime=(Get-Date).AddMinutes(-15)} -EA 0 |
        Select-Object TimeCreated,Id,@{n='Msg';e={$_.Message.Split("`n")[0]}} | Format-Table -AutoSize
}

# Quick "are my scored services still up?" check
function Test-Scored { param([int[]]$Ports = @(25,587,465,143,993,110,995,80,443,53,445,389))
    $Ports | ForEach-Object { [pscustomobject]@{ Port = $_; Listening = [bool](Get-NetTCPConnection -State Listen -LocalPort $_ -EA 0) } } | Format-Table -AutoSize
    "Automatic services that are NOT running:"
    Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Select-Object Name,Status | Format-Table -AutoSize
}

#endregion

Write-Warning "Helper functions loaded (New-Pw, Set-Reg, Sweep, Test-Scored). Copy blocks below one at a time - do NOT run this file whole."
return

###############################################################################
# TIER 0 - BASELINE AND BACKUP
###############################################################################
#region 0.x Baseline and backup

New-Item -ItemType Directory -Force C:\Blue | Out-Null
Start-Transcript -Path C:\Blue\transcript.log -Append          # automatic change log of everything you type

Get-ComputerInfo | Select-Object WindowsProductName,OsBuildNumber,CsName,CsDomain,CsDomainRole   # DomainRole 4 or 5 = Domain Controller
Get-WindowsFeature | Where-Object Installed | Select-Object Name,DisplayName | Format-Table -AutoSize
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -EA 0 |
    Where-Object DisplayName | Select-Object DisplayName,DisplayVersion | Sort-Object DisplayName | Format-Table -AutoSize

# Save originals so you can compare or roll back
netsh advfirewall export C:\Blue\fw_original.wfw
secedit /export /cfg C:\Blue\secpol_original.cfg
Get-Service | Select-Object Name,Status,StartType | Export-Csv C:\Blue\services_baseline.csv -NoTypeInformation
Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Export-Csv C:\Blue\tasks_baseline.csv -NoTypeInformation
Get-LocalUser | Select-Object Name,Enabled | Export-Csv C:\Blue\localusers_baseline.csv -NoTypeInformation

# [DC] baseline of AD users and GPOs
Import-Module ActiveDirectory,GroupPolicy
Get-ADUser -Filter * -Properties whenCreated | Select-Object SamAccountName,Enabled,whenCreated | Export-Csv C:\Blue\adusers_baseline.csv -NoTypeInformation
New-Item -ItemType Directory -Force C:\Blue\GPO | Out-Null
Backup-GPO -All -Path C:\Blue\GPO

# System state backup (needs a separate volume, e.g. E:)  - skip if you have hypervisor snapshots
Install-WindowsFeature Windows-Server-Backup
wbadmin start systemstatebackup -backupTarget:E: -quiet

#endregion

###############################################################################
# TIER 1 - CREDENTIALS AND ACCOUNTS
###############################################################################
#region 1.1 Change passwords

# --- one account, local ---
$p = Read-Host "New password" -AsSecureString
Set-LocalUser -Name "Administrator" -Password $p

# --- one account, domain [DC] ---
Set-ADAccountPassword -Identity "jsmith" -Reset -NewPassword $p

# --- ALL enabled domain users, random passwords, saved to a file [DC] ---
# [!] Put scoring / service accounts in $skip. Tell your team (and whoever owns user logins) first.
$skip = 'krbtgt','Guest','DefaultAccount','scoreuser'
$out = foreach ($u in (Get-ADUser -Filter * | Where-Object { $_.SamAccountName -notin $skip -and $_.Enabled })) {
    $pw = New-Pw
    Set-ADAccountPassword $u -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
    [pscustomobject]@{ User = $u.SamAccountName; Password = $pw }
}
$out | Export-Csv C:\Blue\newpasswords.csv -NoTypeInformation      # protect this file

# --- ALL enabled local users (non-DC) ---
foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin $skip })) {
    Set-LocalUser $u -Password (ConvertTo-SecureString (New-Pw) -AsPlainText -Force)
}

# hMailServer mailbox passwords are NOT Windows accounts - see section 5.1
#endregion

#region 1.2 Audit privileged groups

# Non-DC
'Administrators','Remote Desktop Users','Backup Operators','Power Users','Network Configuration Operators' | ForEach-Object {
    "== $_"; Get-LocalGroupMember $_ -EA 0 | Select-Object Name,ObjectClass }
# Remove a member:
# Remove-LocalGroupMember -Group Administrators -Member "DOMAIN\baduser"

# [DC]
'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Backup Operators','Account Operators','Server Operators',
'Print Operators','DnsAdmins','Group Policy Creator Owners','Remote Desktop Users','Organization Management' | ForEach-Object {
    "== $_"; Get-ADGroupMember $_ -Recursive -EA 0 | Select-Object SamAccountName,objectClass }
# Remove a member:
# Remove-ADGroupMember -Identity 'Domain Admins' -Members baduser -Confirm:$false

# Accounts flagged as privileged by AD (AdminCount=1)
Get-ADUser -Filter 'AdminCount -eq 1' | Select-Object SamAccountName,Enabled
#endregion

#region 1.3 Default and rogue accounts

Disable-LocalUser -Name Guest
# [!] Renaming Administrator can break scoring logins. Only if the rules allow:
# Rename-LocalUser -Name Administrator -NewName 'blueadm'
# Disable-LocalUser -Name somebaduser
# Remove-LocalUser -Name somebaduser

Get-LocalUser | Where-Object { $_.Name -like '*$' }                      # hidden-looking local users

# [DC]
Disable-ADAccount -Identity Guest
Get-ADUser -Filter 'SamAccountName -like "*$"'                           # user accounts ending in $ are suspicious
Get-ADUser -Filter * -Properties whenCreated,LastLogonDate,PasswordNeverExpires,Description |
    Sort-Object whenCreated -Descending | Select-Object -First 25 SamAccountName,Enabled,whenCreated,LastLogonDate,PasswordNeverExpires
Get-ADUser -Filter * -Properties Description | Where-Object Description | Select-Object SamAccountName,Description   # passwords hiding in descriptions?
Get-ADUser -Filter 'PasswordNotRequired -eq $true' | Select-Object SamAccountName
# Fix: Get-ADUser -Filter 'PasswordNotRequired -eq $true' | Set-ADUser -PasswordNotRequired $false
Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory }   # SID history abuse
# Disable a rogue user:  Disable-ADAccount -Identity baduser
#endregion

#region 1.4 Password and lockout policy

# Local policy (on a DC this edits the domain policy)
net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:24 /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15

# [DC] domain policy
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -MinPasswordLength 12 -ComplexityEnabled $true `
    -PasswordHistoryCount 24 -MaxPasswordAge 90.00:00:00 -MinPasswordAge 1.00:00:00 `
    -LockoutThreshold 10 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00 -ReversibleEncryptionEnabled $false
Get-ADDefaultDomainPasswordPolicy
#endregion

#region 1.5 Kick unknown sessions

query user                          # note the ID column
# logoff 3                          # log off session ID 3
Get-SmbSession | Select-Object ClientComputerName,ClientUserName,NumOpens
# [!] Closes ALL SMB sessions (users reconnect automatically):
# Get-SmbSession | Close-SmbSession -Force
Get-SmbOpenFile | Select-Object ClientUserName,Path
#endregion

###############################################################################
# TIER 2 - ATTACK SURFACE
###############################################################################
#region 2.1 Firewall   [!] DO STEPS IN ORDER - allow rules BEFORE default-deny

# Step 1 - allow what you serve. Edit the lists to match YOUR scored services.
$team = '10.0.0.5','10.0.0.6'                    # <-- your team's management IPs
New-NetFirewallRule -DisplayName 'ALLOW Mail SMTP/Submission' -Direction Inbound -Protocol TCP -LocalPort 25,587,465 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'ALLOW Mail IMAP/POP3'       -Direction Inbound -Protocol TCP -LocalPort 143,993,110,995 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'ALLOW Web'                  -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'ALLOW DNS TCP'              -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'ALLOW DNS UDP'              -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'ALLOW ICMP echo'            -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'ALLOW RDP team only'        -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $team -Action Allow -Profile Any

# [DC] keep domain traffic working (domain members must reach these)
Get-NetFirewallRule -DisplayGroup 'Active Directory Domain Services','Kerberos Key Distribution Center','DNS Service','Core Networking' -EA 0 | Enable-NetFirewallRule

# Step 2 - see every enabled inbound allow rule with its ports, so you know what to disable
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ForEach-Object {
    $pf = $_ | Get-NetFirewallPortFilter
    [pscustomobject]@{ Name = $_.DisplayName; Group = $_.DisplayGroup; Proto = $pf.Protocol; Port = $pf.LocalPort; Profile = $_.Profile }
} | Sort-Object Port | Format-Table -AutoSize

# Step 3 - restrict built-in admin rules to the team's IPs
Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -EA 0       | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $team
Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -EA 0 | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $team

# Step 4 - disable rules you do not need. [!] Do NOT disable SMB (445) on a DC / file server.
# Disable-NetFirewallRule -DisplayGroup 'Remote Service Management','Remote Event Log Management','Remote Scheduled Tasks Management','Windows Management Instrumentation (WMI)','Network Discovery','Remote Volume Management'

# Step 5 - default deny inbound + logging
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767 -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'

# LOCKED OUT? From the console:  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Allow
# Or roll back:                  netsh advfirewall import C:\Blue\fw_original.wfw

# Block an attacker IP (explicit block beats allow). [!] Never block the scoring engine.
# New-NetFirewallRule -DisplayName 'BLOCK red 1.2.3.4' -Direction Inbound -RemoteAddress 1.2.3.4 -Action Block
#endregion

#region 2.2 Map listening ports to processes

Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA 0).Name}},@{n='Path';e={(Get-Process -Id $_.OwningProcess -EA 0).Path}} |
    Sort-Object LocalPort | Format-Table -AutoSize
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,@{n='Process';e={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Sort-Object LocalPort | Format-Table -AutoSize
#endregion

#region 2.3 Disable unneeded services and features

# [!] Review the list. Remove 'MSFTPSVC' / 'Spooler' from it if you need them.
$svc = 'Spooler','RemoteRegistry','TlntSvr','SNMP','upnphost','SSDPSRV','WebClient','Fax','bthserv',
       'XblAuthManager','XblGameSave','XboxNetApiSvc','lltdsvc','RemoteAccess','MSFTPSVC'
foreach ($s in $svc) {
    if (Get-Service $s -EA 0) { Stop-Service $s -Force -EA 0; Set-Service $s -StartupType Disabled; "disabled $s" }
}

# SMBv1 off
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Uninstall-WindowsFeature FS-SMB1 -EA 0

# Remove risky features (ignore errors for ones not installed)
Uninstall-WindowsFeature Telnet-Client,TFTP-Client,SNMP-Service,PowerShell-V2 -EA 0
# Uninstall-WindowsFeature Web-Ftp-Server        # only if FTP is not scored

# Find known attacker / remote-access tools running right now
Get-Process | Where-Object { $_.Name -match '^(nc|ncat|netcat|nc64)$|teamviewer|anydesk|vnc|psexe|mimikatz|chisel|plink|ngrok|meterpreter|beacon' } |
    Select-Object Id,Name,Path
#endregion

#region 2.4 Installed software (look for remote tools, hacking tools)

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -EA 0 |
    Where-Object DisplayName | Select-Object DisplayName,Publisher,InstallDate | Sort-Object InstallDate -Descending | Format-Table -AutoSize
# Uninstall (MSI):   Get-Package -Name '*AnyDesk*' | Uninstall-Package
# Or:                wmic product where "name like '%TeamViewer%'" call uninstall /nointeractive
Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' -and $_.State -eq 'Installed' }   # SSH server present?
#endregion

#region 2.5 RDP and WinRM

$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
Set-Reg $rdp UserAuthentication 1      # require NLA
Set-Reg $rdp SecurityLayer 2           # SSL/TLS
Set-Reg $rdp MinEncryptionLevel 3      # high
Get-LocalGroupMember 'Remote Desktop Users' -EA 0

# Turn RDP OFF completely (if you do not need it):
# Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1
# Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'

# Turn WinRM / PS remoting OFF (if unused):
# Disable-PSRemoting -Force; Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled
# Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management'
#endregion

###############################################################################
# TIER 3 - EVICT EXISTING FOOTHOLDS (repeat often)
###############################################################################
#region 3.1 Scheduled tasks

Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    Select-Object TaskPath,TaskName,State,@{n='User';e={$_.Principal.UserId}},
        @{n='Run';e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ';'}} | Format-List

# Tasks under \Microsoft\ that run shells / LOLBins (attackers hide there too)
Get-ScheduledTask | Where-Object { $_.Actions.Execute -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin' } |
    Select-Object TaskPath,TaskName,@{n='Run';e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ';'}} | Format-List

# Compare against the baseline you saved
Compare-Object (Import-Csv C:\Blue\tasks_baseline.csv).TaskName (Get-ScheduledTask).TaskName

# Remove one:
# Unregister-ScheduledTask -TaskName 'EvilTask' -Confirm:$false
#endregion

#region 3.2 Services and auto-start registry keys

Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch '^"?C:\\(Windows|Program Files)' } |
    Select-Object Name,State,StartMode,StartName,PathName | Format-List
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'powershell|cmd\.exe|\\Temp\\|\\Users\\|ProgramData|\\Public\\' } |
    Select-Object Name,StartName,PathName | Format-List
# New services since baseline:
Compare-Object (Import-Csv C:\Blue\services_baseline.csv).Name (Get-Service).Name

# Remove a rogue service:
# Stop-Service BadSvc -Force; sc.exe delete BadSvc

# Registry autoruns
$keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
foreach ($k in $keys) { "== $k"; Get-ItemProperty $k -EA 0 | Select-Object * -ExcludeProperty PS* | Format-List }
# Remove one:  Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'EvilValue'

# Winlogon: Shell must be explorer.exe, Userinit must be C:\Windows\system32\userinit.exe,
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Shell,Userinit,Taskman
# Fix:
# Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'explorer.exe'
# Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,'

# AppInit DLLs (must be empty)
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Select-Object AppInit_DLLs,LoadAppInit_DLLs
# Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -Value ''
#endregion

#region 3.3 Startup folders, WMI, IFEO, sticky-keys backdoors

Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp','C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' -Force -EA 0

# Image File Execution Options "Debugger" hijacks
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
    Where-Object { (Get-ItemProperty $_.PSPath).Debugger } |
    Select-Object PSChildName,@{n='Debugger';e={(Get-ItemProperty $_.PSPath).Debugger}}
# Remove:  Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -EA 0

# Accessibility binaries replaced with cmd.exe? (press Shift x5 at login screen as a manual test)
$cmdHash = (Get-FileHash C:\Windows\System32\cmd.exe).Hash
'sethc','utilman','osk','narrator','magnify','displayswitch','atbroker' | ForEach-Object {
    $f = "C:\Windows\System32\$_.exe"
    if (Test-Path $f) {
        $sig = (Get-AuthenticodeSignature $f).Status
        $bad = ((Get-FileHash $f).Hash -eq $cmdHash) -or ($sig -ne 'Valid')
        '{0,-15} signature={1,-10} {2}' -f $_, $sig, $(if ($bad) { '!!! SUSPICIOUS' } else { 'ok' })
    }
}
sfc /scannow            # restores replaced system binaries (takes a few minutes)

# WMI persistence (a clean system normally has none of these)
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
# Remove all:
# Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
# Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Remove-WmiObject
# Get-WmiObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject
#endregion

#region 3.4 Suspicious processes and connections

Get-NetTCPConnection -State Established | Select-Object LocalPort,RemoteAddress,RemotePort,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA 0).Name}},@{n='Path';e={(Get-Process -Id $_.OwningProcess -EA 0).Path}} |
    Sort-Object Proc | Format-Table -AutoSize

# Processes running out of user-writable folders
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match '\\(Temp|Users|ProgramData|Public)\\' } |
    Select-Object ProcessId,Name,ParentProcessId,ExecutablePath,CommandLine | Format-List

# Running binaries with no valid signature
Get-Process | Where-Object Path | Select-Object -Unique Path | ForEach-Object { Get-AuthenticodeSignature $_.Path } |
    Where-Object Status -ne 'Valid' | Select-Object Path,Status

# Kill one:  Stop-Process -Id 1234 -Force
#endregion

#region 3.5 Shares and permissions

Get-SmbShare | Select-Object Name,Path,Description
Get-SmbShare | ForEach-Object { Get-SmbShareAccess -Name $_.Name } | Format-Table -AutoSize
# Remove a share:        Remove-SmbShare -Name 'EvilShare' -Force
# Remove Everyone:       Revoke-SmbShareAccess -Name 'Data' -AccountName Everyone -Force
# Grant specific group:  Grant-SmbShareAccess -Name 'Data' -AccountName 'DOMAIN\Staff' -AccessRight Change -Force
#endregion

#region 3.6 Web shells and dropped files

# Recently modified web files (Exchange + IIS)
Get-ChildItem C:\inetpub,"$env:ExchangeInstallPath\FrontEnd\HttpProxy" -Recurse -Include *.aspx,*.asp,*.ashx,*.asmx,*.php,*.jsp -EA 0 |
    Sort-Object LastWriteTime -Descending | Select-Object -First 40 FullName,LastWriteTime,Length

# Web files containing shell-like code
Get-ChildItem C:\inetpub -Recurse -Include *.aspx,*.asp,*.ashx,*.php -EA 0 |
    Select-String -Pattern 'eval\(','Process\.Start','cmd\.exe','FromBase64String','System\.Diagnostics\.Process','WScript\.Shell','Request\.Form\[' |
    Select-Object Path,LineNumber -Unique

# New executables / scripts in common drop locations (last 3 days)
Get-ChildItem C:\Windows\Temp,C:\Users\*\AppData\Local\Temp,C:\ProgramData,C:\Users\Public -Recurse -Force -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.hta -EA 0 |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-3) | Select-Object FullName,LastWriteTime
# Recently changed files in System32:
Get-ChildItem C:\Windows\System32 -File -EA 0 | Where-Object LastWriteTime -gt (Get-Date).AddDays(-3) | Select-Object Name,LastWriteTime
#endregion

#region 3.7 Hosts file, certificates, proxy, DNS client

Get-Content C:\Windows\System32\drivers\etc\hosts | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }   # should print nothing useful
Get-ChildItem Cert:\LocalMachine\Root | Sort-Object NotBefore -Descending | Select-Object -First 15 Subject,Thumbprint,NotBefore
netsh winhttp show proxy
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses
# Reset hosts file:  Set-Content C:\Windows\System32\drivers\etc\hosts '# cleaned'
#endregion

#region 3.8 Defender (state, exclusions, scan)

Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected
Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension       # red team adds exclusions to hide malware

Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
    -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled
Set-MpPreference -EnableNetworkProtection Enabled -EA 0

# Remove ALL exclusions. [!] Exchange has legitimate AV exclusions - review first, remove only the ones you cannot justify.
# $mp = Get-MpPreference
# $mp.ExclusionPath      | ForEach-Object { Remove-MpPreference -ExclusionPath $_ }
# $mp.ExclusionProcess   | ForEach-Object { Remove-MpPreference -ExclusionProcess $_ }
# $mp.ExclusionExtension | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ }

Update-MpSignature
Start-MpScan -ScanType QuickScan
# Start-MpScan -ScanType FullScan -AsJob        # slow, run in background
Get-MpThreatDetection | Select-Object InitialDetectionTime,ProcessName,Resources
#endregion

#region 3.9 GPO tampering [DC]

Get-GPO -All | Sort-Object ModificationTime -Descending | Select-Object DisplayName,ModificationTime,GpoStatus
Get-GPOReport -All -ReportType Html -Path C:\Blue\GPOreport.html          # open it and read startup scripts, tasks, restricted groups
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Include *.ps1,*.bat,*.vbs,*.cmd,*.exe,*.dll -EA 0 | Select-Object FullName,LastWriteTime
# Restore a GPO from your earlier backup:  Restore-GPO -Name 'Default Domain Policy' -Path C:\Blue\GPO
#endregion

###############################################################################
# TIER 4 - PATCHING
###############################################################################
#region 4.x Windows and application patches

Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID,InstalledOn,Description

# Option A - PSWindowsUpdate module (needs internet)
Install-PackageProvider NuGet -Force
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot        # reboot later at a safe moment

# Option B - built-in
UsoClient StartScan
UsoClient StartDownload
UsoClient StartInstall
# Or:  sconfig  -> option 6

# [EX] Exchange build number (compare against Microsoft's latest CU/SU)
Get-ExchangeServer | Format-List Name,AdminDisplayVersion

# Pending reboot?
Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
#endregion

###############################################################################
# TIER 5 - PROTECT THE SCORED SERVICES
###############################################################################
#region 5.1a Exchange mail server [EX]

# --- open relay / receive connectors ---
Get-ReceiveConnector | Format-List Name,Bindings,RemoteIPRanges,PermissionGroups,AuthMechanism,RequireTLS,MaxMessageSize
# Who has relay rights? (ANONYMOUS should NOT have ms-Exch-SMTP-Accept-Any-Recipient)
Get-ReceiveConnector | Get-ADPermission | Where-Object { $_.ExtendedRights -like '*ms-Exch-SMTP-Accept-Any-Recipient*' -and -not $_.IsInherited } |
    Format-Table Identity,User,ExtendedRights -AutoSize
# Remove anonymous relay:
# Remove-ADPermission -Identity "SERVER\ConnectorName" -User "NT AUTHORITY\ANONYMOUS LOGON" -ExtendedRights ms-Exch-SMTP-Accept-Any-Recipient
# Tighten a relay connector's allowed IPs (never 0.0.0.0-255.255.255.255):
# Set-ReceiveConnector "SERVER\ConnectorName" -RemoteIPRanges 10.0.0.0/24
Get-AcceptedDomain | Format-Table Name,DomainName,DomainType

# --- malicious transport rules, forwarding, inbox rules, permissions ---
Get-TransportRule | Format-List Name,State,Priority,Description
# Remove-TransportRule -Identity "EvilRule" -Confirm:$false
Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress } | Select-Object Name,ForwardingAddress,ForwardingSmtpAddress
# Fix: Set-Mailbox user -ForwardingAddress $null -ForwardingSmtpAddress $null
Get-Mailbox -ResultSize Unlimited | ForEach-Object { Get-InboxRule -Mailbox $_.Identity -EA 0 } |
    Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage } |
    Select-Object MailboxOwnerId,Name,ForwardTo,RedirectTo,DeleteMessage
# Remove-InboxRule -Mailbox user -Identity "RuleName"
Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | Where-Object { $_.User -notlike 'NT AUTHORITY\*' -and -not $_.IsInherited } |
    Select-Object Identity,User,AccessRights
Get-ManagementRoleAssignment -Role ApplicationImpersonation -GetEffectiveUsers          # commonly abused
Get-RoleGroupMember 'Organization Management'

# --- exposed web endpoints ---
Get-OwaVirtualDirectory | Format-List Server,InternalUrl,ExternalUrl
Get-EcpVirtualDirectory | Format-List Server,InternalUrl,ExternalUrl
# Hide ECP from outside:  Set-EcpVirtualDirectory -Identity "SERVER\ecp (Default Web Site)" -ExternalUrl $null

# --- turn off protocols you do not serve ---
# [!] Only if POP/IMAP are NOT scored:
# Get-CASMailbox -ResultSize Unlimited | Set-CASMailbox -PopEnabled $false -ImapEnabled $false

# --- service health ---
Get-Service MSExchange* | Where-Object Status -ne 'Running' | Select-Object Name,Status
Test-ServiceHealth
#endregion

#region 5.1b hMailServer (via COM)

$h = New-Object -ComObject hMailServer.Application
$h.Authenticate('Administrator','CURRENT_ADMIN_PASSWORD') | Out-Null
# List every account, whether it is active, and whether forwarding is on
for ($i = 0; $i -lt $h.Domains.Count; $i++) {
    $d = $h.Domains.Item($i)
    "== Domain: $($d.Name)"
    for ($j = 0; $j -lt $d.Accounts.Count; $j++) {
        $a = $d.Accounts.Item($j)
        '{0}  active={1}  forward={2} -> {3}' -f $a.Address,$a.Active,$a.ForwardEnabled,$a.ForwardAddress
    }
    for ($k = 0; $k -lt $d.Aliases.Count; $k++) { $al = $d.Aliases.Item($k); "alias: $($al.Name) -> $($al.Value)" }
}
# Reset a mailbox password / disable forwarding:
# $a = $h.Domains.ItemByName('example.com').Accounts.ItemByAddress('user@example.com')
# $a.Password = (New-Pw); $a.ForwardEnabled = $false; $a.Save()
# Auto-ban, IP ranges, and required SMTP auth are easiest in the hMailServer Administrator GUI (Settings > Advanced).
#endregion

#region 5.1c Mail TLS hardening (any mail server using Windows Schannel)

# [!] RISKY: needs a reboot and can break old clients / the scoring engine. Test mail flow after.
$s = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($proto in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') {
    foreach ($role in 'Server','Client') { Set-Reg "$s\$proto\$role" Enabled 0; Set-Reg "$s\$proto\$role" DisabledByDefault 1 }
}
foreach ($role in 'Server','Client') { Set-Reg "$s\TLS 1.2\$role" Enabled 1; Set-Reg "$s\TLS 1.2\$role" DisabledByDefault 0 }
# .NET must use TLS 1.2 or Exchange breaks:
foreach ($n in 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319','HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319') {
    Set-Reg $n SchUseStrongCrypto 1; Set-Reg $n SystemDefaultTlsVersions 1
}
#endregion

#region 5.2 IIS / webmail

Import-Module WebAdministration
Get-Website | Select-Object Name,State,PhysicalPath,@{n='Bindings';e={$_.Bindings.Collection.bindingInformation -join ', '}}
Get-WebBinding | Select-Object protocol,bindingInformation,certificateHash
Get-IISAppPool | Select-Object Name,State,@{n='Identity';e={$_.ProcessModel.IdentityType}}

# Directory browsing OFF on every site
Get-Website | ForEach-Object { Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath "IIS:\Sites\$($_.Name)" }
# Remove X-Powered-By header globally
Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders' -Name . -AtElement @{name='X-Powered-By'} -EA 0
# Stop a site you do not need:  Stop-Website 'SiteName'
# [!] On Exchange servers, do NOT remove 'Default Web Site' or 'Exchange Back End'.
Get-WindowsFeature Web-* | Where-Object Installed | Select-Object Name
#endregion

#region 5.3 DNS server

Get-DnsServerZone | Select-Object ZoneName,ZoneType,DynamicUpdate,SecureSecondaries,IsDsIntegrated
foreach ($z in (Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' })) {
    Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries NoTransfer          # no zone transfers
    if ($z.IsDsIntegrated) { Set-DnsServerPrimaryZone -Name $z.ZoneName -DynamicUpdate Secure }
}
# Check records red team may change (MX is critical for mail)
$zone = (Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -notlike '_msdcs*' } | Select-Object -First 1).ZoneName
Get-DnsServerResourceRecord -ZoneName $zone | Where-Object RecordType -in 'MX','A','AAAA','CNAME','TXT','SRV' | Sort-Object RecordType |
    Format-Table HostName,RecordType,Timestamp,@{n='Data';e={$_.RecordData.CimInstanceProperties.Value -join ' '}} -AutoSize
# [!] Only if nothing relies on this server as a resolver:
# Set-DnsServerRecursion -Enable $false
#endregion

###############################################################################
# TIER 6 - OS AUTHENTICATION AND PROTOCOL HARDENING
###############################################################################
#region 6.1 NTLM, LM hashes, anonymous access, credential theft

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-Reg $lsa LmCompatibilityLevel 5          # NTLMv2 only, refuse LM and NTLM
Set-Reg $lsa NoLMHash 1                      # never store LM hashes
Set-Reg $lsa RestrictAnonymous 1
Set-Reg $lsa RestrictAnonymousSAM 1          # no anonymous SAM enumeration
Set-Reg $lsa EveryoneIncludesAnonymous 0
Set-Reg "$lsa\MSV1_0" NTLMMinClientSec 537395200   # require NTLMv2 session security + 128-bit
Set-Reg "$lsa\MSV1_0" NTLMMinServerSec 537395200
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0    # no cleartext creds in memory
# [!] LSA protection: reboot needed, test first (some drivers conflict)
# Set-Reg $lsa RunAsPPL 1
#endregion

#region 6.2 SMB hardening

Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
$lm = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-Reg $lm RestrictNullSessAccess 1
Set-Reg $lm NullSessionShares @('') MultiString
Set-Reg $lm NullSessionPipes  @('') MultiString
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,RestrictNamedPipeAccessViaQuic
#endregion

#region 6.3 Name-resolution poisoning (LLMNR, NetBIOS, mDNS, WPAD)

Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0       # LLMNR off
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' EnableMDNS 0        # mDNS off
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' DisableWpad 1
# NetBIOS over TCP/IP off on every adapter (2 = disable)
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
#endregion

#region 6.4 UAC, AutoPlay, logon screen, remote assistance

$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-Reg $sys EnableLUA 1
Set-Reg $sys ConsentPromptBehaviorAdmin 2
Set-Reg $sys LocalAccountTokenFilterPolicy 0     # blocks remote UAC bypass for local admins
Set-Reg $sys DontDisplayLastUserName 1
Set-Reg $sys InactivityTimeoutSecs 900
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0
# Optional: stop wscript/cscript from running .vbs/.js (can break admin scripts)
# Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' Enabled 0

# If you must keep Print Spooler running, PrintNightmare mitigations:
$pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
Set-Reg $pp NoWarningNoElevationOnInstall 0
Set-Reg $pp UpdatePromptSettings 0
Set-Reg $pp RestrictDriverInstallationToAdministrators 1
#endregion

#region 6.5 User rights assignments (via secedit)

# On a DC the domain GPO overrides local settings - do this in GPMC there instead.
secedit /export /cfg C:\Blue\sec.inf /areas USER_RIGHTS
# Edit C:\Blue\sec.inf in Notepad. Good targets:
#   SeDenyNetworkLogonRight   = *S-1-5-32-546            (Guests)
#   SeDebugPrivilege          = *S-1-5-32-544            (Administrators only)
#   SeTcbPrivilege            =                          (nobody)
#   SeRemoteInteractiveLogonRight = *S-1-5-32-544        (Administrators only; add *S-1-5-32-555 if RDP users needed)
# Then apply:
# secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Blue\sec.inf /areas USER_RIGHTS
#endregion

###############################################################################
# TIER 7 - ACTIVE DIRECTORY SPECIFIC [DC]
###############################################################################
#region 7.1 ZeroLogon and LDAP signing

Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' FullSecureChannelProtection 1
# [!] Test apps that use LDAP: unsigned simple binds will fail after this
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 2
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LdapEnforceChannelBinding 1
# Stop regular users from joining rogue machines to the domain (blocks noPac / RBCD tricks)
Set-ADDomain -Identity (Get-ADDomain) -Replace @{ 'ms-DS-MachineAccountQuota' = '0' }
#endregion

#region 7.2 Kerberos attack paths

Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Select-Object SamAccountName                 # AS-REP roastable
# Fix: Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Set-ADAccountControl -DoesNotRequirePreAuth $false
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName   # kerberoastable
Get-ADUser -Filter 'TrustedForDelegation -eq $true' | Select-Object SamAccountName                   # unconstrained delegation
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Select-Object Name
Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object { $_.'msDS-AllowedToDelegateTo' } | Select-Object SamAccountName

# krbtgt reset (golden-ticket cleanup). [!] Run TWICE, hours apart if possible. Confirm with team first.
# Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString (New-Pw 32) -AsPlainText -Force)
#endregion

#region 7.3 DCSync rights and AdminSDHolder

$dn = (Get-ADDomain).DistinguishedName
$repl = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'
(Get-Acl "AD:$dn").Access | Where-Object { "$($_.ObjectType)" -in $repl } | Select-Object IdentityReference,ActiveDirectoryRights
# Only Domain Controllers / Enterprise DCs / Administrators should appear. Anyone else = DCSync backdoor.

(Get-Acl "AD:CN=AdminSDHolder,CN=System,$dn").Access |
    Where-Object { $_.IdentityReference -notmatch 'SYSTEM|Domain Admins|Enterprise Admins|Administrators|SELF|Authenticated Users|ENTERPRISE DOMAIN CONTROLLERS|Pre-Windows 2000|Everyone' } |
    Format-Table IdentityReference,ActiveDirectoryRights -AutoSize
#endregion

#region 7.4 DSRM password

# Replace NEWPASSWORD
ntdsutil "set dsrm password" "reset password on server null" "NEWPASSWORD" q q
#endregion

###############################################################################
# TIER 8 - DETECTION AND LOGGING
###############################################################################
#region 8.1 Audit policy

Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy 1       # force advanced audit policy
$sf = 'Logon','Special Logon','User Account Management','Security Group Management','Computer Account Management','Credential Validation',
      'Kerberos Authentication Service','Kerberos Service Ticket Operations','Sensitive Privilege Use','File Share','Other Object Access Events',
      'Directory Service Changes','Audit Policy Change','Authentication Policy Change','Security System Extension','Process Creation','Account Lockout'
foreach ($c in $sf) { auditpol /set /subcategory:"$c" /success:enable /failure:enable | Out-Null }
auditpol /set /subcategory:"Logoff" /success:enable | Out-Null
auditpol /get /category:*
# Simpler but noisy: auditpol /set /category:* /success:enable /failure:enable
#endregion

#region 8.2 Command-line and PowerShell logging

Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Set-Reg "$ps\ScriptBlockLogging" EnableScriptBlockLogging 1
Set-Reg "$ps\ModuleLogging" EnableModuleLogging 1
Set-Reg "$ps\ModuleLogging\ModuleNames" '*' '*' String
Set-Reg "$ps\Transcription" EnableTranscripting 1
Set-Reg "$ps\Transcription" EnableInvocationHeader 1
Set-Reg "$ps\Transcription" OutputDirectory 'C:\Blue\PSTranscripts' String
#endregion

#region 8.3 Event log sizes (never clear logs)

wevtutil sl Security /ms:1073741824
wevtutil sl System /ms:268435456
wevtutil sl Application /ms:268435456
wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true /ms:268435456
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true

# Hunt in the logs
# New users / group changes / tasks / services / log cleared in the last hour
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720,4722,4724,4728,4732,4756,4698,4697,1102;StartTime=(Get-Date).AddHours(-1)} -EA 0 |
    Select-Object TimeCreated,Id,Message | Format-List
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddHours(-1)} -EA 0 | Select-Object TimeCreated,Message | Format-List

# Top source IPs of failed logons (last 30 min)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddMinutes(-30)} -EA 0 | ForEach-Object {
    ([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'IpAddress' | ForEach-Object '#text'
} | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 Count,Name

# Successful remote logons (type 3 = network, 10 = RDP)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddMinutes(-30)} -EA 0 | ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{ Time = $_.TimeCreated; Type = ($d | Where-Object Name -eq 'LogonType').'#text'; User = ($d | Where-Object Name -eq 'TargetUserName').'#text'; IP = ($d | Where-Object Name -eq 'IpAddress').'#text' }
} | Where-Object Type -in '3','10' | Format-Table -AutoSize
#endregion

#region 8.4 Sysmon (if the rules allow extra tools)

# .\sysmon64.exe -accepteula -i .\sysmonconfig.xml
# Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50
#endregion

###############################################################################
# TIER 9 - MAINTAIN AND RECOVER
###############################################################################
#region 9.x Re-baseline, backup, verify

# After hardening is done, record the "good" listening ports (Sweep compares against this)
Get-NetTCPConnection -State Listen | ForEach-Object { $_.LocalPort } | Sort-Object -Unique | Set-Content C:\Blue\baseline_ports.txt

# Fresh backups of your hardened state
netsh advfirewall export C:\Blue\fw_hardened.wfw
secedit /export /cfg C:\Blue\secpol_hardened.cfg
Backup-GPO -All -Path C:\Blue\GPO                       # [DC]

# Every 15-30 minutes:
Sweep
Test-Scored

# Send a test email (replace addresses)
Send-MailMessage -SmtpServer localhost -Port 25 -From 'a@yourdomain.local' -To 'b@yourdomain.local' -Subject 'test' -Body 'test'

# A scored service is down? Restart it:
# Restart-Service -Name MSExchangeTransport -Force
# Get-Service MSExchange*,hMailServer,W3SVC,DNS,NTDS,Netlogon -EA 0 | Select-Object Name,Status
#endregion
