#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Blue-team Windows Server hardening in one script (PowerShell 5.1, Server 2016/2019/2022).

.DESCRIPTION
  Default run = DRY RUN: it audits the server and prints what it WOULD change. Nothing is modified.
  Add -Apply to make the changes. Every registry change is logged to an undo file, services and
  tasks that get disabled are logged, and the firewall is exported first, so -Rollback can undo it.

  Risky actions are OFF unless you ask for them with a switch (see below).

.EXAMPLE
  .\Harden-Server.ps1                    # dry run + audit (safe, changes nothing)
  .\Harden-Server.ps1 -Apply             # apply the safe hardening
  .\Harden-Server.ps1 -Apply -ResetPasswords -FirewallLockdown -QuarantineSuspicious
  .\Harden-Server.ps1 -Rollback          # undo registry/services/firewall/task changes

.NOTES
  EDIT THE $Config SECTION BELOW BEFORE RUNNING.
  Output folder: C:\Blue   (log, audit report, undo files, backups, new passwords)
#>
[CmdletBinding()]
param(
    [switch]$Apply,                    # actually make changes (otherwise dry run)
    [switch]$ResetPasswords,           # [RISKY] random new passwords for all enabled accounts (except protected + you)
    [switch]$FirewallLockdown,         # [RISKY] default-deny inbound, with a 10-minute auto-rollback safety net
    [switch]$QuarantineSuspicious,     # [RISKY] disable suspicious tasks/services, kill unsigned procs in user-writable dirs
    [switch]$DisableLegacyTLS,         # [RISKY] disable SSL3/TLS1.0/1.1 (reboot; can break old clients / scoring)
    [switch]$RequireLdapSigning,       # [RISKY] DC: require LDAP signing + channel binding
    [switch]$EnableLsaProtection,      # [RISKY] RunAsPPL (reboot; some drivers conflict)
    [switch]$DisableRDP,               # turn RDP off completely
    [switch]$RemoveDefenderExclusions, # remove ALL Defender exclusions (Exchange has legitimate ones)
    [switch]$InstallUpdates,           # install Windows updates (no automatic reboot)
    [switch]$AuditOnly,                # print audit findings only, skip the hardening plan
    [switch]$Rollback                  # undo what this script changed
)

###############################################################################
# CONFIG - EDIT THIS
###############################################################################
$Config = @{
    TeamIPs             = @()                 # management IPs allowed to RDP/WinRM, e.g. @('10.0.0.5','10.0.0.6')
    ProtectedAccounts   = @('scoreuser')      # scoring / service accounts: NEVER touched by password reset
    ExtraTCPPorts       = @()                 # extra scored TCP ports to keep open, e.g. @(21,3306)
    ExtraUDPPorts       = @()
    KeepServices        = @()                 # services you must NOT disable, e.g. @('Spooler','MSFTPSVC')
    RequireSmbSigning   = $true               # set $false if scoring clients cannot do SMB signing
    LockdownRollbackMin = 10                  # minutes before the firewall lockdown auto-reverts unless you cancel it
}

###############################################################################
# SETUP AND HELPERS
###############################################################################
$ErrorActionPreference = 'Continue'
$BlueDir     = 'C:\Blue'
New-Item -ItemType Directory -Force $BlueDir | Out-Null
$LogFile     = Join-Path $BlueDir 'harden.log'
$ReportFile  = Join-Path $BlueDir 'audit_report.txt'
$UndoFile    = Join-Path $BlueDir 'registry_undo.csv'
$SvcUndoFile = Join-Path $BlueDir 'changed_services.csv'
$TaskUndoFile= Join-Path $BlueDir 'disabled_tasks.txt'
$QuarLog     = Join-Path $BlueDir 'quarantine.log'
$script:Applied = 0; $script:Planned = 0; $script:Failed = 0; $script:Warnings = @()

function Log { param([string]$Msg)
    Add-Content -Path $LogFile -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Msg)
}
function Section { param([string]$Title)
    Write-Host ""; Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan; Write-Host ("=" * 78) -ForegroundColor Cyan
    Log "== $Title"
}
function Warn { param([string]$Msg)
    Write-Host "[WARN]    $Msg" -ForegroundColor Yellow; $script:Warnings += $Msg; Log "WARN $Msg"
}
function Step { param([string]$Name, [scriptblock]$Action)
    if (-not $Apply) { Write-Host "[DRY-RUN] $Name" -ForegroundColor DarkGray; $script:Planned++; return }
    try {
        $ErrorActionPreference = 'Stop'
        & $Action
        Write-Host "[APPLIED] $Name" -ForegroundColor Green; Log "APPLIED $Name"; $script:Applied++
    } catch {
        Write-Host "[FAILED]  $Name : $($_.Exception.Message)" -ForegroundColor Red; Log "FAILED $Name : $($_.Exception.Message)"; $script:Failed++
    }
}
function Report { param([string]$Title, $Data)
    $txt = ($Data | Format-List | Out-String).Trim()
    if ($txt) {
        Write-Host "`n--- $Title ---" -ForegroundColor Yellow; Write-Host $txt
        Add-Content $ReportFile "`n--- $Title ---`n$txt"
    }
}
# Registry write that records the old value so -Rollback can restore it
function Set-RegSafe { param($Path, $Name, $Value, $Type = 'DWord')
    $old = '<absent>'; $kind = ''
    if (Test-Path $Path) {
        $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $p) {
            $v = $p.$Name; $kind = (Get-Item $Path).GetValueKind($Name).ToString()
            if ($v -is [array]) { $old = ($v -join '|') } else { $old = "$v" }
        }
    }
    [pscustomobject]@{ Path = $Path; Name = $Name; Old = $old; Kind = $kind } | Export-Csv $UndoFile -Append -NoTypeInformation
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}
function Disable-Svc { param([string]$Name)
    $s = Get-Service $Name -ErrorAction SilentlyContinue
    if (-not $s) { return }
    "$Name,$($s.StartType),$($s.Status)" | Add-Content $SvcUndoFile
    Stop-Service $Name -Force -ErrorAction SilentlyContinue
    Set-Service $Name -StartupType Disabled
}
function New-Pw { param([int]$Length = 16)
    $chars = ([char[]](48..57)) + ([char[]](65..90)) + ([char[]](97..122)) + ([char[]]'!#$%*+-=?')
    -join (1..$Length | ForEach-Object { $chars | Get-Random })
}

###############################################################################
# ROLLBACK MODE
###############################################################################
if ($Rollback) {
    Section 'ROLLBACK'
    Unregister-ScheduledTask -TaskName 'BlueFirewallRollback' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path "$BlueDir\fw_original.wfw") { netsh advfirewall import "$BlueDir\fw_original.wfw" | Out-Null; Write-Host 'Firewall restored from C:\Blue\fw_original.wfw' -ForegroundColor Green }
    if (Test-Path $UndoFile) {
        $rows = @(Import-Csv $UndoFile); [array]::Reverse($rows)
        foreach ($r in $rows) {
            try {
                if ($r.Old -eq '<absent>') { Remove-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue }
                else {
                    $val = $r.Old
                    if ($r.Kind -eq 'DWord') { $val = [int]$val } elseif ($r.Kind -eq 'MultiString') { $val = @($r.Old -split '\|') }
                    New-ItemProperty -Path $r.Path -Name $r.Name -Value $val -PropertyType $r.Kind -Force | Out-Null
                }
            } catch { Write-Host "Could not restore $($r.Path)\$($r.Name)" -ForegroundColor Yellow }
        }
        Write-Host "Registry values restored ($($rows.Count))" -ForegroundColor Green
    }
    if (Test-Path $SvcUndoFile) {
        foreach ($line in Get-Content $SvcUndoFile) {
            $n, $start, $state = $line -split ','
            if ($start -in 'Automatic','Manual','Disabled') { Set-Service $n -StartupType $start -ErrorAction SilentlyContinue }
            if ($state -eq 'Running') { Start-Service $n -ErrorAction SilentlyContinue }
        }
        Write-Host 'Services restored' -ForegroundColor Green
    }
    if (Test-Path $TaskUndoFile) {
        foreach ($line in Get-Content $TaskUndoFile) {
            $path, $name = $line -split '\|'
            Enable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host 'Scheduled tasks re-enabled' -ForegroundColor Green
    }
    Write-Host "`nNOT rolled back: password resets, killed processes, Defender exclusion removals, uninstalled features." -ForegroundColor Yellow
    return
}

###############################################################################
# PREFLIGHT: DETECT WHAT THIS SERVER IS
###############################################################################
Start-Transcript -Path (Join-Path $BlueDir 'transcript.log') -Append | Out-Null
$os          = (Get-CimInstance Win32_OperatingSystem).Caption
$isDC        = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
$hasExchange = Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer'
$hasHMail    = [bool](Get-Service hMailServer -ErrorAction SilentlyContinue)
$hasSMTPSVC  = [bool](Get-Service SMTPSVC -ErrorAction SilentlyContinue)
$hasMail     = $hasExchange -or $hasHMail -or $hasSMTPSVC
$hasIIS      = [bool](Get-Service W3SVC -ErrorAction SilentlyContinue)
$hasDNS      = [bool](Get-Service DNS -ErrorAction SilentlyContinue)
if ($isDC) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue; Import-Module GroupPolicy -ErrorAction SilentlyContinue }

Section 'PREFLIGHT'
Write-Host "OS: $os"
Write-Host ("Roles detected -> DC:{0}  Exchange:{1}  hMailServer:{2}  IIS:{3}  DNS:{4}" -f $isDC,$hasExchange,$hasHMail,$hasIIS,$hasDNS)
Write-Host ("Mode: {0}" -f $(if ($Apply) { 'APPLY (changes WILL be made)' } else { 'DRY RUN (nothing will be changed)' })) -ForegroundColor $(if ($Apply) { 'Red' } else { 'Green' })

# Ports to keep open, built from detected roles + your extras
$tcpPorts = @(); $udpPorts = @()
if ($hasMail)               { $tcpPorts += 25,587,465,143,993,110,995 }
if ($hasIIS -or $hasExchange){ $tcpPorts += 80,443 }
if ($hasDNS)                { $tcpPorts += 53; $udpPorts += 53 }
$tcpPorts += $Config.ExtraTCPPorts; $udpPorts += $Config.ExtraUDPPorts
$tcpPorts = @($tcpPorts | Sort-Object -Unique); $udpPorts = @($udpPorts | Sort-Object -Unique)
Write-Host ("Service ports kept open -> TCP: {0}  UDP: {1}" -f ($tcpPorts -join ','), ($udpPorts -join ','))
$portsBefore = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.LocalPort } | Sort-Object -Unique)

if ($Apply -and -not (Test-Path "$BlueDir\fw_original.wfw")) {
    Section 'BACKUPS (first run only)'
    Step 'Export firewall config'      { netsh advfirewall export "$BlueDir\fw_original.wfw" | Out-Null }
    Step 'Export local security policy'{ secedit /export /cfg "$BlueDir\secpol_original.cfg" | Out-Null }
    Step 'Save service / task / user / port baselines' {
        Get-Service | Select-Object Name,Status,StartType | Export-Csv "$BlueDir\services_baseline.csv" -NoTypeInformation
        Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Export-Csv "$BlueDir\tasks_baseline.csv" -NoTypeInformation
        Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled | Export-Csv "$BlueDir\localusers_baseline.csv" -NoTypeInformation
        $portsBefore | Set-Content "$BlueDir\baseline_ports_before.txt"
        if ($isDC) {
            Get-ADUser -Filter * | Select-Object SamAccountName,Enabled | Export-Csv "$BlueDir\adusers_baseline.csv" -NoTypeInformation
            New-Item -ItemType Directory -Force "$BlueDir\GPO" | Out-Null; Backup-GPO -All -Path "$BlueDir\GPO" | Out-Null
        }
    }
}

###############################################################################
# AUDIT (READ-ONLY, ALWAYS RUNS) - things that need a human decision
###############################################################################
Section 'AUDIT: ACCOUNTS AND GROUPS (review these yourself)'
if ($isDC) {
    $grp = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Backup Operators','Account Operators','Server Operators','Print Operators','DnsAdmins','Remote Desktop Users'
    foreach ($g in $grp) { Report "Members of $g" (Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue | Select-Object SamAccountName,objectClass) }
    Report 'AD users created in the last 3 days' (Get-ADUser -Filter * -Properties whenCreated | Where-Object { $_.whenCreated -gt (Get-Date).AddDays(-3) } | Select-Object SamAccountName,whenCreated)
    Report 'AD users with a "description" (passwords sometimes hide here)' (Get-ADUser -Filter * -Properties Description | Where-Object Description | Select-Object SamAccountName,Description)
    Report 'Kerberoastable accounts (have an SPN)' (Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName)
    Report 'Unconstrained delegation' (@(Get-ADUser -Filter 'TrustedForDelegation -eq $true' | Select-Object -ExpandProperty SamAccountName) + @(Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Where-Object { $_.DistinguishedName -notmatch 'OU=Domain Controllers' } | Select-Object -ExpandProperty Name))
    $dn = (Get-ADDomain).DistinguishedName
    $repl = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'
    Report 'DCSync-capable ACEs on the domain root (only DCs/Admins belong here)' ((Get-Acl "AD:$dn").Access | Where-Object { "$($_.ObjectType)" -in $repl } | Select-Object IdentityReference,ActiveDirectoryRights)
    Report 'Recently modified GPOs' (Get-GPO -All | Sort-Object ModificationTime -Descending | Select-Object -First 8 DisplayName,ModificationTime)
} else {
    foreach ($g in 'Administrators','Remote Desktop Users','Backup Operators') { Report "Members of $g" (Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass) }
    Report 'Local users' (Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet)
}
if (Test-Path "$BlueDir\localusers_baseline.csv") {
    $new = Compare-Object (Import-Csv "$BlueDir\localusers_baseline.csv").Name (Get-LocalUser -ErrorAction SilentlyContinue).Name | Where-Object SideIndicator -eq '=>'
    Report 'NEW local users since baseline' ($new | Select-Object -ExpandProperty InputObject)
}

Section 'AUDIT: PERSISTENCE AND INTRUSION SIGNS'
Report 'Scheduled tasks outside \Microsoft\' (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    Select-Object TaskPath,TaskName,State,@{n='Run';e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ';'}})
Report 'Any task launching shells / LOLBins' (Get-ScheduledTask | Where-Object { $_.Actions.Execute -match 'powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin' } |
    Select-Object TaskPath,TaskName,@{n='Run';e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ';'}})
Report 'Services running from odd locations' (Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'powershell|cmd\.exe|\\Temp\\|\\Users\\|ProgramData|\\Public\\' -and $_.PathName -notmatch 'Windows Defender' } | Select-Object Name,StartName,PathName)
Report 'Run / RunOnce autostart entries' (@(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') |
    ForEach-Object { $k = $_; $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$k : $($_.Name) = $($_.Value)" } } })
Report 'Startup-folder items' (Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp','C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' -Force -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' | Select-Object FullName,LastWriteTime)
Report 'WMI event subscriptions (the default "SCM Event Log" ones are normal)' (Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | Select-Object __CLASS,Name)
$cmdHash = (Get-FileHash C:\Windows\System32\cmd.exe).Hash
Report 'Accessibility binaries that are replaced or unsigned (sticky-keys backdoor)' ('sethc','utilman','osk','narrator','magnify','displayswitch','atbroker' | ForEach-Object {
    $f = "C:\Windows\System32\$_.exe"; if (Test-Path $f) { $sig = (Get-AuthenticodeSignature $f).Status; if ((Get-FileHash $f).Hash -eq $cmdHash -or $sig -ne 'Valid') { "$f  signature=$sig  -> run: sfc /scannow" } } })
Report 'hosts file entries' (Get-Content C:\Windows\System32\drivers\etc\hosts | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() })
Report 'Non-default SMB shares' (Get-SmbShare | Where-Object { $_.Name -notin 'ADMIN$','C$','IPC$','NETLOGON','SYSVOL' -and $_.Name -notmatch '^[A-Z]\$$' } | Select-Object Name,Path)
Report 'Listening ports with their process' (Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalPort,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},@{n='Path';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} -Unique)
Report 'Outbound/established connections (non-loopback)' (Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } |
    Select-Object LocalPort,RemoteAddress,RemotePort,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}})
Report 'Unsigned processes running from user-writable folders' (Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match '\\(Temp|Users|ProgramData|Public)\\' -and $_.ProcessId -ne $PID } |
    Where-Object { (Get-AuthenticodeSignature $_.ExecutablePath -ErrorAction SilentlyContinue).Status -ne 'Valid' } | Select-Object ProcessId,Name,ExecutablePath,CommandLine)
Report 'Recently dropped executables/scripts (last 3 days)' (Get-ChildItem C:\Windows\Temp,C:\Users\*\AppData\Local\Temp,C:\ProgramData,C:\Users\Public -Recurse -Force -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.hta -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-3) | Select-Object FullName,LastWriteTime -First 40)
if ($hasIIS -or $hasExchange) {
    Report 'Recently modified web files (possible web shells)' (Get-ChildItem C:\inetpub,"$env:ExchangeInstallPath\FrontEnd\HttpProxy" -Recurse -Include *.aspx,*.asp,*.ashx,*.asmx,*.php,*.jsp -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 25 FullName,LastWriteTime,Length)
    Report 'Web files containing shell-like code' (Get-ChildItem C:\inetpub -Recurse -Include *.aspx,*.asp,*.ashx,*.php -ErrorAction SilentlyContinue |
        Select-String -Pattern 'eval\(','Process\.Start','cmd\.exe','FromBase64String','System\.Diagnostics\.Process','WScript\.Shell','Request\.Form\[' | Select-Object Path,LineNumber -Unique)
}
Report 'Defender exclusions (red team adds these to hide malware)' (Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension)
if (Test-Path "$BlueDir\tasks_baseline.csv") {
    Report 'NEW scheduled tasks since baseline' (Compare-Object (Import-Csv "$BlueDir\tasks_baseline.csv").TaskName (Get-ScheduledTask).TaskName | Where-Object SideIndicator -eq '=>' | Select-Object -ExpandProperty InputObject)
}
if (Test-Path "$BlueDir\services_baseline.csv") {
    Report 'NEW services since baseline' (Compare-Object (Import-Csv "$BlueDir\services_baseline.csv").Name (Get-Service).Name | Where-Object SideIndicator -eq '=>' | Select-Object -ExpandProperty InputObject)
}

if ($hasExchange) {
    Section 'AUDIT: EXCHANGE'
    if (-not (Get-Command Get-ReceiveConnector -ErrorAction SilentlyContinue)) { try { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop } catch {} }
    if (Get-Command Get-ReceiveConnector -ErrorAction SilentlyContinue) {
        Report 'Exchange build' (Get-ExchangeServer | Select-Object Name,AdminDisplayVersion)
        Report 'Receive connectors' (Get-ReceiveConnector | Select-Object Name,Bindings,RemoteIPRanges,PermissionGroups,AuthMechanism)
        Report 'OPEN RELAY: anonymous with Accept-Any-Recipient (fix: Remove-ADPermission -Identity "SERVER\Connector" -User "NT AUTHORITY\ANONYMOUS LOGON" -ExtendedRights ms-Exch-SMTP-Accept-Any-Recipient)' (Get-ReceiveConnector | Get-ADPermission | Where-Object { $_.ExtendedRights -like '*ms-Exch-SMTP-Accept-Any-Recipient*' -and -not $_.IsInherited } | Select-Object Identity,User)
        Report 'Transport rules' (Get-TransportRule | Select-Object Name,State,Priority,Description)
        Report 'Mailboxes with forwarding set' (Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress } | Select-Object Name,ForwardingAddress,ForwardingSmtpAddress)
        Report 'Inbox rules that forward/redirect/delete' (Get-Mailbox -ResultSize Unlimited | ForEach-Object { Get-InboxRule -Mailbox $_.Identity -ErrorAction SilentlyContinue } | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage } | Select-Object MailboxOwnerId,Name,ForwardTo,RedirectTo,DeleteMessage)
        Report 'ApplicationImpersonation holders (commonly abused)' (Get-ManagementRoleAssignment -Role ApplicationImpersonation -GetEffectiveUsers -ErrorAction SilentlyContinue | Select-Object Name,EffectiveUserName)
        Report 'Organization Management members' (Get-RoleGroupMember 'Organization Management' | Select-Object Name,RecipientType)
    } else { Warn 'Exchange cmdlets not available here. Re-run the audit from Exchange Management Shell.' }
}
if ($hasHMail) { Warn 'hMailServer detected: change the admin password and each mailbox password in hMailServer Administrator (not Windows accounts). Check Settings > Advanced > IP Ranges and Auto-ban.' }

if ($AuditOnly) { Write-Host "`nAudit saved to $ReportFile" -ForegroundColor Green; Stop-Transcript | Out-Null; return }

###############################################################################
# HARDENING PLAN (dry-run unless -Apply)
###############################################################################
Section 'TIER 1: ACCOUNTS AND PASSWORDS'
$neverTouch = @($Config.ProtectedAccounts) + 'krbtgt','Guest','DefaultAccount','WDAGUtilityAccount',$env:USERNAME
Step 'Disable Guest account' { if ($isDC) { Disable-ADAccount -Identity Guest } else { Disable-LocalUser -Name Guest } }
Step 'Password policy (len 12, complexity, history 24) + lockout (10 tries / 15 min)' {
    if ($isDC) {
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -MinPasswordLength 12 -ComplexityEnabled $true -PasswordHistoryCount 24 `
            -MaxPasswordAge 90.00:00:00 -MinPasswordAge 1.00:00:00 -LockoutThreshold 10 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00 -ReversibleEncryptionEnabled $false
    } else { net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:24 /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null }
}
if ($isDC) {
    Step 'Clear "password not required" flag on AD users' { Get-ADUser -Filter 'PasswordNotRequired -eq $true' | Set-ADUser -PasswordNotRequired $false }
    Step 'Require Kerberos pre-auth on all AD users (stops AS-REP roasting)' { Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Set-ADAccountControl -DoesNotRequirePreAuth $false }
    Step 'Set MachineAccountQuota to 0 (blocks rogue machine joins / noPac)' { Set-ADDomain -Identity (Get-ADDomain) -Replace @{ 'ms-DS-MachineAccountQuota' = '0' } }
}
if ($ResetPasswords) {
    Step "Reset ALL enabled account passwords (skipping: $($neverTouch -join ', '))" {
        $out = @()
        if ($isDC) { $users = Get-ADUser -Filter * | Where-Object { $_.Enabled -and $_.SamAccountName -notin $neverTouch } | ForEach-Object { $_.SamAccountName } }
        else       { $users = Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin $neverTouch } | ForEach-Object { $_.Name } }
        foreach ($u in $users) {
            $pw = New-Pw; $sec = ConvertTo-SecureString $pw -AsPlainText -Force
            if ($isDC) { Set-ADAccountPassword -Identity $u -Reset -NewPassword $sec } else { Set-LocalUser -Name $u -Password $sec }
            $out += [pscustomobject]@{ User = $u; Password = $pw }
        }
        $f = Join-Path $BlueDir 'new_passwords.csv'
        $out | Export-Csv $f -NoTypeInformation
        icacls $f /inheritance:r /grant:r 'Administrators:(F)' | Out-Null
        Write-Host "  -> $($out.Count) passwords written to $f (Administrators only). YOUR OWN account was not changed - change it manually." -ForegroundColor Yellow
    }
}

Section 'TIER 2: ATTACK SURFACE (firewall, services, remote access)'
Step 'Firewall ON for all profiles + dropped-packet logging' {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767 -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
}
Step "Create allow rules for service ports (TCP $($tcpPorts -join ',') / UDP $($udpPorts -join ',')) + ICMP echo" {
    Remove-NetFirewallRule -DisplayName 'BLUE *' -ErrorAction SilentlyContinue
    if ($tcpPorts.Count) { New-NetFirewallRule -DisplayName 'BLUE Allow service TCP' -Direction Inbound -Protocol TCP -LocalPort ($tcpPorts | ForEach-Object { "$_" }) -Action Allow -Profile Any | Out-Null }
    if ($udpPorts.Count) { New-NetFirewallRule -DisplayName 'BLUE Allow service UDP' -Direction Inbound -Protocol UDP -LocalPort ($udpPorts | ForEach-Object { "$_" }) -Action Allow -Profile Any | Out-Null }
    New-NetFirewallRule -DisplayName 'BLUE Allow ICMP echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null
    if ($isDC) { Get-NetFirewallRule -DisplayGroup 'Active Directory Domain Services','Kerberos Key Distribution Center','DNS Service','Core Networking' -ErrorAction SilentlyContinue | Enable-NetFirewallRule }
}
if ($Config.TeamIPs.Count) {
    Step "Restrict RDP and WinRM rules to team IPs ($($Config.TeamIPs -join ','))" {
        foreach ($g in 'Remote Desktop','Windows Remote Management') {
            Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $Config.TeamIPs
        }
    }
} else { Warn 'Config.TeamIPs is empty: RDP/WinRM firewall rules are NOT restricted, and -FirewallLockdown will be skipped.' }

if ($FirewallLockdown) {
    if (-not $Config.TeamIPs.Count) { Warn 'FirewallLockdown SKIPPED: set Config.TeamIPs first, otherwise you could lock yourself out.' }
    else {
        Step 'Disable broad built-in inbound rule groups (remote mgmt, WMI, discovery)' {
            Disable-NetFirewallRule -DisplayGroup 'Remote Service Management','Remote Event Log Management','Remote Scheduled Tasks Management','Windows Management Instrumentation (WMI)','Network Discovery','Remote Volume Management' -ErrorAction SilentlyContinue
        }
        Step "Schedule SAFETY NET: firewall reverts to allow in $($Config.LockdownRollbackMin) min unless you cancel it" {
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Allow"'
            $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($Config.LockdownRollbackMin)
            Register-ScheduledTask -TaskName 'BlueFirewallRollback' -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        }
        Step 'Default-DENY inbound on all profiles' { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow }
        if ($Apply) {
            Write-Host "`n  >>> VERIFY NOW: you still have access AND mail/web/DNS work. Then run:" -ForegroundColor Yellow
            Write-Host "      Unregister-ScheduledTask -TaskName BlueFirewallRollback -Confirm:`$false" -ForegroundColor Yellow
        }
    }
}

$svcList = 'Spooler','RemoteRegistry','TlntSvr','SNMP','upnphost','SSDPSRV','WebClient','Fax','bthserv','XblAuthManager','XblGameSave','XboxNetApiSvc','lltdsvc','RemoteAccess','MSFTPSVC'
foreach ($s in $svcList) {
    if ($Config.KeepServices -contains $s) { continue }
    if (Get-Service $s -ErrorAction SilentlyContinue) { Step "Stop + disable service $s" { Disable-Svc $s } }
}
Step 'Disable SMBv1 and remove Telnet/TFTP/SNMP/PowerShell-v2/SMB1 features' {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Uninstall-WindowsFeature FS-SMB1,Telnet-Client,TFTP-Client,SNMP-Service,PowerShell-V2 -ErrorAction SilentlyContinue | Out-Null
}
if ($DisableRDP) {
    Step 'Disable RDP completely' {
        Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1
        Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
    }
} else {
    Step 'RDP hardening: NLA required, TLS security layer, high encryption' {
        $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        Set-RegSafe $rdp UserAuthentication 1; Set-RegSafe $rdp SecurityLayer 2; Set-RegSafe $rdp MinEncryptionLevel 3
    }
}

Section 'TIER 3: EVICT FOOTHOLDS (unambiguous fixes)'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($b in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','atbroker.exe') {
    $k = "$ifeo\$b"
    if ((Test-Path $k) -and (Get-ItemProperty $k -ErrorAction SilentlyContinue).Debugger) {
        Step "Remove IFEO Debugger hijack on $b" { Set-RegSafe $k Debugger '' String; Remove-ItemProperty -Path $k -Name Debugger }
    }
}
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; $wlp = Get-ItemProperty $wl
if ($wlp.Shell -and $wlp.Shell -ne 'explorer.exe') { Step "Reset Winlogon Shell (was: $($wlp.Shell))" { Set-RegSafe $wl Shell 'explorer.exe' String } }
if ($wlp.Userinit -and $wlp.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Step "Reset Winlogon Userinit (was: $($wlp.Userinit))" { Set-RegSafe $wl Userinit 'C:\Windows\system32\userinit.exe,' String } }
$ai = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue).AppInit_DLLs
if ($ai) { Step "Clear AppInit_DLLs (was: $ai)" { Set-RegSafe 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' AppInit_DLLs '' String } }

if ($QuarantineSuspicious) {
    Step 'Disable (not delete) scheduled tasks outside \Microsoft\ that launch shells/LOLBins' {
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.Actions.Execute -match 'powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin' } | ForEach-Object {
            "$($_.TaskPath)|$($_.TaskName)" | Add-Content $TaskUndoFile
            "TASK disabled: $($_.TaskPath)$($_.TaskName)" | Add-Content $QuarLog
            Disable-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName | Out-Null
        }
    }
    Step 'Stop + disable services whose binary is in Temp/Users/ProgramData/Public' {
        Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '\\Temp\\|\\Users\\|ProgramData|\\Public\\' -and $_.PathName -notmatch 'Windows Defender' } | ForEach-Object {
            "SERVICE disabled: $($_.Name) $($_.PathName)" | Add-Content $QuarLog; Disable-Svc $_.Name
        }
    }
    Step 'Kill UNSIGNED processes running from Temp/Users/ProgramData/Public' {
        Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match '\\(Temp|Users|ProgramData|Public)\\' -and $_.ProcessId -ne $PID } | ForEach-Object {
            if ((Get-AuthenticodeSignature $_.ExecutablePath -ErrorAction SilentlyContinue).Status -ne 'Valid') {
                "PROCESS killed: $($_.ProcessId) $($_.ExecutablePath)" | Add-Content $QuarLog
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Section 'TIER 4: PATCHING AND DEFENDER'
if ($InstallUpdates) {
    Step 'Install Windows updates (no automatic reboot)' {
        try { Install-PackageProvider NuGet -Force | Out-Null; Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot }
        catch { UsoClient StartScan; UsoClient StartDownload; UsoClient StartInstall }
    }
} else { Write-Host '[SKIP]    Windows updates (use -InstallUpdates; remember reboots can interrupt scoring)' -ForegroundColor DarkGray }
Step 'Defender: real-time, behavior, script scanning, cloud, PUA, network protection ON' {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
}
Step 'Defender: update signatures + start quick scan in background' { Update-MpSignature -ErrorAction SilentlyContinue; Start-MpScan -ScanType QuickScan -AsJob | Out-Null }
if ($RemoveDefenderExclusions) {
    Step 'Remove ALL Defender exclusions' {
        $mp = Get-MpPreference
        $mp.ExclusionPath      | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionPath $_ }
        $mp.ExclusionProcess   | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionProcess $_ }
        $mp.ExclusionExtension | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ }
    }
}

Section 'TIER 5: SCORED SERVICES (IIS / DNS)'
if ($hasIIS) {
    Step 'IIS: directory browsing off on all sites, remove X-Powered-By header' {
        Import-Module WebAdministration
        Get-Website | ForEach-Object { Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath "IIS:\Sites\$($_.Name)" }
        Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders' -Name . -AtElement @{ name = 'X-Powered-By' } -ErrorAction SilentlyContinue
    }
}
if ($hasDNS) {
    Step 'DNS: block zone transfers, secure-only dynamic updates on AD-integrated zones' {
        Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object {
            Set-DnsServerPrimaryZone -Name $_.ZoneName -SecureSecondaries NoTransfer
            if ($_.IsDsIntegrated) { Set-DnsServerPrimaryZone -Name $_.ZoneName -DynamicUpdate Secure }
        }
    }
    Report 'DNS records to eyeball (MX/A/CNAME/TXT)' (Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -notlike '_msdcs*' } | ForEach-Object {
        $z = $_.ZoneName; Get-DnsServerResourceRecord -ZoneName $z | Where-Object RecordType -in 'MX','A','CNAME','TXT' | ForEach-Object { "$z : $($_.HostName) $($_.RecordType) $($_.RecordData.CimInstanceProperties.Value -join ' ')" } })
}
if ($DisableLegacyTLS) {
    Step 'Disable SSL2/SSL3/TLS1.0/TLS1.1, enable TLS1.2, force .NET strong crypto (REBOOT REQUIRED)' {
        $s = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        foreach ($p in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') { foreach ($r in 'Server','Client') { Set-RegSafe "$s\$p\$r" Enabled 0; Set-RegSafe "$s\$p\$r" DisabledByDefault 1 } }
        foreach ($r in 'Server','Client') { Set-RegSafe "$s\TLS 1.2\$r" Enabled 1; Set-RegSafe "$s\TLS 1.2\$r" DisabledByDefault 0 }
        foreach ($n in 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319','HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319') { Set-RegSafe $n SchUseStrongCrypto 1; Set-RegSafe $n SystemDefaultTlsVersions 1 }
    }
}

Section 'TIER 6: PROTOCOL AND CREDENTIAL HARDENING'
Step 'NTLMv2 only, no LM hashes, no anonymous SAM/share enumeration, no cleartext creds (WDigest)' {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-RegSafe $lsa LmCompatibilityLevel 5; Set-RegSafe $lsa NoLMHash 1; Set-RegSafe $lsa RestrictAnonymous 1
    Set-RegSafe $lsa RestrictAnonymousSAM 1; Set-RegSafe $lsa EveryoneIncludesAnonymous 0
    Set-RegSafe "$lsa\MSV1_0" NTLMMinClientSec 537395200; Set-RegSafe "$lsa\MSV1_0" NTLMMinServerSec 537395200
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0
}
if ($EnableLsaProtection) { Step 'Enable LSA protection (RunAsPPL, reboot required)' { Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL 1 } }
Step 'SMB: block null sessions' {
    $lm = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Set-RegSafe $lm RestrictNullSessAccess 1; Set-RegSafe $lm NullSessionShares @('') MultiString; Set-RegSafe $lm NullSessionPipes @('') MultiString
}
if ($Config.RequireSmbSigning) {
    Step 'SMB signing required (server + client)' {
        Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
        Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
    }
}
Step 'Disable LLMNR, mDNS, WPAD auto-discovery, NetBIOS over TCP/IP' {
    Set-RegSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' EnableMDNS 0
    Set-RegSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' DisableWpad 1
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null
}
Step 'UAC on, remote-UAC filter on, hide last user, 15-min inactivity lock, AutoPlay off, Remote Assistance off' {
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegSafe $sys EnableLUA 1; Set-RegSafe $sys ConsentPromptBehaviorAdmin 2; Set-RegSafe $sys LocalAccountTokenFilterPolicy 0
    Set-RegSafe $sys DontDisplayLastUserName 1; Set-RegSafe $sys InactivityTimeoutSecs 900
    Set-RegSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0
}
Step 'PrintNightmare mitigations (matters if Print Spooler stays enabled)' {
    $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    Set-RegSafe $pp NoWarningNoElevationOnInstall 0; Set-RegSafe $pp UpdatePromptSettings 0; Set-RegSafe $pp RestrictDriverInstallationToAdministrators 1
}
if ($isDC) {
    Step 'ZeroLogon enforcement (FullSecureChannelProtection)' { Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' FullSecureChannelProtection 1 }
    if ($RequireLdapSigning) {
        Step 'Require LDAP signing + channel binding (apps using unsigned LDAP binds will break)' {
            Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 2
            Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LdapEnforceChannelBinding 1
        }
    }
}

Section 'TIER 8: LOGGING AND DETECTION'
Step 'Advanced audit policy (logons, accounts, groups, process creation, Kerberos, shares, policy changes)' {
    Set-RegSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy 1
    foreach ($c in 'Logon','Special Logon','User Account Management','Security Group Management','Computer Account Management','Credential Validation',
                   'Kerberos Authentication Service','Kerberos Service Ticket Operations','Sensitive Privilege Use','File Share','Other Object Access Events',
                   'Directory Service Changes','Audit Policy Change','Authentication Policy Change','Security System Extension','Process Creation','Account Lockout') {
        auditpol /set /subcategory:"$c" /success:enable /failure:enable | Out-Null
    }
    auditpol /set /subcategory:"Logoff" /success:enable | Out-Null
}
Step 'Log command lines in process-creation events + PowerShell script-block logging + transcription' {
    Set-RegSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1
    $ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Set-RegSafe "$ps\ScriptBlockLogging" EnableScriptBlockLogging 1
    Set-RegSafe "$ps\Transcription" EnableTranscripting 1; Set-RegSafe "$ps\Transcription" EnableInvocationHeader 1
    Set-RegSafe "$ps\Transcription" OutputDirectory (Join-Path $BlueDir 'PSTranscripts') String
}
Step 'Enlarge event logs (Security 1 GB) so evidence is not overwritten' {
    wevtutil sl Security /ms:1073741824; wevtutil sl System /ms:268435456; wevtutil sl Application /ms:268435456
    wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true /ms:268435456; wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
}

###############################################################################
# SUMMARY AND POST-CHECK
###############################################################################
Section 'SUMMARY'
if ($Apply) {
    Write-Host ("Applied: {0}   Failed: {1}" -f $script:Applied, $script:Failed) -ForegroundColor $(if ($script:Failed) { 'Yellow' } else { 'Green' })
    Step 'Save post-hardening baseline + firewall/policy exports' {
        Get-NetTCPConnection -State Listen | ForEach-Object { $_.LocalPort } | Sort-Object -Unique | Set-Content "$BlueDir\baseline_ports.txt"
        netsh advfirewall export "$BlueDir\fw_hardened.wfw" | Out-Null; secedit /export /cfg "$BlueDir\secpol_hardened.cfg" | Out-Null
    } | Out-Null
    $portsAfter = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.LocalPort } | Sort-Object -Unique)
    $lost = @($portsBefore | Where-Object { $_ -notin $portsAfter })
    if ($lost.Count) { Write-Host "ALERT: ports that were listening before and are NOT now: $($lost -join ', ')  -> a scored service may be down. Check it, or run -Rollback." -ForegroundColor Red }
    else { Write-Host 'All previously listening ports are still listening.' -ForegroundColor Green }
    Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Select-Object Name,Status | Format-Table -AutoSize
} else {
    Write-Host ("DRY RUN complete: {0} change(s) would be made. Review above, edit `$Config, then re-run with -Apply." -f $script:Planned) -ForegroundColor Green
}
if ($script:Warnings.Count) { Write-Host "`nWarnings:" -ForegroundColor Yellow; $script:Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow } }
Write-Host @"

MANUAL FOLLOW-UPS (a script cannot decide these for you):
  1. Review the audit output / $ReportFile : remove unknown admins, rogue users, suspicious tasks, forwarding rules, web shells.
  2. Mail users: change mailbox passwords (hMailServer Administrator, or AD password for Exchange). Announce changes to your team.
  3. Test: send + receive an email, log in as a normal user, hit every scored port from another machine.
  4. Re-run with -AuditOnly every 15-30 minutes: it compares against your baseline and flags new tasks/services/users.
  5. Compromise confirmed on a DC? Reset krbtgt twice (hours apart) and the DSRM password (ntdsutil).
  6. NOTE: baselines capture the server as it is on your first -Apply. Anything red team already planted is in it, so review the audit FIRST.
Undo anything this script changed with:  .\Harden-Server.ps1 -Rollback
"@
Stop-Transcript | Out-Null
