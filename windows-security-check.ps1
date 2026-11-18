<#
.SYNOPSIS
    Read-only security check for a Windows computer.

.DESCRIPTION
    Reviews seven basic security points and prints a summary marked as
    [OK], [WARN], [INFO] or [SKIP]. It also saves a simple HTML report.

    The script only READS information. It never changes any setting.

    Checks:
      1. Microsoft Defender is on and its signatures are up to date
      2. Windows Firewall is on in all profiles
      3. Date of the last installed Windows update
      4. Members of the local Administrators group
      5. Guest account is disabled
      6. Failed sign-ins (event 4625)          - needs administrator
      7. Critical and error events (System and Application logs)

.PARAMETER Days
    How many days back to look in the event logs. Default: 7.

.PARAMETER ReportPath
    Where to save the HTML report. Default: current folder.

.EXAMPLE
    .\windows-security-check.ps1

.EXAMPLE
    .\windows-security-check.ps1 -Days 3 -ReportPath C:\Temp\report.html
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$Days = 7,

    [string]$ReportPath = (Join-Path (Get-Location) ("security-report-{0}-{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Settings (limits used to decide between OK and WARN)
# ---------------------------------------------------------------------------
$MaxSignatureAgeDays = 3     # Defender signatures older than this -> WARN
$MaxUpdateAgeDays    = 30    # Last update older than this -> WARN
$MaxAdmins           = 2     # More admins than this -> WARN
$FailedSignInLimit   = 10    # This many failed sign-ins or more -> WARN

$since   = (Get-Date).AddDays(-$Days)
$results = New-Object System.Collections.Generic.List[object]

# Some checks (like the Security log) only work as administrator
$currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin     = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Saves the result of one check
function Add-Result {
    param(
        [string]$Check,
        [ValidateSet('OK', 'WARN', 'INFO', 'SKIP')][string]$Status,
        [string]$Summary,
        [string[]]$Details = @()
    )
    $results.Add([pscustomobject]@{
        Check   = $Check
        Status  = $Status
        Summary = $Summary
        Details = $Details
    })
}

# Runs one check. If it fails, the script goes on with the next one.
function Invoke-Check {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
    } catch {
        Add-Result $Name 'SKIP' 'Could not run this check.' @($_.Exception.Message)
    }
}

# Get-WinEvent throws an error when there are no events. Here that just means "zero events".
function Get-RecentEvents {
    param([hashtable]$Filter)
    try {
        return @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
}

# Reads one field (for example "TargetUserName") from the event details
function Get-EventField {
    param($LogEvent, [string]$Field)
    $xml  = [xml]$LogEvent.ToXml()
    $data = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Field }
    if ($data) { return $data.InnerText }
    return ''
}

# First line of the event message, cut to 120 characters
function Get-ShortMessage {
    param($LogEvent)
    $msg = $LogEvent.Message
    if ([string]::IsNullOrWhiteSpace($msg)) { return '(no description available)' }
    $line = ($msg -split "`r?`n")[0].Trim()
    if ($line.Length -gt 120) { $line = $line.Substring(0, 117) + '...' }
    return $line
}

# ---------------------------------------------------------------------------
# 1. Microsoft Defender
# ---------------------------------------------------------------------------
Invoke-Check 'Microsoft Defender' {
    $mp = Get-MpComputerStatus
    $details = @(
        "Antivirus enabled: $($mp.AntivirusEnabled)",
        "Real-time protection: $($mp.RealTimeProtectionEnabled)",
        "Signature age: $($mp.AntivirusSignatureAge) day(s) (version $($mp.AntivirusSignatureVersion))"
    )

    if (-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) {
        Add-Result 'Microsoft Defender' 'WARN' 'Defender or its real-time protection is turned off.' $details
    } elseif ($mp.AntivirusSignatureAge -gt $MaxSignatureAgeDays) {
        Add-Result 'Microsoft Defender' 'WARN' "Signatures are $($mp.AntivirusSignatureAge) days old." $details
    } else {
        Add-Result 'Microsoft Defender' 'OK' 'Defender is on and up to date.' $details
    }
}

# ---------------------------------------------------------------------------
# 2. Windows Firewall
# ---------------------------------------------------------------------------
Invoke-Check 'Windows Firewall' {
    $profiles = @(Get-NetFirewallProfile)
    $details  = @($profiles | ForEach-Object { "$($_.Name): $($_.Enabled)" })
    # "Enabled" can be True, False or NotConfigured, so we compare it as text
    $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' })

    if ($off.Count -gt 0) {
        $names = ($off | ForEach-Object { $_.Name }) -join ', '
        Add-Result 'Windows Firewall' 'WARN' "Firewall is off in: $names." $details
    } else {
        Add-Result 'Windows Firewall' 'OK' 'Firewall is on in all profiles.' $details
    }
}

# ---------------------------------------------------------------------------
# 3. Windows updates
# ---------------------------------------------------------------------------
Invoke-Check 'Windows Update' {
    $hotfixes = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)

    if ($hotfixes.Count -eq 0) {
        Add-Result 'Windows Update' 'WARN' 'No installed updates were found.'
        return
    }

    $last    = $hotfixes[0]
    $age     = ((Get-Date) - $last.InstalledOn).Days
    $details = @($hotfixes | Select-Object -First 5 | ForEach-Object {
        "$($_.HotFixID) - $($_.InstalledOn.ToString('yyyy-MM-dd')) - $($_.Description)"
    })

    if ($age -gt $MaxUpdateAgeDays) {
        Add-Result 'Windows Update' 'WARN' "Last update was installed $age days ago." $details
    } else {
        Add-Result 'Windows Update' 'OK' "Last update was installed $age day(s) ago ($($last.HotFixID))." $details
    }
}

# ---------------------------------------------------------------------------
# 4. Local administrators
# ---------------------------------------------------------------------------
Invoke-Check 'Local administrators' {
    # S-1-5-32-544 is the Administrators group in any language
    # (it is called "Administradores" on a Spanish Windows)
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
            "$($_.Name) ($($_.ObjectClass), $($_.PrincipalSource))"
        })
    } catch {
        # Known problem: Get-LocalGroupMember fails if the group has deleted or cloud accounts.
        # In that case we ask WMI/CIM instead.
        $group  = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
        $admins = @(Get-CimAssociatedInstance -InputObject $group -Association Win32_GroupUser |
            ForEach-Object { "$($_.Domain)\$($_.Name)" })
    }

    # The built-in Administrator account always has a SID that ends in -500
    $builtIn = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    if ($builtIn -and $builtIn.Enabled) {
        Add-Result 'Local administrators' 'WARN' "The built-in '$($builtIn.Name)' account is enabled." $admins
    } elseif ($admins.Count -gt $MaxAdmins) {
        Add-Result 'Local administrators' 'WARN' "$($admins.Count) admin accounts. Check if all of them need it." $admins
    } else {
        Add-Result 'Local administrators' 'INFO' "$($admins.Count) admin account(s)." $admins
    }
}

# ---------------------------------------------------------------------------
# 5. Guest account
# ---------------------------------------------------------------------------
Invoke-Check 'Guest account' {
    # The Guest account always has a SID that ends in -501
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }

    if (-not $guest) {
        Add-Result 'Guest account' 'INFO' 'There is no Guest account on this computer.'
    } elseif ($guest.Enabled) {
        Add-Result 'Guest account' 'WARN' "The Guest account ('$($guest.Name)') is enabled."
    } else {
        Add-Result 'Guest account' 'OK' "The Guest account ('$($guest.Name)') is disabled."
    }
}

# ---------------------------------------------------------------------------
# 6. Failed sign-ins (Security log, event 4625)
# ---------------------------------------------------------------------------
Invoke-Check 'Failed sign-ins' {
    if (-not $isAdmin) {
        Add-Result 'Failed sign-ins' 'SKIP' 'Run PowerShell as administrator to read the Security log.'
        return
    }

    $failed = @(Get-RecentEvents @{ LogName = 'Security'; Id = 4625; StartTime = $since })

    if ($failed.Count -eq 0) {
        Add-Result 'Failed sign-ins' 'OK' "No failed sign-ins in the last $Days day(s)."
        return
    }

    # Turn each event into a small object with the user and the source IP
    $attempts = $failed | ForEach-Object {
        [pscustomobject]@{
            User = Get-EventField $_ 'TargetUserName'
            IP   = Get-EventField $_ 'IpAddress'
        }
    }

    $details = @($attempts | Group-Object User, IP | Sort-Object Count -Descending |
        Select-Object -First 5 | ForEach-Object {
            "$($_.Count) attempt(s) - user/IP: $($_.Name)"
        })

    if ($failed.Count -ge $FailedSignInLimit) {
        Add-Result 'Failed sign-ins' 'WARN' "$($failed.Count) failed sign-ins in $Days day(s). Someone may be guessing passwords." $details
    } else {
        Add-Result 'Failed sign-ins' 'INFO' "$($failed.Count) failed sign-in(s) in $Days day(s)." $details
    }
}

# ---------------------------------------------------------------------------
# 7. Critical and error events (System and Application logs)
# ---------------------------------------------------------------------------
Invoke-Check 'Critical and error events' {
    # Level 1 = Critical, Level 2 = Error
    $events   = @(Get-RecentEvents @{ LogName = 'System', 'Application'; Level = 1, 2; StartTime = $since })
    $critical = @($events | Where-Object { $_.Level -eq 1 })
    $errors   = $events.Count - $critical.Count

    if ($events.Count -eq 0) {
        Add-Result 'Critical and error events' 'OK' "No critical or error events in the last $Days day(s)."
        return
    }

    $details = @()

    # The most recent critical events
    foreach ($e in ($critical | Sort-Object TimeCreated -Descending | Select-Object -First 10)) {
        $details += "CRITICAL $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm')) - $($e.ProviderName) (ID $($e.Id)) - $(Get-ShortMessage $e)"
    }

    # Which programs cause the most errors
    $top = $events | Group-Object { "$($_.LogName) / $($_.ProviderName) (ID $($_.Id))" } |
        Sort-Object Count -Descending | Select-Object -First 5
    foreach ($g in $top) {
        $details += "Most frequent: $($g.Count)x $($g.Name)"
    }

    $summary = "$($critical.Count) critical and $errors error event(s) in $Days day(s)."
    if ($critical.Count -gt 0) {
        Add-Result 'Critical and error events' 'WARN' $summary $details
    } else {
        Add-Result 'Critical and error events' 'INFO' $summary $details
    }
}

# ---------------------------------------------------------------------------
# Show the results on screen
# ---------------------------------------------------------------------------
$colors = @{ OK = 'Green'; WARN = 'Yellow'; INFO = 'Cyan'; SKIP = 'DarkGray' }

Write-Host ''
Write-Host "Windows security check - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
if (-not $isAdmin) { Write-Host 'Tip: run as administrator to see all checks.' -ForegroundColor DarkGray }
Write-Host ''

foreach ($r in $results) {
    Write-Host ('[{0,-4}] ' -f $r.Status) -ForegroundColor $colors[$r.Status] -NoNewline
    Write-Host "$($r.Check): $($r.Summary)"
    foreach ($d in $r.Details) {
        Write-Host "       - $d" -ForegroundColor Gray
    }
}

$okCount   = @($results | Where-Object { $_.Status -eq 'OK' }).Count
$warnCount = @($results | Where-Object { $_.Status -eq 'WARN' }).Count
Write-Host ''
Write-Host "Summary: $okCount OK, $warnCount warning(s), $($results.Count) checks."

# ---------------------------------------------------------------------------
# Save the HTML report
# ---------------------------------------------------------------------------
function ConvertTo-SafeHtml([string]$Text) { [System.Net.WebUtility]::HtmlEncode($Text) }

$rows = foreach ($r in $results) {
    $detailList = ''
    if ($r.Details.Count -gt 0) {
        $items      = ($r.Details | ForEach-Object { "<li>$(ConvertTo-SafeHtml $_)</li>" }) -join ''
        $detailList = "<ul>$items</ul>"
    }
    "<tr><td><span class='badge $($r.Status.ToLower())'>$($r.Status)</span></td>" +
    "<td><strong>$(ConvertTo-SafeHtml $r.Check)</strong><br>$(ConvertTo-SafeHtml $r.Summary)$detailList</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security report - $(ConvertTo-SafeHtml $env:COMPUTERNAME)</title>
<style>
  body  { font-family: Segoe UI, Arial, sans-serif; margin: 2rem auto; max-width: 900px; padding: 0 1rem; color: #1f2328; background: #fff; }
  h1    { font-size: 1.5rem; margin-bottom: .25rem; }
  .meta { color: #59636e; margin-top: 0; }
  table { border-collapse: collapse; width: 100%; }
  td    { border-top: 1px solid #d1d9e0; padding: .75rem .5rem; vertical-align: top; }
  ul    { margin: .4rem 0 0; padding-left: 1.2rem; color: #59636e; font-size: .9rem; }
  .badge { display: inline-block; min-width: 3.2rem; text-align: center; padding: .15rem .4rem; border-radius: 4px; font-weight: 600; font-size: .8rem; }
  .ok   { background: #dafbe1; color: #116329; }
  .warn { background: #fff1c2; color: #7d4e00; }
  .info { background: #ddf4ff; color: #0550ae; }
  .skip { background: #eff2f5; color: #59636e; }
</style>
</head>
<body>
<h1>Windows security check</h1>
<p class="meta">Computer: $(ConvertTo-SafeHtml $env:COMPUTERNAME) &middot; Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; Last $Days day(s) &middot; Administrator: $isAdmin</p>
<p><strong>$okCount OK</strong>, <strong>$warnCount warning(s)</strong>, $($results.Count) checks.</p>
<table>
$($rows -join "`n")
</table>
<p class="meta">Read-only check. No settings were changed.</p>
</body>
</html>
"@

Set-Content -Path $ReportPath -Value $html -Encoding UTF8
Write-Host "HTML report saved to: $ReportPath"
