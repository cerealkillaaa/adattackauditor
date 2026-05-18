[CmdletBinding()]
param(
    [string]$ConfigPath = ".\config.json",
    [switch]$OpenReport
)

$ErrorActionPreference = "Stop"

# =========================
# GLOBALS
# =========================

$Script:StartTime = Get-Date
$Script:ReportRoot = Join-Path $PSScriptRoot "Reports"
$Script:Findings = New-Object System.Collections.Generic.List[object]

# =========================
# UTILITY FUNCTIONS
# =========================

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "        AD ATTACK SURFACE AUDITOR v1.0.0" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $color = switch ($Level) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }

    Write-Host "[$Level] $Message" -ForegroundColor $color
}

function Ensure-ReportFolder {
    if (-not (Test-Path $Script:ReportRoot)) {
        New-Item -Path $Script:ReportRoot -ItemType Directory | Out-Null
    }
}

function Load-Config {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Status "Config file not found. Using default settings." "WARN"

        return [pscustomobject]@{
            StaleUserDays         = 90
            StaleComputerDays     = 90
            PasswordAgeDays       = 180
            IncludeDisabledUsers  = $false
            PrivilegedGroups      = @(
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins",
                "Administrators",
                "Account Operators",
                "Backup Operators",
                "Server Operators",
                "Print Operators"
            )
            ReportTitle           = "AD Attack Surface Audit"
        }
    }

    return Get-Content $Path -Raw | ConvertFrom-Json
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$ObjectType,
        [string]$ObjectName,
        [string]$SamAccountName,
        [string]$DistinguishedName,
        [string]$Issue,
        [string]$Recommendation,
        [int]$RiskScore
    )

    $Script:Findings.Add([pscustomobject]@{
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category          = $Category
        Severity          = $Severity
        ObjectType        = $ObjectType
        ObjectName        = $ObjectName
        SamAccountName    = $SamAccountName
        DistinguishedName = $DistinguishedName
        Issue             = $Issue
        Recommendation    = $Recommendation
        RiskScore         = $RiskScore
    })
}

function Get-SeverityClass {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { "sev-critical" }
        "High"     { "sev-high" }
        "Medium"   { "sev-medium" }
        "Low"      { "sev-low" }
        default    { "sev-info" }
    }
}

# =========================
# DATA COLLECTION
# =========================

function Get-AuditData {
    param($Config)

    Write-Status "Collecting AD users..."
    $users = Get-ADUser -Filter * -Properties `
        DisplayName,
        Enabled,
        PasswordNeverExpires,
        PasswordLastSet,
        LastLogonDate,
        AdminCount,
        ServicePrincipalName,
        TrustedForDelegation,
        TrustedToAuthForDelegation,
        DoesNotRequirePreAuth,
        CannotChangePassword,
        AccountExpirationDate,
        Manager,
        UserPrincipalName,
        MemberOf,
        WhenCreated

    Write-Status "Collecting AD computers..."
    $computers = Get-ADComputer -Filter * -Properties `
        Enabled,
        LastLogonDate,
        OperatingSystem,
        TrustedForDelegation,
        TrustedToAuthForDelegation,
        ServicePrincipalName,
        WhenCreated

    Write-Status "Collecting AD groups..."
    $groups = Get-ADGroup -Filter * -Properties `
        Members,
        ManagedBy,
        GroupScope,
        GroupCategory,
        WhenCreated

    return [pscustomobject]@{
        Users     = $users
        Computers = $computers
        Groups    = $groups
    }
}

# =========================
# AUDIT CHECKS
# =========================

function Test-PasswordNeverExpires {
    param($Users)

    foreach ($user in $Users) {
        if ($user.PasswordNeverExpires -eq $true -and $user.Enabled -eq $true) {
            Add-Finding `
                -Category "Account Security" `
                -Severity "High" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "Enabled user account has PasswordNeverExpires set." `
                -Recommendation "Require regular password rotation or migrate to stronger controls such as MFA and conditional access." `
                -RiskScore 8
        }
    }
}

function Test-StaleUsers {
    param($Users, [int]$StaleDays)

    $cutoff = (Get-Date).AddDays(-$StaleDays)

    foreach ($user in $Users) {
        if ($user.Enabled -eq $true -and $user.LastLogonDate -and $user.LastLogonDate -lt $cutoff) {
            Add-Finding `
                -Category "Stale Accounts" `
                -Severity "Medium" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "Enabled user has not logged in since $($user.LastLogonDate)." `
                -Recommendation "Review account ownership and disable if no longer required." `
                -RiskScore 5
        }

        if ($user.Enabled -eq $true -and -not $user.LastLogonDate) {
            Add-Finding `
                -Category "Stale Accounts" `
                -Severity "Medium" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "Enabled user has no recorded LastLogonDate." `
                -Recommendation "Confirm whether this account is unused, newly created, or a service account." `
                -RiskScore 5
        }
    }
}

function Test-StaleComputers {
    param($Computers, [int]$StaleDays)

    $cutoff = (Get-Date).AddDays(-$StaleDays)

    foreach ($computer in $Computers) {
        if ($computer.Enabled -eq $true -and $computer.LastLogonDate -and $computer.LastLogonDate -lt $cutoff) {
            Add-Finding `
                -Category "Stale Computers" `
                -Severity "Medium" `
                -ObjectType "Computer" `
                -ObjectName $computer.Name `
                -SamAccountName $computer.SamAccountName `
                -DistinguishedName $computer.DistinguishedName `
                -Issue "Enabled computer has not logged in since $($computer.LastLogonDate)." `
                -Recommendation "Disable, remove, or investigate stale computer account." `
                -RiskScore 5
        }

        if ($computer.Enabled -eq $true -and -not $computer.LastLogonDate) {
            Add-Finding `
                -Category "Stale Computers" `
                -Severity "Low" `
                -ObjectType "Computer" `
                -ObjectName $computer.Name `
                -SamAccountName $computer.SamAccountName `
                -DistinguishedName $computer.DistinguishedName `
                -Issue "Enabled computer has no recorded LastLogonDate." `
                -Recommendation "Verify whether this system is active." `
                -RiskScore 3
        }
    }
}

function Test-PrivilegedUsers {
    param($PrivilegedGroups)

    foreach ($groupName in $PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop

            foreach ($member in $members) {
                Add-Finding `
                    -Category "Privilege Exposure" `
                    -Severity "High" `
                    -ObjectType $member.ObjectClass `
                    -ObjectName $member.Name `
                    -SamAccountName $member.SamAccountName `
                    -DistinguishedName $member.DistinguishedName `
                    -Issue "Object is a member of privileged group: $groupName." `
                    -Recommendation "Verify this privileged membership is required and approved." `
                    -RiskScore 8
            }
        }
        catch {
            Write-Status "Could not read privileged group: $groupName" "WARN"
        }
    }
}

function Test-AdminCountUsers {
    param($Users)

    foreach ($user in $Users) {
        if ($user.AdminCount -eq 1) {
            Add-Finding `
                -Category "Privilege Exposure" `
                -Severity "Medium" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "User has AdminCount=1, indicating current or historical privileged status." `
                -Recommendation "Review privileged history and reset AdminSDHolder inheritance if no longer privileged." `
                -RiskScore 6
        }
    }
}

function Test-DelegationRisk {
    param($Users, $Computers)

    foreach ($user in $Users) {
        if ($user.TrustedForDelegation -eq $true) {
            Add-Finding `
                -Category "Delegation Risk" `
                -Severity "Critical" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "User is trusted for unconstrained delegation." `
                -Recommendation "Remove unconstrained delegation. Use constrained delegation where absolutely required." `
                -RiskScore 10
        }

        if ($user.TrustedToAuthForDelegation -eq $true) {
            Add-Finding `
                -Category "Delegation Risk" `
                -Severity "High" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "User is trusted to authenticate for delegation." `
                -Recommendation "Review constrained delegation configuration and limit scope." `
                -RiskScore 8
        }
    }

    foreach ($computer in $Computers) {
        if ($computer.TrustedForDelegation -eq $true) {
            Add-Finding `
                -Category "Delegation Risk" `
                -Severity "Critical" `
                -ObjectType "Computer" `
                -ObjectName $computer.Name `
                -SamAccountName $computer.SamAccountName `
                -DistinguishedName $computer.DistinguishedName `
                -Issue "Computer is trusted for unconstrained delegation." `
                -Recommendation "Remove unconstrained delegation unless explicitly required." `
                -RiskScore 10
        }

        if ($computer.TrustedToAuthForDelegation -eq $true) {
            Add-Finding `
                -Category "Delegation Risk" `
                -Severity "High" `
                -ObjectType "Computer" `
                -ObjectName $computer.Name `
                -SamAccountName $computer.SamAccountName `
                -DistinguishedName $computer.DistinguishedName `
                -Issue "Computer is trusted to authenticate for delegation." `
                -Recommendation "Review constrained delegation configuration and limit scope." `
                -RiskScore 8
        }
    }
}

function Test-KerberoastableUsers {
    param($Users)

    foreach ($user in $Users) {
        if ($user.Enabled -eq $true -and $user.ServicePrincipalName) {
            Add-Finding `
                -Category "Kerberoasting Exposure" `
                -Severity "High" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "Enabled user account has SPNs configured and may be Kerberoastable." `
                -Recommendation "Use gMSA where possible, enforce long random passwords, and review SPN necessity." `
                -RiskScore 8
        }
    }
}

function Test-ASREPRoastableUsers {
    param($Users)

    foreach ($user in $Users) {
        if ($user.Enabled -eq $true -and $user.DoesNotRequirePreAuth -eq $true) {
            Add-Finding `
                -Category "AS-REP Roasting Exposure" `
                -Severity "Critical" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "User does not require Kerberos pre-authentication." `
                -Recommendation "Enable Kerberos pre-authentication unless there is a documented exception." `
                -RiskScore 10
        }
    }
}

function Test-UsersWithoutManagers {
    param($Users)

    foreach ($user in $Users) {
        if ($user.Enabled -eq $true -and -not $user.Manager) {
            Add-Finding `
                -Category "Identity Hygiene" `
                -Severity "Low" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "Enabled user has no manager assigned." `
                -Recommendation "Assign a manager to improve ownership, access review, and offboarding workflows." `
                -RiskScore 2
        }
    }
}

function Test-EmptyGroups {
    param($Groups)

    foreach ($group in $Groups) {
        if (-not $group.Members -or $group.Members.Count -eq 0) {
            Add-Finding `
                -Category "Group Hygiene" `
                -Severity "Low" `
                -ObjectType "Group" `
                -ObjectName $group.Name `
                -SamAccountName $group.SamAccountName `
                -DistinguishedName $group.DistinguishedName `
                -Issue "Group has no members." `
                -Recommendation "Review and remove unused groups if no longer required." `
                -RiskScore 2
        }
    }
}

function Test-OldPasswords {
    param($Users, [int]$PasswordAgeDays)

    $cutoff = (Get-Date).AddDays(-$PasswordAgeDays)

    foreach ($user in $Users) {
        if ($user.Enabled -eq $true -and $user.PasswordLastSet -and $user.PasswordLastSet -lt $cutoff) {
            Add-Finding `
                -Category "Password Hygiene" `
                -Severity "Medium" `
                -ObjectType "User" `
                -ObjectName $user.Name `
                -SamAccountName $user.SamAccountName `
                -DistinguishedName $user.DistinguishedName `
                -Issue "Password was last set on $($user.PasswordLastSet)." `
                -Recommendation "Review password policy, especially for privileged and service accounts." `
                -RiskScore 5
        }
    }
}

function Test-DisabledPrivilegedUsers {
    param($PrivilegedGroups)

    foreach ($groupName in $PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop |
                Where-Object { $_.ObjectClass -eq "user" }

            foreach ($member in $members) {
                $user = Get-ADUser -Identity $member.SamAccountName -Properties Enabled

                if ($user.Enabled -eq $false) {
                    Add-Finding `
                        -Category "Privilege Hygiene" `
                        -Severity "Medium" `
                        -ObjectType "User" `
                        -ObjectName $user.Name `
                        -SamAccountName $user.SamAccountName `
                        -DistinguishedName $user.DistinguishedName `
                        -Issue "Disabled user remains in privileged group: $groupName." `
                        -Recommendation "Remove disabled accounts from privileged groups." `
                        -RiskScore 6
                }
            }
        }
        catch {
            Write-Status "Could not evaluate disabled privileged users in $groupName" "WARN"
        }
    }
}

# =========================
# REPORTING
# =========================

function Export-CsvReport {
    param([string]$BaseName)

    $csvPath = Join-Path $Script:ReportRoot "$BaseName.csv"
    $Script:Findings | Sort-Object RiskScore -Descending | Export-Csv -Path $csvPath -NoTypeInformation
    return $csvPath
}

function Export-HtmlReport {
    param(
        [string]$BaseName,
        [string]$Title
    )

    $htmlPath = Join-Path $Script:ReportRoot "$BaseName.html"

    $total = $Script:Findings.Count
    $critical = ($Script:Findings | Where-Object Severity -eq "Critical").Count
    $high = ($Script:Findings | Where-Object Severity -eq "High").Count
    $medium = ($Script:Findings | Where-Object Severity -eq "Medium").Count
    $low = ($Script:Findings | Where-Object Severity -eq "Low").Count
    $riskTotal = ($Script:Findings | Measure-Object RiskScore -Sum).Sum

    $rows = foreach ($finding in ($Script:Findings | Sort-Object RiskScore -Descending)) {
        $class = Get-SeverityClass -Severity $finding.Severity

        "<tr>
            <td><span class='$class'>$($finding.Severity)</span></td>
            <td>$($finding.Category)</td>
            <td>$($finding.ObjectType)</td>
            <td>$($finding.ObjectName)</td>
            <td>$($finding.SamAccountName)</td>
            <td>$($finding.Issue)</td>
            <td>$($finding.Recommendation)</td>
            <td>$($finding.RiskScore)</td>
        </tr>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>$Title</title>
    <style>
        body {
            background: #0f172a;
            color: #e5e7eb;
            font-family: Segoe UI, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }

        h1 {
            color: #38bdf8;
            margin-bottom: 5px;
        }

        .subtitle {
            color: #94a3b8;
            margin-bottom: 30px;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }

        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 14px;
            padding: 18px;
            box-shadow: 0 10px 25px rgba(0,0,0,.25);
        }

        .card-title {
            color: #94a3b8;
            font-size: 13px;
            margin-bottom: 8px;
        }

        .card-value {
            font-size: 28px;
            font-weight: 700;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
            border-radius: 14px;
            overflow: hidden;
        }

        th {
            background: #020617;
            color: #38bdf8;
            text-align: left;
            padding: 12px;
            font-size: 13px;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #334155;
            vertical-align: top;
            font-size: 13px;
        }

        tr:hover {
            background: #263449;
        }

        .sev-critical {
            background: #7f1d1d;
            color: #fecaca;
            padding: 5px 9px;
            border-radius: 999px;
            font-weight: 700;
        }

        .sev-high {
            background: #9a3412;
            color: #fed7aa;
            padding: 5px 9px;
            border-radius: 999px;
            font-weight: 700;
        }

        .sev-medium {
            background: #854d0e;
            color: #fef3c7;
            padding: 5px 9px;
            border-radius: 999px;
            font-weight: 700;
        }

        .sev-low {
            background: #164e63;
            color: #cffafe;
            padding: 5px 9px;
            border-radius: 999px;
            font-weight: 700;
        }

        .footer {
            margin-top: 25px;
            color: #64748b;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <h1>$Title</h1>
    <div class="subtitle">
        Generated: $(Get-Date) |
        Runtime: $([math]::Round(((Get-Date) - $Script:StartTime).TotalSeconds, 2)) seconds
    </div>

    <div class="cards">
        <div class="card">
            <div class="card-title">Total Findings</div>
            <div class="card-value">$total</div>
        </div>
        <div class="card">
            <div class="card-title">Critical</div>
            <div class="card-value">$critical</div>
        </div>
        <div class="card">
            <div class="card-title">High</div>
            <div class="card-value">$high</div>
        </div>
        <div class="card">
            <div class="card-title">Medium</div>
            <div class="card-value">$medium</div>
        </div>
        <div class="card">
            <div class="card-title">Low</div>
            <div class="card-value">$low</div>
        </div>
        <div class="card">
            <div class="card-title">Risk Score</div>
            <div class="card-value">$riskTotal</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Type</th>
                <th>Name</th>
                <th>SAM</th>
                <th>Issue</th>
                <th>Recommendation</th>
                <th>Risk</th>
            </tr>
        </thead>
        <tbody>
            $($rows -join "`n")
        </tbody>
    </table>

    <div class="footer">
        AD Attack Surface Auditor v1.0.0 | Read-only assessment
    </div>
</body>
</html>
"@

    Set-Content -Path $htmlPath -Value $html -Encoding UTF8
    return $htmlPath
}

# =========================
# MAIN
# =========================

function Start-ADAttackSurfaceAudit {
    Write-Banner
    Ensure-ReportFolder

    Write-Status "Loading configuration..."
    $config = Load-Config -Path $ConfigPath

    Write-Status "Importing Active Directory module..."
    Import-Module ActiveDirectory

    $data = Get-AuditData -Config $config

    Write-Status "Running audit checks..."

    Test-PasswordNeverExpires -Users $data.Users
    Test-StaleUsers -Users $data.Users -StaleDays $config.StaleUserDays
    Test-StaleComputers -Computers $data.Computers -StaleDays $config.StaleComputerDays
    Test-PrivilegedUsers -PrivilegedGroups $config.PrivilegedGroups
    Test-AdminCountUsers -Users $data.Users
    Test-DelegationRisk -Users $data.Users -Computers $data.Computers
    Test-KerberoastableUsers -Users $data.Users
    Test-ASREPRoastableUsers -Users $data.Users
    Test-UsersWithoutManagers -Users $data.Users
    Test-EmptyGroups -Groups $data.Groups
    Test-OldPasswords -Users $data.Users -PasswordAgeDays $config.PasswordAgeDays
    Test-DisabledPrivilegedUsers -PrivilegedGroups $config.PrivilegedGroups

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $baseName = "AD-Attack-Surface-Audit-$timestamp"

    Write-Status "Exporting CSV report..."
    $csvPath = Export-CsvReport -BaseName $baseName

    Write-Status "Exporting HTML report..."
    $htmlPath = Export-HtmlReport -BaseName $baseName -Title $config.ReportTitle

    Write-Host ""
    Write-Status "Audit complete." "OK"
    Write-Host "CSV Report:  $csvPath"
    Write-Host "HTML Report: $htmlPath"
    Write-Host ""

    if ($OpenReport) {
        Start-Process $htmlPath
    }
}

Start-ADAttackSurfaceAudit