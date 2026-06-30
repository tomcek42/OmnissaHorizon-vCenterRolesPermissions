<#
.SYNOPSIS
    Creates the custom vCenter Server role for Omnissa App Volumes.
    Self-contained variant - runnable as a one-liner:

        irm https://raw.githubusercontent.com/tomcek42/AppVolumes-vCenter-Role/main/Invoke-AppVolumesRole.ps1 | iex

.DESCRIPTION
    This variant is intentionally standalone (no companion files required) so it
    can be executed in memory via 'irm <URL> | iex'. Missing values (vCenter
    server, role name, options) are prompted interactively and stored in a
    config.json so later runs can reuse them.

    Credentials are stored encrypted (Windows DPAPI, Export-Clixml). They are
    bound to the Windows user and machine that created them.

    Optionally the script can also:
      - create a local vCenter SSO service account (vsphere.local) with a strong
        generated password (requires the VMware.vSphere.SsoAdmin module), or use
        an existing principal, and
      - assign the role as a permission at the vCenter root (propagated).

    Location (default): the directory of the .ps1 file. When executed via
    'irm <URL> | iex' (no file present) the current working directory is used.

.PARAMETER Server
    vCenter server (FQDN). Overrides the value from config.json.

.PARAMETER Username
    Account used to sign in to vCenter (must be allowed to create roles/permissions
    and SSO users when creating a service account).

.PARAMETER RoleName
    Name of the role to create (default: AppVolumes).

.PARAMETER RoleDescription
    Description for the role.

.PARAMETER IncludeCryptographicOperations
    Adds the Cryptographer.* privileges (only needed when VM storage uses
    encryption policies).

.PARAMETER Overwrite
    Updates an existing role instead of failing.

.PARAMETER IgnoreCertificateErrors
    Sets the session certificate action to 'Ignore'.

.PARAMETER WorkingDirectory
    Storage location for config.json and the credential file. Default: the .ps1
    directory, or the current working directory when run via 'irm | iex'.

.PARAMETER SetupServiceAccount
    Creates/assigns a service account and assigns the role at the vCenter root.

.PARAMETER ServiceAccountMode
    'Create' creates a new SSO person user; 'AssignExisting' uses an existing
    principal.

.PARAMETER ServiceAccountName
    SSO user name (without domain) when ServiceAccountMode = Create.

.PARAMETER ServiceAccountDomain
    SSO domain for the created user (default: vsphere.local).

.PARAMETER ServiceAccountPrincipal
    Existing principal (e.g. 'DOMAIN\svc-appvolumes') when
    ServiceAccountMode = AssignExisting.

.PARAMETER ServiceAccountDescription
    Description for the created SSO user.

.PARAMETER PasswordLength
    Length of the generated password (minimum 18).

.PARAMETER NonInteractive
    Suppresses prompts. Missing required values then cause the script to fail.

.NOTES
    Note: 'irm | iex' cannot pass parameters; in that case missing values are
    prompted interactively. To use parameters, run the file directly
    (.\Invoke-AppVolumesRole.ps1 -Server ...) or via a script block:
        & ([scriptblock]::Create((irm <URL>))) -Server vcenter... -RoleName AppVolumes
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$Username,
    [string]$RoleName,
    [string]$RoleDescription,
    [switch]$IncludeCryptographicOperations,
    [switch]$Overwrite,
    [switch]$IgnoreCertificateErrors,
    [string]$WorkingDirectory,
    [string]$ConfigPath,
    [switch]$NonInteractive,

    # Service account / permission
    [switch]$SetupServiceAccount,
    [string]$ServiceAccountMode,    # 'Create' or 'AssignExisting' (validated in the body)
    [string]$ServiceAccountName,
    [string]$ServiceAccountDomain,
    [string]$ServiceAccountPrincipal,
    [string]$ServiceAccountDescription,
    [int]$PasswordLength = 18
)

$ErrorActionPreference = 'Stop'

# Force TLS 1.2 (important for downloads on Windows PowerShell 5.1)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# --- Privileges per Omnissa App Volumes Administration Guide -------------------
$BasePrivilegeIds = @(
    'System.Anonymous', 'System.View', 'System.Read'
    'Global.CancelTask'
    'Folder.Create', 'Folder.Delete'
    'Datastore.Browse', 'Datastore.DeleteFile', 'Datastore.FileManagement'
    'Datastore.AllocateSpace', 'Datastore.UpdateVirtualMachineFiles'
    'Host.Local.CreateVM', 'Host.Local.ReconfigVM', 'Host.Local.DeleteVM'
    'VirtualMachine.Inventory.Create', 'VirtualMachine.Inventory.CreateFromExisting'
    'VirtualMachine.Inventory.Register', 'VirtualMachine.Inventory.Delete'
    'VirtualMachine.Inventory.Unregister', 'VirtualMachine.Inventory.Move'
    'VirtualMachine.Interact.PowerOn', 'VirtualMachine.Interact.PowerOff', 'VirtualMachine.Interact.Suspend'
    'VirtualMachine.Config.AddExistingDisk', 'VirtualMachine.Config.AddNewDisk'
    'VirtualMachine.Config.RemoveDisk', 'VirtualMachine.Config.AddRemoveDevice'
    'VirtualMachine.Config.Settings', 'VirtualMachine.Config.Resource'
    'VirtualMachine.Config.AdvancedConfig'        # Missing from PowerCLI doc, added from GUI
    'VirtualMachine.Config.QueryUnownedFiles'     # Missing from PowerCLI doc, added from GUI
    'VirtualMachine.Provisioning.Customize', 'VirtualMachine.Provisioning.Clone'
    'VirtualMachine.Provisioning.PromoteDisks', 'VirtualMachine.Provisioning.CreateTemplateFromVM'
    'VirtualMachine.Provisioning.DeployTemplate', 'VirtualMachine.Provisioning.CloneTemplate'
    'VirtualMachine.Provisioning.MarkAsTemplate', 'VirtualMachine.Provisioning.MarkAsVM'
    'VirtualMachine.Provisioning.ReadCustSpecs', 'VirtualMachine.Provisioning.ModifyCustSpecs'
    'Resource.AssignVMToPool'
    'Task.Create'
    'Sessions.TerminateSession'
)
$CryptographicPrivilegeIds = @(
    'Cryptographer.Access'      # Direct Access
    'Cryptographer.AddDisk'     # Add Disk (missing from PowerCLI doc, added from GUI)
)

# --- Helper functions ---------------------------------------------------------
function Read-DefaultedValue {
    param([string]$Prompt, [string]$Default)
    if ($NonInteractive) { return $Default }
    $suffix = if ($Default) { " [$Default]" } else { '' }
    $value = Read-Host -Prompt "$Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    if ($NonInteractive) { return $Default }
    $hint = if ($Default) { '(Y/n)' } else { '(y/N)' }
    $value = Read-Host -Prompt "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return ($value -match '^(y|j)')
}

function New-StrongPassword {
    param([int]$Length = 18)
    if ($Length -lt 18) { $Length = 18 }
    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',  # upper (no I/O)
        'abcdefghijkmnpqrstuvwxyz',  # lower (no l/o)
        '23456789',                  # digits (no 0/1)
        '!@#$%^*-_=+'                 # specials
    )
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buffer = [byte[]]::new(1)
    $pick = {
        param($set)
        $rng.GetBytes($buffer)
        $set[[int]$buffer[0] % $set.Length]
    }
    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($s in $sets) { $chars.Add((& $pick $s)) }   # guarantee one of each class
    $allSet = -join $sets
    while ($chars.Count -lt $Length) { $chars.Add((& $pick $allSet)) }
    # Fisher-Yates shuffle so the guaranteed characters are not in fixed positions
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $rng.GetBytes($buffer)
        $j = [int]$buffer[0] % ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return (-join $chars)
}

function Write-Banner {
    param([string]$Title)
    $line = '=' * 64
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  " + $Title) -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "-- $Title " -ForegroundColor Cyan -NoNewline
    Write-Host ('-' * [Math]::Max(0, 60 - $Title.Length)) -ForegroundColor DarkCyan
}

function Write-Field {
    param([string]$Label, [string]$Value)
    Write-Host ("   {0,-16}: " -f $Label) -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor White
}

function Resolve-RequiredModule {
    param([string]$CheckName, [string]$InstallName)
    if (Get-Module -ListAvailable -Name $CheckName) {
        Write-Host "   [ OK ] $CheckName" -ForegroundColor Green
        return $true
    }
    Write-Host "   [MISS] $CheckName" -ForegroundColor Yellow
    if (-not $NonInteractive) {
        if (Read-YesNo -Prompt "          Install '$InstallName' now (Scope CurrentUser)?" -Default $true) {
            try {
                Install-Module -Name $InstallName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                if (Get-Module -ListAvailable -Name $CheckName) {
                    Write-Host "   [ OK ] Installed $CheckName" -ForegroundColor Green
                    return $true
                }
            }
            catch {
                Write-Host "   [FAIL] Install failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    Write-Host "          Install manually: Install-Module $InstallName -Scope CurrentUser" -ForegroundColor Yellow
    return $false
}

Write-Banner 'App Volumes - vCenter Role Setup'
Write-Section 'Configuration'

# --- Working directory and configuration --------------------------------------
# Prefer the directory of the .ps1 file (config/credential live next to the
# script). When run via 'irm <URL> | iex' there is no file -> fall back to the
# current working directory.
if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $WorkingDirectory = $PSScriptRoot
    }
    elseif (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        $WorkingDirectory = Split-Path -Parent $PSCommandPath
    }
    else {
        $WorkingDirectory = (Get-Location).Path
    }
}
if (-not (Test-Path -LiteralPath $WorkingDirectory)) {
    New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null
}

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path -Path $WorkingDirectory -ChildPath 'config.json'
}
$credentialPath = Join-Path -Path $WorkingDirectory -ChildPath 'vcenter-credential.xml'

Write-Host "Working directory: $WorkingDirectory" -ForegroundColor DarkGray

# Load existing config.json (as defaults)
$config = $null
if (Test-Path -LiteralPath $ConfigPath) {
    try { $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json }
    catch { Write-Host "Note: config.json unreadable, will be recreated ($($_.Exception.Message))." -ForegroundColor DarkYellow }
}

# Resolve values: parameter > config.json > interactive prompt
$cfgServer    = if ($config) { $config.vCenter.Server } else { $null }
$cfgUser      = if ($config) { $config.vCenter.Username } else { $null }
$cfgIgnore    = if ($config) { [bool]$config.vCenter.IgnoreCertificateErrors } else { $false }
$cfgRoleName  = if ($config) { $config.Role.Name } else { $null }
$cfgRoleDesc  = if ($config) { $config.Role.Description } else { $null }
$cfgCrypto    = if ($config) { [bool]$config.Role.IncludeCryptographicOperations } else { $false }
$cfgOverwrite = if ($config) { [bool]$config.Role.Overwrite } else { $false }

$cfgSvc          = if ($config) { $config.ServiceAccount } else { $null }
$cfgSvcEnabled   = if ($cfgSvc) { [bool]$cfgSvc.Enabled } else { $false }
$cfgSvcMode      = if ($cfgSvc -and $cfgSvc.Mode) { $cfgSvc.Mode } else { 'Create' }
$cfgSvcName      = if ($cfgSvc -and $cfgSvc.Name) { $cfgSvc.Name } else { 'svc-appvolumes' }
$cfgSvcDomain    = if ($cfgSvc -and $cfgSvc.Domain) { $cfgSvc.Domain } else { 'vsphere.local' }
$cfgSvcPrincipal = if ($cfgSvc) { $cfgSvc.Principal } else { '' }
$cfgSvcDesc      = if ($cfgSvc -and $cfgSvc.Description) { $cfgSvc.Description } else { 'App Volumes Manager service account' }
$cfgPwLen        = if ($cfgSvc -and $cfgSvc.PasswordLength) { [int]$cfgSvc.PasswordLength } else { 18 }

$viServer = if ($Server) { $Server } elseif ($cfgServer) { $cfgServer } else { Read-DefaultedValue -Prompt 'vCenter server (FQDN)' -Default $null }
if ([string]::IsNullOrWhiteSpace($viServer)) { throw 'No vCenter server provided.' }

$vcUser = if ($Username) { $Username } elseif ($cfgUser) { $cfgUser } else { Read-DefaultedValue -Prompt 'Username' -Default 'administrator@vsphere.local' }

$roleName = if ($RoleName) { $RoleName } elseif ($cfgRoleName) { $cfgRoleName } else { Read-DefaultedValue -Prompt 'Role name' -Default 'AppVolumes' }

$roleDescription = if ($PSBoundParameters.ContainsKey('RoleDescription')) { $RoleDescription }
                   elseif ($cfgRoleDesc) { $cfgRoleDesc }
                   else { Read-DefaultedValue -Prompt 'Role description' -Default 'Custom role for the Omnissa App Volumes Manager service account' }

$includeCrypto = if ($PSBoundParameters.ContainsKey('IncludeCryptographicOperations')) { [bool]$IncludeCryptographicOperations }
                 elseif ($config) { $cfgCrypto }
                 else { Read-YesNo -Prompt 'Include Cryptographic Operations (only for encrypted storage)?' -Default $false }

$ignoreCert = if ($PSBoundParameters.ContainsKey('IgnoreCertificateErrors')) { [bool]$IgnoreCertificateErrors }
              elseif ($config) { $cfgIgnore }
              else { Read-YesNo -Prompt 'Ignore certificate errors (self-signed certs)?' -Default $false }

$overwrite = if ($PSBoundParameters.ContainsKey('Overwrite')) { [bool]$Overwrite }
             elseif ($config) { $cfgOverwrite }
             else { $false }

# Service account settings
$svcEnabled = if ($PSBoundParameters.ContainsKey('SetupServiceAccount')) { [bool]$SetupServiceAccount }
              elseif ($config) { $cfgSvcEnabled }
              else { Read-YesNo -Prompt 'Set up a service account and assign the role at the vCenter root?' -Default $false }

$svcMode = $cfgSvcMode; $svcName = $cfgSvcName; $svcDomain = $cfgSvcDomain
$svcPrincipal = $cfgSvcPrincipal; $svcDesc = $cfgSvcDesc; $pwLen = $cfgPwLen

if ($svcEnabled) {
    if ($ServiceAccountMode) { $svcMode = $ServiceAccountMode }
    elseif ($cfgSvc -and $cfgSvc.Mode) { $svcMode = $cfgSvcMode }
    elseif (-not $NonInteractive) {
        Write-Host "   Service account mode:" -ForegroundColor Gray
        Write-Host "     [1] Create a new vCenter SSO user (vsphere.local)" -ForegroundColor White
        Write-Host "     [2] Assign an existing principal (e.g. an AD account)" -ForegroundColor White
        $ans = Read-DefaultedValue -Prompt "   Select" -Default '1'
        $svcMode = if ($ans -match '^\s*2' -or $ans -match '^[Aa]') { 'AssignExisting' } else { 'Create' }
    }
    if ($svcMode -notin @('Create', 'AssignExisting')) {
        throw "ServiceAccountMode must be 'Create' or 'AssignExisting' (got '$svcMode')."
    }

    if ($PSBoundParameters.ContainsKey('PasswordLength')) { $pwLen = $PasswordLength } elseif ($cfgPwLen) { $pwLen = $cfgPwLen }
    if ($pwLen -lt 18) { $pwLen = 18 }

    if ($svcMode -eq 'Create') {
        $svcName   = if ($ServiceAccountName) { $ServiceAccountName } elseif ($cfgSvc -and $cfgSvc.Name) { $cfgSvcName } else { Read-DefaultedValue -Prompt 'SSO service account name' -Default 'svc-appvolumes' }
        $svcDomain = if ($ServiceAccountDomain) { $ServiceAccountDomain } elseif ($cfgSvc -and $cfgSvc.Domain) { $cfgSvcDomain } else { Read-DefaultedValue -Prompt 'SSO domain' -Default 'vsphere.local' }
        $svcDesc   = if ($PSBoundParameters.ContainsKey('ServiceAccountDescription')) { $ServiceAccountDescription } elseif ($cfgSvc -and $cfgSvc.Description) { $cfgSvcDesc } else { Read-DefaultedValue -Prompt 'Service account description' -Default 'App Volumes Manager service account' }
        $svcPrincipal = "$svcDomain\$svcName"
    }
    else {
        $svcPrincipal = if ($ServiceAccountPrincipal) { $ServiceAccountPrincipal } elseif ($cfgSvcPrincipal) { $cfgSvcPrincipal } else { Read-DefaultedValue -Prompt "Existing principal (e.g. 'DOMAIN\svc-appvolumes')" -Default $null }
        if ([string]::IsNullOrWhiteSpace($svcPrincipal)) { throw 'AssignExisting mode requires a principal.' }
    }
}

# Write/update config.json (without secrets)
$configObject = [ordered]@{
    vCenter = [ordered]@{
        Server                  = $viServer
        Username                = $vcUser
        IgnoreCertificateErrors = $ignoreCert
    }
    Role = [ordered]@{
        Name                           = $roleName
        Description                    = $roleDescription
        IncludeCryptographicOperations = $includeCrypto
        Overwrite                      = $overwrite
    }
    ServiceAccount = [ordered]@{
        Enabled                = $svcEnabled
        Mode                   = $svcMode
        Name                   = $svcName
        Domain                 = $svcDomain
        Principal              = $svcPrincipal
        Description            = $svcDesc
        PasswordLength         = $pwLen
        AssignPermissionAtRoot = $true
    }
}
$configObject | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
Write-Host "Configuration saved: $ConfigPath" -ForegroundColor DarkGray

# --- Preflight: required modules ----------------------------------------------
Write-Section 'Required PowerShell modules'
$modulesOk = $true
if (-not (Resolve-RequiredModule -CheckName 'VMware.VimAutomation.Core' -InstallName 'VMware.PowerCLI')) { $modulesOk = $false }
if ($svcEnabled -and $svcMode -eq 'Create') {
    if (-not (Resolve-RequiredModule -CheckName 'VMware.vSphere.SsoAdmin' -InstallName 'VMware.vSphere.SsoAdmin')) { $modulesOk = $false }
}
if (-not $modulesOk) {
    throw 'One or more required modules are missing. Install them (see above) and re-run.'
}
Import-Module 'VMware.VimAutomation.Core' -ErrorAction Stop

$certAction = if ($ignoreCert) { 'Ignore' } else { 'Fail' }
Set-PowerCLIConfiguration -InvalidCertificateAction $certAction -Scope Session -Confirm:$false | Out-Null

# --- Credentials (encrypted) --------------------------------------------------
if (Test-Path -LiteralPath $credentialPath) {
    try { $credential = Import-Clixml -LiteralPath $credentialPath }
    catch { throw "Credential file '$credentialPath' could not be decrypted (bound to user/machine). Delete it and recreate. Details: $($_.Exception.Message)" }
    if (-not ($credential -is [System.Management.Automation.PSCredential])) {
        throw "File '$credentialPath' does not contain valid credentials. Delete it and recreate."
    }
    Write-Host "Loaded encrypted credentials ($($credential.UserName))." -ForegroundColor Cyan
}
else {
    if ($NonInteractive) { throw "No credential file present and NonInteractive is set: $credentialPath" }
    Write-Host "No credential file found - please enter credentials." -ForegroundColor Yellow
    $credential = Get-Credential -UserName $vcUser -Message "vCenter sign-in for $viServer"
    $credential | Export-Clixml -LiteralPath $credentialPath -Force
    Write-Host "Credentials stored encrypted: $credentialPath" -ForegroundColor Green
}

# --- Build privilege list -----------------------------------------------------
$privilegeIds = [System.Collections.Generic.List[string]]::new()
$BasePrivilegeIds | ForEach-Object { $privilegeIds.Add($_) }
if ($includeCrypto) {
    $CryptographicPrivilegeIds | ForEach-Object { $privilegeIds.Add($_) }
    Write-Host "Including Cryptographic Operations (+$($CryptographicPrivilegeIds.Count))." -ForegroundColor Cyan
}
else {
    Write-Host "Not including Cryptographic Operations." -ForegroundColor Cyan
}

# --- Summary ------------------------------------------------------------------
Write-Section 'Summary'
Write-Field 'vCenter'      $viServer
Write-Field 'User'         $vcUser
Write-Field 'Role'         $roleName
Write-Field 'Crypto ops'   $(if ($includeCrypto) { 'included' } else { 'excluded' })
Write-Field 'Ignore cert'  $(if ($ignoreCert) { 'yes' } else { 'no' })
if ($svcEnabled) {
    Write-Field 'Service acct' $(if ($svcMode -eq 'Create') { "create  $svcPrincipal" } else { "assign  $svcPrincipal" })
    Write-Field 'Permission'   'vCenter root (propagated)'
}
else {
    Write-Field 'Service acct' 'skipped'
}

# --- Connect and create the role ----------------------------------------------
$connection = $null
$ssoConnection = $null
try {
    Write-Host "Connecting to vCenter '$viServer' ..." -ForegroundColor Cyan
    $connection = Connect-VIServer -Server $viServer -Credential $credential -ErrorAction Stop

    $privileges = Get-VIPrivilege -Server $connection -Id $privilegeIds -ErrorAction Stop
    $resolvedIds = $privileges | Select-Object -ExpandProperty Id
    $missing = $privilegeIds | Where-Object { $resolvedIds -notcontains $_ }
    if ($missing) {
        throw "The following privilege IDs were not found on vCenter: $($missing -join ', ')"
    }
    Write-Host "Resolved all $($privilegeIds.Count) privileges." -ForegroundColor Green

    $existingRole = Get-VIRole -Server $connection -Name $roleName -ErrorAction SilentlyContinue
    if ($existingRole) {
        if (-not $overwrite) {
            throw "Role '$roleName' already exists. Use -Overwrite (or Role.Overwrite=true) to update it."
        }
        Write-Host "Role '$roleName' already exists - updating." -ForegroundColor Yellow
        Set-VIRole -Role $existingRole -AddPrivilege $privileges -Server $connection -ErrorAction Stop | Out-Null
        $resultRole = Get-VIRole -Server $connection -Name $roleName
    }
    else {
        Write-Host "Creating new role '$roleName' ..." -ForegroundColor Cyan
        $resultRole = New-VIRole -Name $roleName -Privilege $privileges -Server $connection -ErrorAction Stop
    }

    # Note: neither PowerCLI nor the vSphere API support setting a description on a
    # custom role, so the description is kept in config.json for documentation only.
    if (-not [string]::IsNullOrWhiteSpace($roleDescription)) {
        Write-Host "Role description recorded in config.json (vCenter does not accept role descriptions via PowerCLI)." -ForegroundColor DarkGray
    }

    $finalRole = Get-VIRole -Server $connection -Name $roleName
    Write-Host "Role '$($finalRole.Name)' now has $($finalRole.PrivilegeList.Count) privileges." -ForegroundColor Green

    # --- Optional: service account + permission -------------------------------
    if ($svcEnabled) {
        Write-Host ""
        Write-Host "Setting up service account (mode: $svcMode) ..." -ForegroundColor Cyan

        if ($svcMode -eq 'Create') {
            if (-not (Get-Module -ListAvailable -Name 'VMware.vSphere.SsoAdmin')) {
                throw "Creating an SSO account requires the VMware.vSphere.SsoAdmin module. Install it with: Install-Module VMware.vSphere.SsoAdmin -Scope CurrentUser"
            }
            Import-Module 'VMware.vSphere.SsoAdmin' -ErrorAction Stop

            $ssoParams = @{
                Server   = $viServer
                User     = $credential.UserName
                Password = $credential.GetNetworkCredential().Password
            }
            if ($ignoreCert) { $ssoParams['SkipCertificateCheck'] = $true }
            $ssoConnection = Connect-SsoAdminServer @ssoParams

            $existingUser = Get-SsoPersonUser -Name $svcName -Domain $svcDomain -Server $ssoConnection -ErrorAction SilentlyContinue
            if ($existingUser) {
                Write-Host "SSO user '$svcDomain\$svcName' already exists - keeping existing password." -ForegroundColor Yellow
            }
            else {
                $generatedPassword = New-StrongPassword -Length $pwLen
                New-SsoPersonUser -UserName $svcName -Password $generatedPassword -Description $svcDesc -Server $ssoConnection | Out-Null
                Write-Host "Created SSO user '$svcDomain\$svcName'." -ForegroundColor Green
                Write-Host ""
                Write-Host "  +------------------------------------------------------------+" -ForegroundColor Yellow
                Write-Host "  |                 SERVICE ACCOUNT PASSWORD                   |" -ForegroundColor Yellow
                Write-Host "  +------------------------------------------------------------+" -ForegroundColor Yellow
                Write-Host "    User    : $svcDomain\$svcName" -ForegroundColor White
                Write-Host -NoNewline "    Password: " -ForegroundColor White
                Write-Host " $generatedPassword " -ForegroundColor Black -BackgroundColor White
                Write-Host "    Shown only once - store it now; it is not saved anywhere." -ForegroundColor Yellow
                Write-Host ""
            }
        }

        # Assign the role at the vCenter root (propagated)
        $rootFolder = Get-Folder -Server $connection -NoRecursion -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $rootFolder) {
            $si = Get-View -Server $connection ServiceInstance
            $rootFolder = Get-VIObjectByVIView -Server $connection -MORef $si.Content.RootFolder
        }

        $existingPerm = Get-VIPermission -Server $connection -Entity $rootFolder -ErrorAction SilentlyContinue |
            Where-Object { $_.Principal -eq $svcPrincipal }
        if ($existingPerm) {
            Write-Host "Permission for '$svcPrincipal' already exists at the root - leaving it unchanged." -ForegroundColor Yellow
        }
        else {
            New-VIPermission -Server $connection -Entity $rootFolder -Principal $svcPrincipal -Role $finalRole -Propagate $true -ErrorAction Stop | Out-Null
            Write-Host "Assigned role '$roleName' to '$svcPrincipal' at the vCenter root (propagated)." -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
}
finally {
    if ($ssoConnection) {
        Disconnect-SsoAdminServer -Server $ssoConnection -ErrorAction SilentlyContinue
    }
    if ($connection) {
        Disconnect-VIServer -Server $connection -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Disconnected from '$viServer'." -ForegroundColor DarkGray
    }
}
