<#
.SYNOPSIS
    Creates the custom vCenter Server roles for Omnissa Horizon VDI (Instant Clone)
    and Omnissa App Volumes, optionally with their service accounts.

    Self-contained variant - runnable as a one-liner:

        irm https://raw.githubusercontent.com/tomcek42/OmnissaHorizon-vCenterRolesPermissions/main/Invoke-OmnissaHorizon_VMwarevCenter.ps1 | iex

.DESCRIPTION
    This script is intentionally standalone (no companion files required) so it can
    be executed in memory via 'irm <URL> | iex'. A menu lets you set up:

        [1] App Volumes only
        [2] Horizon VDI (Instant Clone) only
        [3] Both
        [4] Exit

    For each selected product the script creates (or updates) a custom vCenter role
    with the documented privilege set and can optionally create/assign a dedicated
    service account and grant the role at the vCenter root (propagated).

    Missing values (vCenter server, role names, options) are prompted interactively
    and stored in a config.json so later runs can reuse them. The vCenter connection
    is shared, so 'Both' connects only once and creates two independent roles and
    two independent service accounts.

    Credentials are stored encrypted (Windows DPAPI, Export-Clixml). They are bound
    to the Windows user and machine that created them.

    Location (default): the directory of the .ps1 file. When executed via
    'irm <URL> | iex' (no file present) the current working directory is used.

.PARAMETER Server
    vCenter server (FQDN). Overrides the value from config.json.

.PARAMETER Username
    Account used to sign in to vCenter (must be allowed to create roles/permissions
    and SSO users when creating a service account).

.PARAMETER Mode
    Which product(s) to set up: 'AppVolumes', 'InstantClone' or 'Both'. When omitted
    an interactive menu is shown (validated in the body).

.PARAMETER IgnoreCertificateErrors
    Sets the session certificate action to 'Ignore'.

.PARAMETER WorkingDirectory
    Storage location for config.json and the credential file. Default: the .ps1
    directory, or the current working directory when run via 'irm | iex'.

.PARAMETER ConfigPath
    Explicit path to config.json (default: <WorkingDirectory>\config.json).

.PARAMETER NonInteractive
    Suppresses prompts. Missing required values then come from config.json/defaults
    or cause the script to fail.

.NOTES
    Note: 'irm | iex' cannot pass parameters; in that case missing values are
    prompted interactively. To use parameters, run the file directly
    (.\Invoke-OmnissaHorizon_VMwarevCenter.ps1 -Server ...) or via a script block:
        & ([scriptblock]::Create((irm <URL>))) -Server vcenter... -Mode Both
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$Username,
    [string]$Mode,                 # 'AppVolumes', 'InstantClone' or 'Both' (validated in the body)
    [switch]$IgnoreCertificateErrors,
    [string]$WorkingDirectory,
    [string]$ConfigPath,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

# Minimum supported vCenter Server major version (checked after connecting).
$MinimumVCenterMajorVersion = 8

# Force TLS 1.2 (important for downloads on Windows PowerShell 5.1)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# =============================================================================
# Product definitions (privilege sets + defaults)
# =============================================================================

# --- App Volumes: per Omnissa App Volumes Administration Guide ----------------
$AppVolumesBasePrivileges = @(
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
$AppVolumesCryptoPrivileges = @(
    'Cryptographer.Access'      # Direct Access
    'Cryptographer.AddDisk'     # Add Disk (missing from PowerCLI doc, added from GUI)
)

# --- Horizon Instant Clone: per "Privileges Required for the vCenter Server ----
# --- User With Instant Clones" (Omnissa Horizon 8 Installation and Upgrade). ---
# Built from the official PDF; Datastore.FileManagement was missing from the
# exported list and has been added, Alarm.DisableActions is kept as a harmless
# extra. The 7 Cryptographer.* privileges are only required for vTPM instant
# clones and live in the optional crypto set below.
$InstantCloneBasePrivileges = @(
    'System.Anonymous', 'System.View', 'System.Read'
    'Alarm.DisableActions', 'Alarm.ToggleEnableOnEntity'
    'Datastore.AllocateSpace', 'Datastore.Browse', 'Datastore.FileManagement'
    'Folder.Create', 'Folder.Delete'
    'Global.DisableMethods', 'Global.EnableMethods', 'Global.ManageCustomFields'
    'Global.SetCustomField', 'Global.VCServer'
    'Host.Config.AdvancedConfig', 'Host.Inventory.EditCluster'
    'InventoryService.Tagging.AttachTag', 'InventoryService.Tagging.CreateCategory'
    'InventoryService.Tagging.CreateTag', 'InventoryService.Tagging.DeleteCategory'
    'InventoryService.Tagging.DeleteTag', 'InventoryService.Tagging.ObjectAttachable'
    'Network.Assign'
    'Resource.AssignVMToPool'
    'StorageProfile.Update', 'StorageProfile.View'
    'VirtualMachine.Config.AddExistingDisk', 'VirtualMachine.Config.AddNewDisk'
    'VirtualMachine.Config.AddRemoveDevice', 'VirtualMachine.Config.AdvancedConfig'
    'VirtualMachine.Config.Annotation', 'VirtualMachine.Config.CPUCount'
    'VirtualMachine.Config.ChangeTracking', 'VirtualMachine.Config.DiskExtend'
    'VirtualMachine.Config.DiskLease', 'VirtualMachine.Config.EditDevice'
    'VirtualMachine.Config.HostUSBDevice', 'VirtualMachine.Config.ManagedBy'
    'VirtualMachine.Config.Memory', 'VirtualMachine.Config.MksControl'
    'VirtualMachine.Config.QueryFTCompatibility', 'VirtualMachine.Config.QueryUnownedFiles'
    'VirtualMachine.Config.RawDevice', 'VirtualMachine.Config.ReloadFromPath'
    'VirtualMachine.Config.RemoveDisk', 'VirtualMachine.Config.Rename'
    'VirtualMachine.Config.ResetGuestInfo', 'VirtualMachine.Config.Resource'
    'VirtualMachine.Config.Settings', 'VirtualMachine.Config.SwapPlacement'
    'VirtualMachine.Config.ToggleForkParent', 'VirtualMachine.Config.UpgradeVirtualHardware'
    'VirtualMachine.Interact.DeviceConnection', 'VirtualMachine.Interact.PowerOff'
    'VirtualMachine.Interact.PowerOn', 'VirtualMachine.Interact.Reset'
    'VirtualMachine.Interact.SESparseMaintenance', 'VirtualMachine.Interact.Suspend'
    'VirtualMachine.Inventory.Create', 'VirtualMachine.Inventory.CreateFromExisting'
    'VirtualMachine.Inventory.Delete', 'VirtualMachine.Inventory.Move'
    'VirtualMachine.Inventory.Register', 'VirtualMachine.Inventory.Unregister'
    'VirtualMachine.Provisioning.Clone', 'VirtualMachine.Provisioning.CloneTemplate'
    'VirtualMachine.Provisioning.Customize', 'VirtualMachine.Provisioning.DeployTemplate'
    'VirtualMachine.Provisioning.DiskRandomAccess', 'VirtualMachine.Provisioning.PromoteDisks'
    'VirtualMachine.Provisioning.ReadCustSpecs'
    'VirtualMachine.State.CreateSnapshot', 'VirtualMachine.State.RemoveSnapshot'
    'VirtualMachine.State.RenameSnapshot', 'VirtualMachine.State.RevertToSnapshot'
)
$InstantCloneCryptoPrivileges = @(
    'Cryptographer.Access'             # Direct Access
    'Cryptographer.Clone'              # Clone
    'Cryptographer.Decrypt'            # Decrypt
    'Cryptographer.Encrypt'            # Encrypt
    'Cryptographer.ManageKeyServers'   # Manage KMS
    'Cryptographer.Migrate'            # Migrate
    'Cryptographer.RegisterHost'       # Register Host
)

# Product catalogue keyed by short name. Order matters for the 'Both' run.
$Products = [ordered]@{
    AppVolumes = [ordered]@{
        Key                       = 'AppVolumes'
        DisplayName               = 'App Volumes'
        DefaultRoleName           = 'App Volumes Service'
        DefaultRoleDescription    = 'Custom role for the Omnissa App Volumes Manager service account'
        DefaultServiceAccountName = 'svc_appvolumes'
        DefaultServiceAccountDesc = 'App Volumes Manager service account'
        CryptoPrompt              = 'Include Cryptographic Operations (only for encrypted storage)?'
        BasePrivileges            = $AppVolumesBasePrivileges
        CryptoPrivileges          = $AppVolumesCryptoPrivileges
    }
    InstantClone = [ordered]@{
        Key                       = 'InstantClone'
        DisplayName               = 'Horizon VDI (Instant Clone)'
        DefaultRoleName           = 'Horizon VDI Service'
        DefaultRoleDescription    = 'Custom role for the Omnissa Horizon Instant Clone vCenter Server user'
        DefaultServiceAccountName = 'svc_horizon'
        DefaultServiceAccountDesc = 'Horizon Instant Clone vCenter service account'
        CryptoPrompt              = 'Include Cryptographic Operations (only for vTPM instant clones)?'
        BasePrivileges            = $InstantCloneBasePrivileges
        CryptoPrivileges          = $InstantCloneCryptoPrivileges
    }
}

# =============================================================================
# Helper functions
# =============================================================================
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

function Test-IsAdministrator {
    # True when the current PowerShell process is running with an elevated token.
    try {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Install-ModuleElevated {
    # Relaunch an elevated instance of the current PowerShell host that installs
    # the given module(s) system-wide (Scope AllUsers), wait for it, then return
    # whether it exited successfully. The current session keeps its state; once
    # the elevated child finishes, Get-Module -ListAvailable will find the module
    # via the AllUsers module path.
    param([string[]]$InstallName)

    $hostExe = try { (Get-Process -Id $PID).Path } catch { $null }
    if ([string]::IsNullOrWhiteSpace($hostExe)) {
        $hostExe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    }

    $names = ($InstallName | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
    $script = @"
`$ErrorActionPreference = 'Stop'
try {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -Force -Scope AllUsers | Out-Null
    }
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    foreach (`$n in @($names)) {
        Write-Host "Installing `$n (Scope AllUsers) ..." -ForegroundColor Cyan
        Install-Module -Name `$n -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
    }
    Write-Host 'Elevated install complete.' -ForegroundColor Green
    exit 0
}
catch {
    Write-Host "Elevated install failed: `$(`$_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Press Enter to close this elevated window'
    exit 1
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    try {
        $proc = Start-Process -FilePath $hostExe -Verb RunAs -PassThru -Wait `
            -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -ErrorAction Stop
        return ($proc.ExitCode -eq 0)
    }
    catch {
        # Most common cause: the user dismissed the UAC prompt.
        Write-Host "   [FAIL] Elevation was cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Resolve-RequiredModule {
    param([string]$CheckName, [string]$InstallName)
    if (Get-Module -ListAvailable -Name $CheckName) {
        Write-Host "   [ OK ] $CheckName" -ForegroundColor Green
        return $true
    }
    Write-Host "   [MISS] $CheckName" -ForegroundColor Yellow

    if ($NonInteractive) {
        Write-Host "          Install manually: Install-Module $InstallName -Scope CurrentUser" -ForegroundColor Yellow
        return $false
    }
    if (-not (Read-YesNo -Prompt "          Install '$InstallName' now?" -Default $true)) {
        Write-Host "          Install manually: Install-Module $InstallName -Scope CurrentUser" -ForegroundColor Yellow
        return $false
    }

    if (Test-IsAdministrator) {
        # Elevated already -> install system-wide directly.
        Write-Host "          Console is elevated - installing '$InstallName' (Scope AllUsers) ..." -ForegroundColor Cyan
        try {
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -Scope AllUsers | Out-Null
            }
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            Install-Module -Name $InstallName -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        }
        catch {
            Write-Host "   [FAIL] Install failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        # Not elevated -> offer to elevate the console for a system-wide install.
        Write-Host "          Console is NOT running as Administrator - a system-wide install needs elevation." -ForegroundColor Yellow
        if (Read-YesNo -Prompt "          Launch an elevated console to install '$InstallName' now?" -Default $true) {
            if (Install-ModuleElevated -InstallName $InstallName) {
                Write-Host "          Elevated install finished - re-checking availability ..." -ForegroundColor Cyan
            }
        }
        elseif (Read-YesNo -Prompt "          Try a per-user install instead (Scope CurrentUser, no admin)?" -Default $true) {
            try {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
                Install-Module -Name $InstallName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
            catch {
                Write-Host "   [FAIL] Per-user install failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    if (Get-Module -ListAvailable -Name $CheckName) {
        Write-Host "   [ OK ] Installed $CheckName" -ForegroundColor Green
        return $true
    }
    Write-Host "          Install manually: Install-Module $InstallName -Scope CurrentUser" -ForegroundColor Yellow
    return $false
}

# Resolve all per-product settings (role + service account) from
# parameter/config/prompt and return them as an ordered hashtable.
function Resolve-ProductSettings {
    param(
        [hashtable]$Meta,
        $ConfigNode
    )
    $cfg = $ConfigNode
    $cfgSvc = if ($cfg) { $cfg.ServiceAccount } else { $null }

    Write-Section "$($Meta.DisplayName) - configuration"

    $roleName = if ($cfg -and $cfg.RoleName) { $cfg.RoleName }
                else { Read-DefaultedValue -Prompt 'Role name' -Default $Meta.DefaultRoleName }

    $roleDesc = if ($cfg -and $cfg.RoleDescription) { $cfg.RoleDescription }
                else { Read-DefaultedValue -Prompt 'Role description' -Default $Meta.DefaultRoleDescription }

    $includeCrypto = if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'IncludeCryptographicOperations')) {
                         [bool]$cfg.IncludeCryptographicOperations
                     }
                     else { Read-YesNo -Prompt $Meta.CryptoPrompt -Default $false }

    $overwrite = if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'Overwrite')) { [bool]$cfg.Overwrite }
                 else { Read-YesNo -Prompt 'Update the role if it already exists?' -Default $true }

    $svcEnabled = if ($cfgSvc -and ($cfgSvc.PSObject.Properties.Name -contains 'Enabled')) { [bool]$cfgSvc.Enabled }
                  else { Read-YesNo -Prompt 'Set up a service account and assign the role at the vCenter root?' -Default $false }

    $svcMode      = if ($cfgSvc -and $cfgSvc.Mode) { $cfgSvc.Mode } else { 'Create' }
    $svcName      = if ($cfgSvc -and $cfgSvc.Name) { $cfgSvc.Name } else { $Meta.DefaultServiceAccountName }
    $svcDomain    = if ($cfgSvc -and $cfgSvc.Domain) { $cfgSvc.Domain } else { 'vsphere.local' }
    $svcPrincipal = if ($cfgSvc -and $cfgSvc.Principal) { $cfgSvc.Principal } else { '' }
    $svcDesc      = if ($cfgSvc -and $cfgSvc.Description) { $cfgSvc.Description } else { $Meta.DefaultServiceAccountDesc }
    $pwLen        = if ($cfgSvc -and $cfgSvc.PasswordLength) { [int]$cfgSvc.PasswordLength } else { 18 }

    if ($svcEnabled) {
        if (-not ($cfgSvc -and $cfgSvc.Mode) -and -not $NonInteractive) {
            Write-Host "   Service account mode:" -ForegroundColor Gray
            Write-Host "     [1] Create a new vCenter SSO user (vsphere.local)" -ForegroundColor White
            Write-Host "     [2] Assign an existing principal (e.g. an AD account)" -ForegroundColor White
            $ans = Read-DefaultedValue -Prompt "   Select" -Default '1'
            $svcMode = if ($ans -match '^\s*2' -or $ans -match '^[Aa]') { 'AssignExisting' } else { 'Create' }
        }
        if ($svcMode -notin @('Create', 'AssignExisting')) {
            throw "ServiceAccount mode must be 'Create' or 'AssignExisting' (got '$svcMode')."
        }
        if ($pwLen -lt 18) { $pwLen = 18 }

        if ($svcMode -eq 'Create') {
            if (-not ($cfgSvc -and $cfgSvc.Name))        { $svcName   = Read-DefaultedValue -Prompt 'SSO service account name' -Default $Meta.DefaultServiceAccountName }
            if (-not ($cfgSvc -and $cfgSvc.Domain))      { $svcDomain = Read-DefaultedValue -Prompt 'SSO domain' -Default 'vsphere.local' }
            if (-not ($cfgSvc -and $cfgSvc.Description))  { $svcDesc   = Read-DefaultedValue -Prompt 'Service account description' -Default $Meta.DefaultServiceAccountDesc }
            $svcPrincipal = "$svcDomain\$svcName"
        }
        else {
            if (-not ($cfgSvc -and $cfgSvc.Principal)) {
                $svcPrincipal = Read-DefaultedValue -Prompt "Existing principal (e.g. 'DOMAIN\svc_horizon')" -Default $null
            }
            if ([string]::IsNullOrWhiteSpace($svcPrincipal)) { throw 'AssignExisting mode requires a principal.' }
        }
    }

    return [ordered]@{
        Key            = $Meta.Key
        DisplayName    = $Meta.DisplayName
        RoleName       = $roleName
        RoleDescription = $roleDesc
        IncludeCrypto  = $includeCrypto
        Overwrite      = $overwrite
        BasePrivileges = $Meta.BasePrivileges
        CryptoPrivileges = $Meta.CryptoPrivileges
        SvcEnabled     = $svcEnabled
        SvcMode        = $svcMode
        SvcName        = $svcName
        SvcDomain      = $svcDomain
        SvcPrincipal   = $svcPrincipal
        SvcDescription = $svcDesc
        PasswordLength = $pwLen
    }
}

# Create/update one role and (optionally) its service account + permission.
function Invoke-ProductRoleSetup {
    param(
        $Settings,
        $Connection,
        $Credential,
        [bool]$IgnoreCert,
        [string]$ServerName
    )

    Write-Banner "$($Settings.DisplayName) - role setup"

    # Build the privilege list
    $privilegeIds = [System.Collections.Generic.List[string]]::new()
    $Settings.BasePrivileges | ForEach-Object { $privilegeIds.Add($_) }
    if ($Settings.IncludeCrypto) {
        $Settings.CryptoPrivileges | ForEach-Object { $privilegeIds.Add($_) }
        Write-Host "Including Cryptographic Operations (+$($Settings.CryptoPrivileges.Count))." -ForegroundColor Cyan
    }
    else {
        Write-Host "Not including Cryptographic Operations." -ForegroundColor Cyan
    }

    $privileges = Get-VIPrivilege -Server $Connection -Id $privilegeIds -ErrorAction Stop
    $resolvedIds = $privileges | Select-Object -ExpandProperty Id
    $missing = $privilegeIds | Where-Object { $resolvedIds -notcontains $_ }
    if ($missing) {
        throw "The following privilege IDs were not found on vCenter: $($missing -join ', ')"
    }
    Write-Host "Resolved all $($privilegeIds.Count) privileges." -ForegroundColor Green

    $roleName = $Settings.RoleName
    $existingRole = Get-VIRole -Server $Connection -Name $roleName -ErrorAction SilentlyContinue
    if ($existingRole) {
        if (-not $Settings.Overwrite) {
            throw "Role '$roleName' already exists. Enable 'Update the role if it already exists' (Overwrite) to update it."
        }
        Write-Host "Role '$roleName' already exists - updating." -ForegroundColor Yellow
        Set-VIRole -Role $existingRole -AddPrivilege $privileges -Server $Connection -ErrorAction Stop | Out-Null
    }
    else {
        Write-Host "Creating new role '$roleName' ..." -ForegroundColor Cyan
        New-VIRole -Name $roleName -Privilege $privileges -Server $Connection -ErrorAction Stop | Out-Null
    }

    # Note: neither PowerCLI nor the vSphere API support setting a description on a
    # custom role, so the description is kept in config.json for documentation only.
    if (-not [string]::IsNullOrWhiteSpace($Settings.RoleDescription)) {
        Write-Host "Role description recorded in config.json (vCenter does not accept role descriptions via PowerCLI)." -ForegroundColor DarkGray
    }

    $finalRole = Get-VIRole -Server $Connection -Name $roleName
    Write-Host "Role '$($finalRole.Name)' now has $($finalRole.PrivilegeList.Count) privileges." -ForegroundColor Green

    # --- Optional: service account + permission -------------------------------
    if ($Settings.SvcEnabled) {
        Write-Host ""
        Write-Host "Setting up service account (mode: $($Settings.SvcMode)) ..." -ForegroundColor Cyan

        if ($Settings.SvcMode -eq 'Create') {
            if (-not (Get-Module -ListAvailable -Name 'VMware.vSphere.SsoAdmin')) {
                throw "Creating an SSO account requires the VMware.vSphere.SsoAdmin module. Install it with: Install-Module VMware.vSphere.SsoAdmin -Scope CurrentUser"
            }
            Import-Module 'VMware.vSphere.SsoAdmin' -ErrorAction Stop

            $ssoParams = @{
                Server   = $ServerName
                User     = $Credential.UserName
                Password = $Credential.GetNetworkCredential().Password
            }
            if ($IgnoreCert) { $ssoParams['SkipCertificateCheck'] = $true }
            $ssoConnection = $null
            try {
                $ssoConnection = Connect-SsoAdminServer @ssoParams

                $existingUser = Get-SsoPersonUser -Name $Settings.SvcName -Domain $Settings.SvcDomain -Server $ssoConnection -ErrorAction SilentlyContinue
                if ($existingUser) {
                    Write-Host "SSO user '$($Settings.SvcDomain)\$($Settings.SvcName)' already exists - keeping existing password." -ForegroundColor Yellow
                }
                else {
                    $generatedPassword = New-StrongPassword -Length $Settings.PasswordLength
                    New-SsoPersonUser -UserName $Settings.SvcName -Password $generatedPassword -Description $Settings.SvcDescription -Server $ssoConnection | Out-Null
                    Write-Host "Created SSO user '$($Settings.SvcDomain)\$($Settings.SvcName)'." -ForegroundColor Green
                    Write-Host ""
                    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Yellow
                    Write-Host "  |                 SERVICE ACCOUNT PASSWORD                   |" -ForegroundColor Yellow
                    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Yellow
                    Write-Host "    User    : $($Settings.SvcDomain)\$($Settings.SvcName)" -ForegroundColor White
                    Write-Host -NoNewline "    Password: " -ForegroundColor White
                    Write-Host " $generatedPassword " -ForegroundColor Black -BackgroundColor White
                    Write-Host "    Shown only once - store it now; it is not saved anywhere." -ForegroundColor Yellow
                    Write-Host ""
                }
            }
            finally {
                if ($ssoConnection) { Disconnect-SsoAdminServer -Server $ssoConnection -ErrorAction SilentlyContinue }
            }
        }

        # Assign the role at the vCenter root (propagated)
        $rootFolder = Get-Folder -Server $Connection -NoRecursion -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $rootFolder) {
            $si = Get-View -Server $Connection ServiceInstance
            $rootFolder = Get-VIObjectByVIView -Server $Connection -MORef $si.Content.RootFolder
        }

        $existingPerm = Get-VIPermission -Server $Connection -Entity $rootFolder -ErrorAction SilentlyContinue |
            Where-Object { $_.Principal -eq $Settings.SvcPrincipal }
        if ($existingPerm) {
            Write-Host "Permission for '$($Settings.SvcPrincipal)' already exists at the root - leaving it unchanged." -ForegroundColor Yellow
        }
        else {
            New-VIPermission -Server $Connection -Entity $rootFolder -Principal $Settings.SvcPrincipal -Role $finalRole -Propagate $true -ErrorAction Stop | Out-Null
            Write-Host "Assigned role '$roleName' to '$($Settings.SvcPrincipal)' at the vCenter root (propagated)." -ForegroundColor Green
        }
    }
}

# =============================================================================
# Main
# =============================================================================
Write-Banner 'Omnissa Horizon VDI + App Volumes - vCenter Roles & Permissions'

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

Write-Section 'Configuration'
Write-Host "Working directory: $WorkingDirectory" -ForegroundColor DarkGray

# Load existing config.json - but only after asking whether it should be used.
# Declining leaves the file on disk yet treats this run as a fresh start (the
# file is still overwritten with the freshly entered values at the end).
$config = $null
if (Test-Path -LiteralPath $ConfigPath) {
    if ($NonInteractive -or (Read-YesNo -Prompt "Found an existing config.json - use its values as defaults?" -Default $true)) {
        try {
            $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
            Write-Host "Using existing configuration: $ConfigPath" -ForegroundColor DarkGray
        }
        catch { Write-Host "Note: config.json unreadable, will be recreated ($($_.Exception.Message))." -ForegroundColor DarkYellow }
    }
    else {
        Write-Host "Ignoring existing config.json for this run (it will be overwritten with the new values)." -ForegroundColor DarkYellow
    }
}

# --- Select products (menu) ---------------------------------------------------
# If config.json is being used and already lists configured products, that set
# is offered as the default menu selection.
$cfgConfiguredKeys = @()
if ($config -and $config.Products) {
    foreach ($k in $Products.Keys) {
        if ($config.Products.PSObject.Properties.Name -contains $k) { $cfgConfiguredKeys += $k }
    }
}

$selectedKeys = $null
if ($Mode) {
    switch -Regex ($Mode) {
        '^(AppVolumes|AV|1)$'        { $selectedKeys = @('AppVolumes') }
        '^(InstantClone|IC|2)$'      { $selectedKeys = @('InstantClone') }
        '^(Both|All|3)$'             { $selectedKeys = @('AppVolumes', 'InstantClone') }
        default { throw "Mode must be 'AppVolumes', 'InstantClone' or 'Both' (got '$Mode')." }
    }
}
elseif ($NonInteractive) {
    if ($cfgConfiguredKeys.Count -gt 0) { $selectedKeys = $cfgConfiguredKeys }
    else { throw 'No -Mode provided and NonInteractive is set.' }
}
else {
    $menuDefault = if ($cfgConfiguredKeys.Count -eq 1) {
                       if ($cfgConfiguredKeys[0] -eq 'AppVolumes') { '1' } else { '2' }
                   }
                   else { '3' }
    Write-Section 'What would you like to set up?'
    Write-Host "   [1] App Volumes" -ForegroundColor White
    Write-Host "   [2] Horizon VDI (Instant Clone)" -ForegroundColor White
    Write-Host "   [3] Both" -ForegroundColor White
    Write-Host "   [4] Exit" -ForegroundColor White
    if ($cfgConfiguredKeys.Count -gt 0) {
        Write-Host "   (config.json currently holds: $(( $cfgConfiguredKeys | ForEach-Object { $Products[$_].DisplayName }) -join ' + '))" -ForegroundColor DarkGray
    }
    $choice = Read-DefaultedValue -Prompt '   Select' -Default $menuDefault
    switch ($choice.Trim()) {
        '1' { $selectedKeys = @('AppVolumes') }
        '2' { $selectedKeys = @('InstantClone') }
        '3' { $selectedKeys = @('AppVolumes', 'InstantClone') }
        '4' { Write-Host "Aborted." -ForegroundColor DarkGray; return }
        default { throw "Invalid selection '$choice'." }
    }
}
Write-Host "Selected: $(( $selectedKeys | ForEach-Object { $Products[$_].DisplayName }) -join ' + ')" -ForegroundColor Cyan

# vCenter connection settings: parameter > config.json > interactive prompt
$cfgServer = if ($config -and $config.vCenter) { $config.vCenter.Server } else { $null }
$cfgUser   = if ($config -and $config.vCenter) { $config.vCenter.Username } else { $null }
$cfgIgnore = if ($config -and $config.vCenter) { [bool]$config.vCenter.IgnoreCertificateErrors } else { $false }

$viServer = if ($Server) { $Server } elseif ($cfgServer) { $cfgServer } else { Read-DefaultedValue -Prompt 'vCenter server (FQDN)' -Default $null }
if ([string]::IsNullOrWhiteSpace($viServer)) { throw 'No vCenter server provided.' }

$vcUser = if ($Username) { $Username } elseif ($cfgUser) { $cfgUser } else { Read-DefaultedValue -Prompt 'Username' -Default 'administrator@vsphere.local' }

$ignoreCert = if ($PSBoundParameters.ContainsKey('IgnoreCertificateErrors')) { [bool]$IgnoreCertificateErrors }
              elseif ($config -and $config.vCenter) { $cfgIgnore }
              else { Read-YesNo -Prompt 'Ignore certificate errors (self-signed certs)?' -Default $false }

# --- Resolve per-product settings ---------------------------------------------
$cfgProducts = if ($config) { $config.Products } else { $null }
$settingsList = @()
foreach ($key in $selectedKeys) {
    $cfgNode = if ($cfgProducts) { $cfgProducts.$key } else { $null }
    $settingsList += Resolve-ProductSettings -Meta $Products[$key] -ConfigNode $cfgNode
}

# --- Write/update config.json (without secrets) -------------------------------
$productsConfig = [ordered]@{}
foreach ($s in $settingsList) {
    $productsConfig[$s.Key] = [ordered]@{
        RoleName                       = $s.RoleName
        RoleDescription                = $s.RoleDescription
        IncludeCryptographicOperations = $s.IncludeCrypto
        Overwrite                      = $s.Overwrite
        ServiceAccount = [ordered]@{
            Enabled                = $s.SvcEnabled
            Mode                   = $s.SvcMode
            Name                   = $s.SvcName
            Domain                 = $s.SvcDomain
            Principal              = $s.SvcPrincipal
            Description            = $s.SvcDescription
            PasswordLength         = $s.PasswordLength
            AssignPermissionAtRoot = $true
        }
    }
}
# Preserve config of products that were not part of this run
if ($cfgProducts) {
    foreach ($p in $cfgProducts.PSObject.Properties) {
        if (-not $productsConfig.Contains($p.Name)) { $productsConfig[$p.Name] = $p.Value }
    }
}

$configObject = [ordered]@{
    vCenter = [ordered]@{
        Server                  = $viServer
        Username                = $vcUser
        IgnoreCertificateErrors = $ignoreCert
    }
    Products = $productsConfig
}
$configObject | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
Write-Host "Configuration saved: $ConfigPath" -ForegroundColor DarkGray

# --- Preflight: required modules ----------------------------------------------
# Check that every PowerShell module needed for the selected run is present (and
# offer to install any that are missing) before we touch vCenter. SsoAdmin is
# only required when a service account is to be CREATED (vsphere.local SSO user).
Write-Section 'Required PowerShell modules'
$needsSso = ($settingsList | Where-Object { $_.SvcEnabled -and $_.SvcMode -eq 'Create' }).Count -gt 0

$requiredModules = @(
    @{ CheckName = 'VMware.VimAutomation.Core'; InstallName = 'VMware.PowerCLI' }
)
if ($needsSso) {
    $requiredModules += @{ CheckName = 'VMware.vSphere.SsoAdmin'; InstallName = 'VMware.vSphere.SsoAdmin' }
}

$missingModules = @()
foreach ($m in $requiredModules) {
    if (-not (Resolve-RequiredModule -CheckName $m.CheckName -InstallName $m.InstallName)) {
        $missingModules += $m.CheckName
    }
}
if ($missingModules.Count -gt 0) {
    throw "Missing required PowerShell module(s): $($missingModules -join ', '). Install them (see above) and re-run."
}
Write-Host "All required PowerShell modules are present." -ForegroundColor Green
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

# --- Summary ------------------------------------------------------------------
Write-Section 'Summary'
Write-Field 'vCenter'      $viServer
Write-Field 'User'         $vcUser
Write-Field 'Ignore cert'  $(if ($ignoreCert) { 'yes' } else { 'no' })
foreach ($s in $settingsList) {
    Write-Host ""
    Write-Field $s.DisplayName ''
    Write-Field '  Role'        $s.RoleName
    Write-Field '  Crypto ops'  $(if ($s.IncludeCrypto) { 'included' } else { 'excluded' })
    if ($s.SvcEnabled) {
        Write-Field '  Service acct' $(if ($s.SvcMode -eq 'Create') { "create  $($s.SvcPrincipal)" } else { "assign  $($s.SvcPrincipal)" })
        Write-Field '  Permission'   'vCenter root (propagated)'
    }
    else {
        Write-Field '  Service acct' 'skipped'
    }
}

# --- Connect (once) and process each selected product -------------------------
$connection = $null
try {
    Write-Host ""
    Write-Host "Connecting to vCenter '$viServer' ..." -ForegroundColor Cyan
    $connection = Connect-VIServer -Server $viServer -Credential $credential -ErrorAction Stop

    # --- Require vCenter Server 8.0 or newer -----------------------------------
    if ($connection.ProductLine -ne 'vpx') {
        throw "Connected endpoint '$viServer' is not a vCenter Server (ProductLine '$($connection.ProductLine)'). This tool must be run against vCenter Server 8.0 or newer."
    }
    $vcVersion = $null
    try { $vcVersion = [version]$connection.Version } catch { }
    if (-not $vcVersion -or $vcVersion.Major -lt $MinimumVCenterMajorVersion) {
        throw "This tool requires vCenter Server $MinimumVCenterMajorVersion.0 or newer. Connected vCenter reports version '$($connection.Version)' (build $($connection.Build))."
    }
    Write-Host "vCenter version $($connection.Version) (build $($connection.Build)) - OK (>= $MinimumVCenterMajorVersion.0)." -ForegroundColor Green

    foreach ($s in $settingsList) {
        Invoke-ProductRoleSetup -Settings $s -Connection $connection -Credential $credential -IgnoreCert $ignoreCert -ServerName $viServer
    }

    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
}
finally {
    if ($connection) {
        Disconnect-VIServer -Server $connection -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Disconnected from '$viServer'." -ForegroundColor DarkGray
    }
}
