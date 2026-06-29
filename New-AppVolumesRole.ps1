<#
.SYNOPSIS
    Erstellt eine benutzerdefinierte vCenter-Server-Rolle fuer Omnissa App Volumes.

.DESCRIPTION
    Liest alle Verbindungs- und Rollen-Parameter aus einer config.json und legt
    ueber PowerCLI eine vCenter-Rolle mit den fuer das App Volumes Manager
    Service-Konto erforderlichen Privilegien an.

    Die Privilegienliste entspricht der vollstaendigen GUI-Tabelle aus dem
    Omnissa App Volumes Administration Guide (Create a Custom vCenter Server Role)
    und enthaelt zusaetzlich die drei Privilegien, die in der PowerCLI-Doku fehlen
    (Cryptographer.AddDisk, VirtualMachine.Config.AdvancedConfig,
    VirtualMachine.Config.QueryUnownedFiles).

    Die Cryptographer.* Privilegien (Direct Access / Add Disk) werden nur
    hinzugefuegt, wenn in der config.json Role.IncludeCryptographicOperations
    auf true gesetzt ist. Sie sind nur noetig, wenn der VM-Storage
    Verschluesselungsrichtlinien verwendet.

.PARAMETER ConfigPath
    Pfad zur config.json. Standard: config.json im Verzeichnis des Skripts.

.EXAMPLE
    .\New-AppVolumesRole.ps1
    .\New-AppVolumesRole.ps1 -ConfigPath "D:\Deploy\config.json"

.NOTES
    Voraussetzung: VMware/Omnissa PowerCLI ist installiert.
        Install-Module -Name VMware.PowerCLI -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath 'config.json')
)

$ErrorActionPreference = 'Stop'

# --- Privilegien laut Omnissa App Volumes Administration Guide -----------------
# Basis-Set (immer): GUI-Tabelle vollstaendig + System-Privilegien fuer PowerCLI.
$BasePrivilegeIds = @(
    # System-Privilegien (in der GUI nicht sichtbar, fuer PowerCLI noetig)
    'System.Anonymous'
    'System.View'
    'System.Read'
    # Global
    'Global.CancelTask'
    # Folder
    'Folder.Create'
    'Folder.Delete'
    # Datastore
    'Datastore.Browse'
    'Datastore.DeleteFile'
    'Datastore.FileManagement'
    'Datastore.AllocateSpace'
    'Datastore.UpdateVirtualMachineFiles'
    # Host > Local operations
    'Host.Local.CreateVM'
    'Host.Local.ReconfigVM'
    'Host.Local.DeleteVM'
    # Virtual machine > Edit Inventory
    'VirtualMachine.Inventory.Create'
    'VirtualMachine.Inventory.CreateFromExisting'
    'VirtualMachine.Inventory.Register'
    'VirtualMachine.Inventory.Delete'
    'VirtualMachine.Inventory.Unregister'
    'VirtualMachine.Inventory.Move'
    # Virtual machine > Interaction
    'VirtualMachine.Interact.PowerOn'
    'VirtualMachine.Interact.PowerOff'
    'VirtualMachine.Interact.Suspend'
    # Virtual machine > Change Configuration
    'VirtualMachine.Config.AddExistingDisk'
    'VirtualMachine.Config.AddNewDisk'
    'VirtualMachine.Config.RemoveDisk'
    'VirtualMachine.Config.AddRemoveDevice'
    'VirtualMachine.Config.Settings'
    'VirtualMachine.Config.Resource'
    'VirtualMachine.Config.AdvancedConfig'        # In PowerCLI-Doku fehlend, aus GUI ergaenzt
    'VirtualMachine.Config.QueryUnownedFiles'     # In PowerCLI-Doku fehlend, aus GUI ergaenzt
    # Virtual machine > Provisioning
    'VirtualMachine.Provisioning.Customize'
    'VirtualMachine.Provisioning.Clone'
    'VirtualMachine.Provisioning.PromoteDisks'
    'VirtualMachine.Provisioning.CreateTemplateFromVM'
    'VirtualMachine.Provisioning.DeployTemplate'
    'VirtualMachine.Provisioning.CloneTemplate'
    'VirtualMachine.Provisioning.MarkAsTemplate'
    'VirtualMachine.Provisioning.MarkAsVM'
    'VirtualMachine.Provisioning.ReadCustSpecs'
    'VirtualMachine.Provisioning.ModifyCustSpecs'
    # Resource
    'Resource.AssignVMToPool'
    # Tasks
    'Task.Create'
    # Sessions
    'Sessions.TerminateSession'
)

# Cryptographic Operations (optional, nur bei verschluesseltem Storage)
$CryptographicPrivilegeIds = @(
    'Cryptographer.Access'      # Direct Access
    'Cryptographer.AddDisk'     # Add Disk (in PowerCLI-Doku fehlend, aus GUI ergaenzt)
)

# --- Konfiguration einlesen ---------------------------------------------------
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Konfigurationsdatei nicht gefunden: $ConfigPath"
}

try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
}
catch {
    throw "config.json konnte nicht als JSON gelesen werden: $($_.Exception.Message)"
}

# Pflichtfelder pruefen
if ([string]::IsNullOrWhiteSpace($config.vCenter.Server)) { throw 'config.json: vCenter.Server fehlt.' }
if ([string]::IsNullOrWhiteSpace($config.vCenter.Username)) { throw 'config.json: vCenter.Username fehlt.' }
if ([string]::IsNullOrWhiteSpace($config.Role.Name)) { throw 'config.json: Role.Name fehlt.' }

$viServer       = $config.vCenter.Server
$roleName       = $config.Role.Name
$roleDescription = $config.Role.Description
$includeCrypto  = [bool]$config.Role.IncludeCryptographicOperations
$overwrite      = [bool]$config.Role.Overwrite
$ignoreCert     = [bool]$config.vCenter.IgnoreCertificateErrors

# Pfad zur verschluesselten Credential-Datei aufloesen (relativ zum Skript)
$credentialPath = $config.vCenter.CredentialPath
if ([string]::IsNullOrWhiteSpace($credentialPath)) {
    $credentialPath = 'vcenter-credential.xml'
}
if (-not [System.IO.Path]::IsPathRooted($credentialPath)) {
    $credentialPath = Join-Path -Path $PSScriptRoot -ChildPath $credentialPath
}

# --- PowerCLI laden -----------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name 'VMware.VimAutomation.Core')) {
    throw 'PowerCLI (VMware.VimAutomation.Core) ist nicht installiert. Bitte zuerst "Install-Module VMware.PowerCLI" ausfuehren.'
}
Import-Module 'VMware.VimAutomation.Core' -ErrorAction Stop

# Zertifikatsverhalten gemaess config.json (nur fuer diese Session)
$certAction = if ($ignoreCert) { 'Ignore' } else { 'Fail' }
Set-PowerCLIConfiguration -InvalidCertificateAction $certAction -Scope Session -Confirm:$false | Out-Null

# --- Anmeldeinformationen aufbauen --------------------------------------------
# Verschluesselte Credential-Datei (DPAPI) laden. Existiert sie noch nicht,
# werden die Daten sicher abgefragt und fuer kuenftige Laeufe gespeichert.
if (Test-Path -LiteralPath $credentialPath) {
    try {
        $credential = Import-Clixml -LiteralPath $credentialPath
    }
    catch {
        throw "Credential-Datei '$credentialPath' konnte nicht entschluesselt werden. Sie ist an den Windows-Benutzer und die Maschine gebunden, auf der sie erstellt wurde. Bitte mit Save-AppVolumesCredential.ps1 neu erzeugen. Details: $($_.Exception.Message)"
    }
    if (-not ($credential -is [System.Management.Automation.PSCredential])) {
        throw "Datei '$credentialPath' enthaelt keine gueltigen Anmeldeinformationen. Bitte mit Save-AppVolumesCredential.ps1 neu erzeugen."
    }
    Write-Host "Verschluesselte Anmeldeinformationen geladen ($($credential.UserName))." -ForegroundColor Cyan
}
else {
    Write-Host "Keine Credential-Datei unter '$credentialPath' gefunden - erzeuge sie ueber Save-AppVolumesCredential.ps1." -ForegroundColor Yellow

    $saveScript = Join-Path -Path $PSScriptRoot -ChildPath 'Save-AppVolumesCredential.ps1'
    if (-not (Test-Path -LiteralPath $saveScript)) {
        throw "Hilfsskript nicht gefunden: $saveScript"
    }

    # Save-AppVolumesCredential.ps1 aufrufen, damit Erzeugung und Format zentral
    # an einer Stelle gepflegt werden.
    & $saveScript -ConfigPath $ConfigPath -CredentialPath $credentialPath

    if (-not (Test-Path -LiteralPath $credentialPath)) {
        throw "Credential-Datei wurde nicht erstellt: $credentialPath"
    }
    $credential = Import-Clixml -LiteralPath $credentialPath
    if (-not ($credential -is [System.Management.Automation.PSCredential])) {
        throw "Datei '$credentialPath' enthaelt keine gueltigen Anmeldeinformationen."
    }
    Write-Host "Verschluesselte Anmeldeinformationen geladen ($($credential.UserName))." -ForegroundColor Cyan
}

# --- Privilegienliste zusammenstellen -----------------------------------------
$privilegeIds = [System.Collections.Generic.List[string]]::new()
$BasePrivilegeIds | ForEach-Object { $privilegeIds.Add($_) }
if ($includeCrypto) {
    $CryptographicPrivilegeIds | ForEach-Object { $privilegeIds.Add($_) }
    Write-Host "Cryptographic Operations werden eingeschlossen ($($CryptographicPrivilegeIds.Count) Privilegien)." -ForegroundColor Cyan
}
else {
    Write-Host "Cryptographic Operations werden NICHT eingeschlossen (Role.IncludeCryptographicOperations = false)." -ForegroundColor Cyan
}

# --- Verbindung und Rollenerstellung ------------------------------------------
$connection = $null
try {
    Write-Host "Verbinde mit vCenter '$viServer' ..." -ForegroundColor Cyan
    $connection = Connect-VIServer -Server $viServer -Credential $credential -ErrorAction Stop

    # Privilegien-Objekte vom Server holen und auf Vollstaendigkeit pruefen
    $privileges = Get-VIPrivilege -Server $connection -Id $privilegeIds -ErrorAction Stop
    $resolvedIds = $privileges | Select-Object -ExpandProperty Id
    $missing = $privilegeIds | Where-Object { $resolvedIds -notcontains $_ }
    if ($missing) {
        throw "Folgende Privilegien-IDs wurden auf dem vCenter nicht gefunden: $($missing -join ', ')"
    }
    Write-Host "Alle $($privilegeIds.Count) Privilegien wurden auf dem vCenter aufgeloest." -ForegroundColor Green

    # Bestehende Rolle behandeln
    $existingRole = Get-VIRole -Server $connection -Name $roleName -ErrorAction SilentlyContinue
    if ($existingRole) {
        if (-not $overwrite) {
            throw "Die Rolle '$roleName' existiert bereits. Setze Role.Overwrite in der config.json auf true, um sie zu aktualisieren."
        }
        Write-Host "Rolle '$roleName' existiert bereits - Privilegien werden aktualisiert (Overwrite = true)." -ForegroundColor Yellow
        Set-VIRole -Role $existingRole -AddPrivilege $privileges -Server $connection -ErrorAction Stop | Out-Null
        $resultRole = Get-VIRole -Server $connection -Name $roleName
    }
    else {
        Write-Host "Erstelle neue Rolle '$roleName' ..." -ForegroundColor Cyan
        $resultRole = New-VIRole -Name $roleName -Privilege $privileges -Server $connection -ErrorAction Stop
    }

    # Optionale Beschreibung setzen (nur falls von der API/Version unterstuetzt)
    if (-not [string]::IsNullOrWhiteSpace($roleDescription)) {
        try {
            Set-VIRole -Role $resultRole -Description $roleDescription -Server $connection -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host "Hinweis: Beschreibung konnte nicht gesetzt werden ($($_.Exception.Message))." -ForegroundColor DarkYellow
        }
    }

    $finalRole = Get-VIRole -Server $connection -Name $roleName
    Write-Host ""
    Write-Host "Fertig. Rolle '$($finalRole.Name)' enthaelt $($finalRole.PrivilegeList.Count) Privilegien." -ForegroundColor Green
}
finally {
    if ($connection) {
        Disconnect-VIServer -Server $connection -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Verbindung zu '$viServer' getrennt." -ForegroundColor DarkGray
    }
}
