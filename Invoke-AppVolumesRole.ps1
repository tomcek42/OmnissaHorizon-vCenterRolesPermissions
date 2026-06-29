<#
.SYNOPSIS
    Erstellt eine benutzerdefinierte vCenter-Server-Rolle fuer Omnissa App Volumes.
    Self-contained Variante - lauffaehig per Einzeiler:

        irm https://raw.githubusercontent.com/<user>/<repo>/main/Invoke-AppVolumesRole.ps1 | iex

.DESCRIPTION
    Diese Fassung ist bewusst eigenstaendig (keine Begleitdateien noetig), damit sie
    ueber 'irm <URL> | iex' direkt im Speicher ausgefuehrt werden kann. Fehlende
    Angaben (vCenter-Server, Rollenname, Optionen) werden interaktiv abgefragt und in
    einer config.json im Arbeitsverzeichnis gespeichert, sodass spaetere Laeufe sie
    wiederverwenden.

    Die Anmeldeinformationen werden verschluesselt (Windows DPAPI, Export-Clixml) im
    Arbeitsverzeichnis abgelegt. Sie sind an den Windows-Benutzer und die Maschine
    gebunden, auf der sie erstellt wurden.

    Ablageort (Standard): Verzeichnis der .ps1-Datei. Wird das Skript per
    'irm <URL> | iex' ausgefuehrt (keine Datei vorhanden), wird das aktuelle
    Arbeitsverzeichnis verwendet.

.PARAMETER Server
    vCenter-Server (FQDN). Ueberschreibt den Wert aus der config.json.

.PARAMETER Username
    Anmeldekonto fuer das vCenter.

.PARAMETER RoleName
    Name der zu erstellenden Rolle (Standard: AppVolumes).

.PARAMETER RoleDescription
    Beschreibung der Rolle.

.PARAMETER IncludeCryptographicOperations
    Ergaenzt die Cryptographer.* Privilegien (nur bei verschluesseltem VM-Storage noetig).

.PARAMETER Overwrite
    Aktualisiert eine bereits vorhandene Rolle statt abzubrechen.

.PARAMETER IgnoreCertificateErrors
    Setzt das Zertifikatsverhalten der Session auf 'Ignore'.

.PARAMETER WorkingDirectory
    Ablageort fuer config.json und Credential-Datei. Standard: Verzeichnis der
    .ps1-Datei bzw. das aktuelle Arbeitsverzeichnis bei 'irm | iex'.

.PARAMETER NonInteractive
    Unterdrueckt Abfragen. Fehlt dann ein Pflichtwert, bricht das Skript mit Fehler ab.

.NOTES
    Hinweis: Bei Ausfuehrung via 'irm | iex' koennen KEINE Parameter uebergeben werden;
    in dem Fall werden fehlende Werte interaktiv abgefragt. Wer Parameter nutzen will,
    ruft die Datei direkt (.\Invoke-AppVolumesRole.ps1 -Server ...) oder per Scriptblock auf:
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
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

# TLS 1.2 erzwingen (wichtig fuer Downloads unter Windows PowerShell 5.1)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# --- Privilegien laut Omnissa App Volumes Administration Guide -----------------
$BasePrivilegeIds = @(
    'System.Anonymous','System.View','System.Read'
    'Global.CancelTask'
    'Folder.Create','Folder.Delete'
    'Datastore.Browse','Datastore.DeleteFile','Datastore.FileManagement'
    'Datastore.AllocateSpace','Datastore.UpdateVirtualMachineFiles'
    'Host.Local.CreateVM','Host.Local.ReconfigVM','Host.Local.DeleteVM'
    'VirtualMachine.Inventory.Create','VirtualMachine.Inventory.CreateFromExisting'
    'VirtualMachine.Inventory.Register','VirtualMachine.Inventory.Delete'
    'VirtualMachine.Inventory.Unregister','VirtualMachine.Inventory.Move'
    'VirtualMachine.Interact.PowerOn','VirtualMachine.Interact.PowerOff','VirtualMachine.Interact.Suspend'
    'VirtualMachine.Config.AddExistingDisk','VirtualMachine.Config.AddNewDisk'
    'VirtualMachine.Config.RemoveDisk','VirtualMachine.Config.AddRemoveDevice'
    'VirtualMachine.Config.Settings','VirtualMachine.Config.Resource'
    'VirtualMachine.Config.AdvancedConfig'        # In PowerCLI-Doku fehlend, aus GUI ergaenzt
    'VirtualMachine.Config.QueryUnownedFiles'     # In PowerCLI-Doku fehlend, aus GUI ergaenzt
    'VirtualMachine.Provisioning.Customize','VirtualMachine.Provisioning.Clone'
    'VirtualMachine.Provisioning.PromoteDisks','VirtualMachine.Provisioning.CreateTemplateFromVM'
    'VirtualMachine.Provisioning.DeployTemplate','VirtualMachine.Provisioning.CloneTemplate'
    'VirtualMachine.Provisioning.MarkAsTemplate','VirtualMachine.Provisioning.MarkAsVM'
    'VirtualMachine.Provisioning.ReadCustSpecs','VirtualMachine.Provisioning.ModifyCustSpecs'
    'Resource.AssignVMToPool'
    'Task.Create'
    'Sessions.TerminateSession'
)
$CryptographicPrivilegeIds = @(
    'Cryptographer.Access'      # Direct Access
    'Cryptographer.AddDisk'     # Add Disk (in PowerCLI-Doku fehlend, aus GUI ergaenzt)
)

# --- Hilfsfunktionen ----------------------------------------------------------
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
    $hint = if ($Default) { '(J/n)' } else { '(j/N)' }
    $value = Read-Host -Prompt "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return ($value -match '^(j|y)')
}

# --- Arbeitsverzeichnis und Konfiguration -------------------------------------
# Bevorzugt das Verzeichnis der .ps1-Datei (Config/Credential liegen dann neben
# dem Skript). Bei 'irm <URL> | iex' existiert keine Datei -> Rueckfall auf das
# aktuelle Arbeitsverzeichnis.
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

Write-Host "Arbeitsverzeichnis: $WorkingDirectory" -ForegroundColor DarkGray

# Vorhandene config.json laden (als Vorbelegung)
$config = $null
if (Test-Path -LiteralPath $ConfigPath) {
    try { $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json }
    catch { Write-Host "Hinweis: config.json unlesbar, wird neu erstellt ($($_.Exception.Message))." -ForegroundColor DarkYellow }
}

# Werte ermitteln: Parameter > config.json > interaktive Abfrage
$cfgServer   = if ($config) { $config.vCenter.Server } else { $null }
$cfgUser     = if ($config) { $config.vCenter.Username } else { $null }
$cfgIgnore   = if ($config) { [bool]$config.vCenter.IgnoreCertificateErrors } else { $false }
$cfgRoleName = if ($config) { $config.Role.Name } else { $null }
$cfgRoleDesc = if ($config) { $config.Role.Description } else { $null }
$cfgCrypto   = if ($config) { [bool]$config.Role.IncludeCryptographicOperations } else { $false }
$cfgOverwrite = if ($config) { [bool]$config.Role.Overwrite } else { $false }

$viServer = if ($Server) { $Server } elseif ($cfgServer) { $cfgServer } else { Read-DefaultedValue -Prompt 'vCenter-Server (FQDN)' -Default $null }
if ([string]::IsNullOrWhiteSpace($viServer)) { throw 'Kein vCenter-Server angegeben.' }

$vcUser = if ($Username) { $Username } elseif ($cfgUser) { $cfgUser } else { Read-DefaultedValue -Prompt 'Benutzername' -Default 'administrator@vsphere.local' }

$roleName = if ($RoleName) { $RoleName } elseif ($cfgRoleName) { $cfgRoleName } else { Read-DefaultedValue -Prompt 'Rollenname' -Default 'AppVolumes' }

$roleDescription = if ($RoleDescription) { $RoleDescription } elseif ($cfgRoleDesc) { $cfgRoleDesc } else { 'Custom role for the Omnissa App Volumes Manager service account' }

$includeCrypto = if ($PSBoundParameters.ContainsKey('IncludeCryptographicOperations')) { [bool]$IncludeCryptographicOperations }
                 elseif ($config) { $cfgCrypto }
                 else { Read-YesNo -Prompt 'Cryptographic Operations einschliessen (nur bei verschluesseltem Storage)?' -Default $false }

$ignoreCert = if ($PSBoundParameters.ContainsKey('IgnoreCertificateErrors')) { [bool]$IgnoreCertificateErrors }
              elseif ($config) { $cfgIgnore }
              else { Read-YesNo -Prompt 'Zertifikatsfehler ignorieren (selbstsignierte Zertifikate)?' -Default $false }

$overwrite = if ($PSBoundParameters.ContainsKey('Overwrite')) { [bool]$Overwrite }
             elseif ($config) { $cfgOverwrite }
             else { $false }

# config.json (ohne Geheimnisse) schreiben/aktualisieren
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
}
$configObject | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
Write-Host "Konfiguration gespeichert: $ConfigPath" -ForegroundColor DarkGray

# --- PowerCLI laden -----------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name 'VMware.VimAutomation.Core')) {
    throw 'PowerCLI (VMware.VimAutomation.Core) ist nicht installiert. Bitte zuerst "Install-Module VMware.PowerCLI -Scope CurrentUser" ausfuehren.'
}
Import-Module 'VMware.VimAutomation.Core' -ErrorAction Stop

$certAction = if ($ignoreCert) { 'Ignore' } else { 'Fail' }
Set-PowerCLIConfiguration -InvalidCertificateAction $certAction -Scope Session -Confirm:$false | Out-Null

# --- Anmeldeinformationen (verschluesselt) ------------------------------------
if (Test-Path -LiteralPath $credentialPath) {
    try { $credential = Import-Clixml -LiteralPath $credentialPath }
    catch { throw "Credential-Datei '$credentialPath' konnte nicht entschluesselt werden (an Benutzer/Maschine gebunden). Bitte loeschen und neu erzeugen. Details: $($_.Exception.Message)" }
    if (-not ($credential -is [System.Management.Automation.PSCredential])) {
        throw "Datei '$credentialPath' enthaelt keine gueltigen Anmeldeinformationen. Bitte loeschen und neu erzeugen."
    }
    Write-Host "Verschluesselte Anmeldeinformationen geladen ($($credential.UserName))." -ForegroundColor Cyan
}
else {
    if ($NonInteractive) { throw "Keine Credential-Datei vorhanden und NonInteractive aktiv: $credentialPath" }
    Write-Host "Keine Credential-Datei gefunden - bitte Anmeldedaten eingeben." -ForegroundColor Yellow
    $credential = Get-Credential -UserName $vcUser -Message "vCenter-Anmeldung fuer $viServer"
    $credential | Export-Clixml -LiteralPath $credentialPath -Force
    Write-Host "Anmeldeinformationen verschluesselt gespeichert: $credentialPath" -ForegroundColor Green
}

# --- Privilegienliste zusammenstellen -----------------------------------------
$privilegeIds = [System.Collections.Generic.List[string]]::new()
$BasePrivilegeIds | ForEach-Object { $privilegeIds.Add($_) }
if ($includeCrypto) {
    $CryptographicPrivilegeIds | ForEach-Object { $privilegeIds.Add($_) }
    Write-Host "Cryptographic Operations werden eingeschlossen (+$($CryptographicPrivilegeIds.Count))." -ForegroundColor Cyan
}
else {
    Write-Host "Cryptographic Operations werden NICHT eingeschlossen." -ForegroundColor Cyan
}

# --- Verbindung und Rollenerstellung ------------------------------------------
$connection = $null
try {
    Write-Host "Verbinde mit vCenter '$viServer' ..." -ForegroundColor Cyan
    $connection = Connect-VIServer -Server $viServer -Credential $credential -ErrorAction Stop

    $privileges = Get-VIPrivilege -Server $connection -Id $privilegeIds -ErrorAction Stop
    $resolvedIds = $privileges | Select-Object -ExpandProperty Id
    $missing = $privilegeIds | Where-Object { $resolvedIds -notcontains $_ }
    if ($missing) {
        throw "Folgende Privilegien-IDs wurden auf dem vCenter nicht gefunden: $($missing -join ', ')"
    }
    Write-Host "Alle $($privilegeIds.Count) Privilegien wurden aufgeloest." -ForegroundColor Green

    $existingRole = Get-VIRole -Server $connection -Name $roleName -ErrorAction SilentlyContinue
    if ($existingRole) {
        if (-not $overwrite) {
            throw "Die Rolle '$roleName' existiert bereits. Mit -Overwrite (oder Role.Overwrite=true) aktualisieren."
        }
        Write-Host "Rolle '$roleName' existiert bereits - wird aktualisiert." -ForegroundColor Yellow
        Set-VIRole -Role $existingRole -AddPrivilege $privileges -Server $connection -ErrorAction Stop | Out-Null
        $resultRole = Get-VIRole -Server $connection -Name $roleName
    }
    else {
        Write-Host "Erstelle neue Rolle '$roleName' ..." -ForegroundColor Cyan
        $resultRole = New-VIRole -Name $roleName -Privilege $privileges -Server $connection -ErrorAction Stop
    }

    if (-not [string]::IsNullOrWhiteSpace($roleDescription)) {
        try { Set-VIRole -Role $resultRole -Description $roleDescription -Server $connection -ErrorAction Stop | Out-Null }
        catch { Write-Host "Hinweis: Beschreibung konnte nicht gesetzt werden ($($_.Exception.Message))." -ForegroundColor DarkYellow }
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
