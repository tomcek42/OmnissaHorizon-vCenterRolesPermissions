<#
.SYNOPSIS
    Speichert die vCenter-Anmeldeinformationen verschluesselt fuer New-AppVolumesRole.ps1.

.DESCRIPTION
    Fragt Benutzername und Passwort interaktiv ab und legt sie ueber Export-Clixml
    verschluesselt ab. Die Verschluesselung erfolgt mit der Windows Data Protection
    API (DPAPI): Die Datei kann ausschliesslich vom SELBEN Windows-Benutzer auf der
    SELBEN Maschine wieder entschluesselt werden, auf der sie erstellt wurde.

    Fuer automatisierte/geplante Ausfuehrung muss dieses Skript daher unter genau
    dem Konto und auf dem Host laufen, unter dem spaeter auch New-AppVolumesRole.ps1
    ausgefuehrt wird.

.PARAMETER ConfigPath
    Pfad zur config.json. Standard: config.json im Skriptverzeichnis.
    Username und Zielpfad (CredentialPath) werden daraus gelesen.

.PARAMETER CredentialPath
    Optionaler direkter Zielpfad fuer die Credential-Datei. Ueberschreibt den
    Wert aus der config.json.

.EXAMPLE
    .\Save-AppVolumesCredential.ps1
    .\Save-AppVolumesCredential.ps1 -CredentialPath "D:\Secure\vcenter.xml"
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath 'config.json'),
    [string]$CredentialPath
)

$ErrorActionPreference = 'Stop'

# Defaults aus config.json holen, sofern vorhanden
$defaultUser = $null
if (Test-Path -LiteralPath $ConfigPath) {
    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $defaultUser = $config.vCenter.Username
        if (-not $CredentialPath -and -not [string]::IsNullOrWhiteSpace($config.vCenter.CredentialPath)) {
            $CredentialPath = $config.vCenter.CredentialPath
        }
    }
    catch {
        Write-Host "Hinweis: config.json konnte nicht gelesen werden ($($_.Exception.Message))." -ForegroundColor DarkYellow
    }
}

if ([string]::IsNullOrWhiteSpace($CredentialPath)) {
    $CredentialPath = Join-Path -Path $PSScriptRoot -ChildPath 'vcenter-credential.xml'
}

# Relative Pfade an das Skriptverzeichnis binden
if (-not [System.IO.Path]::IsPathRooted($CredentialPath)) {
    $CredentialPath = Join-Path -Path $PSScriptRoot -ChildPath $CredentialPath
}

# Anmeldeinformationen abfragen (Username vorbelegt, falls in config.json vorhanden)
if (-not [string]::IsNullOrWhiteSpace($defaultUser)) {
    $credential = Get-Credential -UserName $defaultUser -Message 'vCenter-Anmeldeinformationen fuer App Volumes'
}
else {
    $credential = Get-Credential -Message 'vCenter-Anmeldeinformationen fuer App Volumes'
}

# Verschluesselt ablegen (DPAPI, an Benutzer + Maschine gebunden)
$credential | Export-Clixml -LiteralPath $CredentialPath -Force

Write-Host ""
Write-Host "Anmeldeinformationen verschluesselt gespeichert:" -ForegroundColor Green
Write-Host "  $CredentialPath" -ForegroundColor Green
Write-Host "Benutzer: $($credential.UserName)" -ForegroundColor Gray
Write-Host ""
Write-Host "Hinweis: Die Datei ist an diesen Windows-Benutzer und diese Maschine gebunden." -ForegroundColor Yellow
Write-Host "Fuehre New-AppVolumesRole.ps1 unter demselben Konto auf demselben Host aus." -ForegroundColor Yellow
