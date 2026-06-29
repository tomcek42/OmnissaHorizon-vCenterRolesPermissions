# App Volumes – Benutzerdefinierte vCenter-Rolle

PowerShell-/PowerCLI-Automatisierung zum Anlegen einer benutzerdefinierten
vCenter-Server-Rolle für das **Omnissa App Volumes Manager** Service-Konto.

Die zugewiesenen Privilegien entsprechen der **vollständigen GUI-Tabelle** aus dem
*Omnissa App Volumes Administration Guide* (Release 2603) und enthalten zusätzlich
die drei Privilegien, die im PowerCLI-Artikel der Doku fehlen.

## Inhalt

| Datei | Zweck |
|-------|-------|
| `New-AppVolumesRole.ps1` | Legt die vCenter-Rolle an (bzw. aktualisiert sie). |
| `Save-AppVolumesCredential.ps1` | Speichert die vCenter-Anmeldedaten verschlüsselt. |
| `config.json` | Zentrale Konfiguration (Server, Rollenname, Optionen). |
| `permissions.txt` | Referenz-Liste der GUI-Privilegien (Quelle für den Abgleich). |

## Schnellstart per Einzeiler (`irm`)

Die self-contained Variante `Invoke-AppVolumesRole.ps1` lässt sich direkt aus
dem Netz ausführen – ohne lokale Begleitdateien:

```powershell
irm https://raw.githubusercontent.com/tomcek42/AppVolumes-vCenter-Role/main/Invoke-AppVolumesRole.ps1 | iex
```

Das Skript fragt fehlende Angaben (vCenter-Server, Rollenname, Optionen)
interaktiv ab und speichert Konfiguration und **verschlüsselte** Anmeldedaten
**im selben Verzeichnis wie die `.ps1`**. Wird das Skript per `irm | iex`
ausgeführt (keine Datei vorhanden), landen sie im **aktuellen Arbeitsverzeichnis**.
Beim nächsten Lauf werden sie wiederverwendet.

> **`| iex` kann keine Parameter übergeben.** Wer Parameter nutzen möchte, ruft
> die Datei direkt auf (`.\Invoke-AppVolumesRole.ps1 -Server ...`) oder über einen
> Scriptblock:
> ```powershell
> & ([scriptblock]::Create((irm https://raw.githubusercontent.com/tomcek42/AppVolumes-vCenter-Role/main/Invoke-AppVolumesRole.ps1))) -Server vcenter.example.local -RoleName AppVolumes
> ```

### Zwei Varianten im Repo

| Skript | Einsatz |
|--------|---------|
| `Invoke-AppVolumesRole.ps1` | **Self-contained**, für den `irm`-Einzeiler. Keine Begleitdateien nötig, interaktiv. |
| `New-AppVolumesRole.ps1` + `Save-AppVolumesCredential.ps1` + `config.json` | Modularer, dateibasierter Workflow (siehe unten). |

## Voraussetzungen

- Windows mit PowerShell 5.1 oder PowerShell 7+
- VMware/Omnissa **PowerCLI**:
  ```powershell
  Install-Module -Name VMware.PowerCLI -Scope CurrentUser
  ```
- Ein vCenter-Konto mit der Berechtigung, Rollen anzulegen
  (z. B. Administrator), zum **Erstellen** der Rolle.

## Konfiguration (`config.json`)

```json
{
    "vCenter": {
        "Server": "vcenter.example.local",
        "Username": "svc-appvolumes@vsphere.local",
        "CredentialPath": "vcenter-credential.xml",
        "IgnoreCertificateErrors": false
    },
    "Role": {
        "Name": "AppVolumes",
        "Description": "Custom role for the Omnissa App Volumes Manager service account",
        "IncludeCryptographicOperations": false,
        "Overwrite": false
    }
}
```

| Schlüssel | Bedeutung |
|-----------|-----------|
| `vCenter.Server` | Hostname/FQDN des vCenter Servers. |
| `vCenter.Username` | Konto für die Anmeldung. Dient nur zur Vorbelegung beim Anlegen der Credential-Datei. |
| `vCenter.CredentialPath` | Pfad zur verschlüsselten Credential-Datei. Relative Pfade beziehen sich auf das Skriptverzeichnis. |
| `vCenter.IgnoreCertificateErrors` | `true` setzt das Zertifikatsverhalten der Session auf *Ignore* (z. B. selbstsignierte Zertifikate). |
| `Role.Name` | Name der zu erstellenden Rolle. |
| `Role.Description` | Beschreibung der Rolle (wird gesetzt, falls die vCenter-Version es unterstützt). |
| `Role.IncludeCryptographicOperations` | `true` ergänzt die `Cryptographer.*`-Privilegien (Direct Access + Add Disk). Nur nötig, wenn der VM-Storage Verschlüsselungsrichtlinien nutzt. |
| `Role.Overwrite` | `true` aktualisiert eine bereits vorhandene Rolle gleichen Namens, statt abzubrechen. |

## Anmeldeinformationen (verschlüsselt)

Es werden **keine Passwörter im Klartext** gespeichert. Die Anmeldedaten liegen
verschlüsselt in der Datei aus `CredentialPath` und werden über die Windows
**Data Protection API (DPAPI)** geschützt.

> **Wichtig:** Die Credential-Datei kann ausschließlich vom **selben
> Windows-Benutzer** auf der **selben Maschine** entschlüsselt werden, auf der
> sie erstellt wurde. Bei automatisierter Ausführung (z. B. geplante Aufgabe)
> müssen Erstellung und Ausführung unter demselben Konto/Host erfolgen.

Credential-Datei vorab anlegen:

```powershell
.\Save-AppVolumesCredential.ps1
```

Alternativ wird sie beim ersten Lauf von `New-AppVolumesRole.ps1` automatisch
abgefragt und gespeichert, falls sie noch nicht existiert.

## Verwendung

```powershell
# 1. config.json anpassen (mindestens Server, Username, Role.Name)

# 2. (optional) Anmeldedaten verschlüsselt hinterlegen
.\Save-AppVolumesCredential.ps1

# 3. Rolle anlegen
.\New-AppVolumesRole.ps1

# Mit abweichendem Konfigurationspfad:
.\New-AppVolumesRole.ps1 -ConfigPath "D:\Deploy\config.json"
```

Falls die PowerShell-Ausführungsrichtlinie das Skript blockiert:

```powershell
powershell -ExecutionPolicy Bypass -File .\New-AppVolumesRole.ps1
```

## Was das Skript tut

1. Liest und validiert `config.json`.
2. Lädt PowerCLI und setzt das Zertifikatsverhalten der Session.
3. Lädt die verschlüsselten Anmeldedaten (oder fragt sie ab und speichert sie).
4. Verbindet sich mit dem vCenter.
5. **Löst alle Privilegien-IDs gegen den vCenter auf und bricht ab, falls eine
   ID dort nicht existiert** – so entsteht nie eine unvollständige Rolle.
6. Legt die Rolle an – oder aktualisiert sie bei `Role.Overwrite = true`.
7. Trennt die Verbindung und meldet die finale Anzahl der Privilegien.

## Privilegien

Basis-Set (immer): **44** Privilegien = die vollständige GUI-Tabelle plus die
System-Privilegien `System.Anonymous`, `System.View`, `System.Read` (in der GUI
nicht sichtbar, für PowerCLI erforderlich).

Optional bei `IncludeCryptographicOperations = true`: zusätzlich
`Cryptographer.Access` und `Cryptographer.AddDisk` (**+2 = 46**).

Die drei in der PowerCLI-Doku fehlenden, aus der GUI ergänzten Privilegien sind:

- `Cryptographer.AddDisk` (nur im Cryptographic-Block)
- `VirtualMachine.Config.AdvancedConfig`
- `VirtualMachine.Config.QueryUnownedFiles`

## Quellen

- [Create a Custom vCenter Server Role](https://docs.omnissa.com/bundle/AppVolumesAdminGuideV2603/page/CreateaCustomvCenterServerRole.html)
- [Create a Custom vCenter Server Role Using PowerCLI](https://docs.omnissa.com/bundle/AppVolumesAdminGuideV2603/page/CreateaCustomvCenterServerRoleUsingPowerCLI.html)
