# Omnissa Horizon VDI + App Volumes vCenter Roles & Permissions Setup

PowerShell/PowerCLI automation that creates the custom vCenter Server roles for
**Omnissa Horizon VDI (Instant Clone)** and the **Omnissa App Volumes Manager**
service account, using the documented privilege sets from the respective Omnissa
guides. A menu lets you set up either product on its own or both at once.

## Quick start (one-liner)

```powershell
irm https://raw.githubusercontent.com/tomcek42/OmnissaHorizon-vCenterRolesPermissions/main/Invoke-OmnissaHorizon_VMwarevCenter.ps1 | iex
```

`Invoke-OmnissaHorizon_VMwarevCenter.ps1` is self-contained. On launch it shows a
menu:

```
[1] App Volumes
[2] Horizon VDI (Instant Clone)
[3] Both
[4] Exit
```

It prompts for any missing values (vCenter server, role names, options) and stores
`config.json` plus the **encrypted** credential file next to the script — or, when
run via `irm | iex`, in the current working directory. Later runs reuse them. The
vCenter connection is shared, so **Both** connects only once and creates two
independent roles and two independent service accounts.

> `| iex` cannot pass parameters. To use parameters, run the file directly
> (`.\Invoke-OmnissaHorizon_VMwarevCenter.ps1 -Server ... -Mode Both`) or via a
> script block:
> ```powershell
> & ([scriptblock]::Create((irm https://raw.githubusercontent.com/tomcek42/OmnissaHorizon-vCenterRolesPermissions/main/Invoke-OmnissaHorizon_VMwarevCenter.ps1))) -Server vcenter.example.local -Mode Both
> ```

## Roles created

| Product | Default role name | Default service account | Privilege source |
|---------|-------------------|--------------------------|------------------|
| App Volumes | `App Volumes Service` | `svc_appvolumes` | App Volumes Administration Guide |
| Horizon VDI (Instant Clone) | `Horizon VDI Service` | `svc_horizon` | Horizon 8 Installation and Upgrade — *Privileges Required for the vCenter Server User With Instant Clones* |

Each role has an optional **Cryptographic Operations** block (toggle, default off):
for App Volumes only when VM storage uses encryption policies, for Instant Clone
only for vTPM instant clones.

## Service account (optional, per product)

For each selected product the script can create the service account and assign the
role. When enabled it either:

- **creates** a new vCenter SSO user (`vsphere.local`) with a strong generated
  password (shown once), or
- **assigns** an existing principal (e.g. an AD account),

and grants the role as a permission at the **vCenter root** (propagated).

The script checks for the required modules up front and offers to install any that
are missing. Creating an SSO user requires the `VMware.vSphere.SsoAdmin` module
(`Install-Module VMware.vSphere.SsoAdmin -Scope CurrentUser`).

> Note: a vCenter role description cannot be set via PowerCLI/the vSphere API, so
> the role description is kept in `config.json` for documentation only. The service
> account, however, does get the description applied.

## Requirements

- **vCenter Server 8.0 or newer** (the script verifies the version after
  connecting and aborts on older releases)
- Windows PowerShell 5.1 or PowerShell 7+
- VMware/Omnissa PowerCLI: `Install-Module -Name VMware.PowerCLI -Scope CurrentUser`
- A vCenter account allowed to create roles and permissions (e.g. Administrator)
- For SSO account creation: the `VMware.vSphere.SsoAdmin` module

The script runs a **module preflight** before connecting: it checks that every
required module is present (and offers to install any that are missing), and
verifies the **vCenter version** right after connecting — both before any role or
permission is touched.

## Files

| File | Purpose |
|------|---------|
| `Invoke-OmnissaHorizon_VMwarevCenter.ps1` | The script (self-contained, interactive, menu-driven). |
| `Instant-Clone_PrivilegeList.json` | Reference export of the Instant Clone privileges. |
| `permissions.txt` | Reference list of the App Volumes GUI privileges. |
| `CHANGELOG.md` | Version history and notable changes. |

On first run the script writes a `config.json` and the encrypted credential file to
its working directory and reuses them on later runs. `config.json` keeps a shared
`vCenter` section and a per-product section under `Products`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the version history and notable changes.

## Credentials

No plaintext passwords are stored. Credentials are encrypted with the Windows Data
Protection API (DPAPI) via `Export-Clixml`.

> The credential file can only be decrypted by the **same Windows user** on the
> **same machine** that created it. For scheduled/automated runs, create and run
> under the same account and host.
