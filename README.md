# App Volumes – Custom vCenter Role

PowerShell/PowerCLI automation that creates the custom vCenter Server role for the
**Omnissa App Volumes Manager** service account, using the full privilege set from
the *App Volumes Administration Guide*.

## Quick start (one-liner)

```powershell
irm https://raw.githubusercontent.com/tomcek42/AppVolumes-vCenter-Role/main/Invoke-AppVolumesRole.ps1 | iex
```

`Invoke-AppVolumesRole.ps1` is self-contained: it prompts for any missing values
(vCenter server, role name, options) and stores `config.json` plus the
**encrypted** credential file next to the script — or, when run via `irm | iex`,
in the current working directory. Later runs reuse them.

> `| iex` cannot pass parameters. To use parameters, run the file directly
> (`.\Invoke-AppVolumesRole.ps1 -Server ...`) or via a script block:
> ```powershell
> & ([scriptblock]::Create((irm https://raw.githubusercontent.com/tomcek42/AppVolumes-vCenter-Role/main/Invoke-AppVolumesRole.ps1))) -Server vcenter.example.local -RoleName AppVolumes
> ```

## Service account (optional)

`Invoke-AppVolumesRole.ps1` can also create the service account and assign the
role. When enabled it either:

- **creates** a new vCenter SSO user (`vsphere.local`) with a strong generated
  password (shown once), or
- **assigns** an existing principal (e.g. an AD account),

and grants the role as a permission at the **vCenter root** (propagated).

The script checks for the required modules up front and offers to install any
that are missing. Creating an SSO user requires the `VMware.vSphere.SsoAdmin`
module (`Install-Module VMware.vSphere.SsoAdmin -Scope CurrentUser`).

> Note: a vCenter role description cannot be set via PowerCLI/the vSphere API, so
> the role description is kept in `config.json` for documentation only. The
> service account, however, does get the description applied.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- VMware/Omnissa PowerCLI: `Install-Module -Name VMware.PowerCLI -Scope CurrentUser`
- A vCenter account allowed to create roles and permissions (e.g. Administrator)
- For SSO account creation: the `VMware.vSphere.SsoAdmin` module

## Files

| File | Purpose |
|------|---------|
| `Invoke-AppVolumesRole.ps1` | Self-contained script for the `irm` one-liner (interactive). |
| `New-AppVolumesRole.ps1` | File-based variant driven by `config.json`. |
| `Save-AppVolumesCredential.ps1` | Stores the vCenter credentials encrypted. |
| `config.json` | Configuration for the file-based variant. |
| `permissions.txt` | Reference list of the GUI privileges. |

## Credentials

No plaintext passwords are stored. Credentials are encrypted with the Windows
Data Protection API (DPAPI) via `Export-Clixml`.

> The credential file can only be decrypted by the **same Windows user** on the
> **same machine** that created it. For scheduled/automated runs, create and run
> under the same account and host.
