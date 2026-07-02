# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-07-02

### Added
- Interactive install of missing PowerShell modules during preflight: on
  confirmation the script checks whether the console is running as Administrator
  and installs the module system-wide (`Scope AllUsers`).
- When the console is not elevated, an option to launch an elevated console for
  the install; alternatively a per-user install (`Scope CurrentUser`).
- Re-verification of availability via `Get-Module -ListAvailable` after each
  install attempt.
- A startup prompt asking whether an existing `config.json` should be used as
  defaults; the product menu then defaults to the products already configured in
  it.

## [1.0.0] - 2026-06-30

### Added
- Initial release: self-contained script that creates the custom vCenter roles
  for Omnissa App Volumes and Horizon VDI (Instant Clone), menu-driven for a
  single product or both at once.
- Optional creation/assignment of a service account and role assignment at the
  vCenter root (propagated).
- Storage of defaults in `config.json`, encrypted credential storage (Windows
  DPAPI), and a vCenter 8.0 version check.

[1.1.0]: https://github.com/tomcek42/OmnissaHorizon-vCenterRolesPermissions/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/tomcek42/OmnissaHorizon-vCenterRolesPermissions/releases/tag/v1.0.0
