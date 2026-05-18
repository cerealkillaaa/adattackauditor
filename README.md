# AD Attack Surface Auditor

A read-only PowerShell tool that audits Active Directory for common attack surface risks and generates CSV + dark-mode HTML reports.

## Features

- Finds stale users
- Finds stale computers
- Detects privileged group members
- Detects AdminCount users
- Detects unconstrained delegation
- Detects constrained delegation
- Finds Kerberoastable users
- Finds AS-REP roastable users
- Finds users with passwords that never expire
- Finds users with old passwords
- Finds empty groups
- Finds users without managers
- Generates CSV and HTML reports

## Requirements

- Windows PowerShell 5.1+
- RSAT Active Directory module
- Domain read permissions

## Usage

```powershell
.\AD-Attack-Surface-Auditor.ps1 -OpenReport
