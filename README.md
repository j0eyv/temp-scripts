# Azure Automation Baseline Drift

This folder contains the new drift mechanism:

- One-time baseline capture in Blob Storage under `baseline/current.json`
- Daily Automation Account job that creates a temporary snapshot
- Baseline compare that writes only changed policies into `changes/<timestamp>/`
- Drift event projection to Table Storage in `TenantPolicyDriftEvents`

## Files

- `main.bicep`: infrastructure for Automation Account, schedule, role assignments, drift table/container
- `Detect-PolicyDrift.ps1`: runbook script that captures, compares, and persists changed artifacts

## Deployment Notes

1. Publish `Detect-PolicyDrift.ps1` to a reachable URL (for example, a raw file URL in your private artifact store).
2. Deploy `main.bicep` and pass:
   - `storageAccountName`
   - `snapshotTenantId`
   - `runbookContentUri`
3. Grant Graph app roles to the Automation Account managed identity:
   - `DeviceManagementConfiguration.Read.All`
   - `DeviceManagementServiceConfig.Read.All`

## Storage Layout

- `baseline/current.json`: immutable baseline reference after first run
- `temp/<timestamp>/current.json`: full current policy snapshot for the run
- `changes/<timestamp>/index.json`: run metadata and changed policy keys
- `changes/<timestamp>/<policyType>/<policyId>.json`: only changed policy files

The web app changelog now reads drift events from `TenantPolicyDriftEvents` and shows all modifications since baseline.
