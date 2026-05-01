<#
.SYNOPSIS
  Detects configuration drift across Microsoft Intune policies and persists results to Azure Storage.

.DESCRIPTION
  Detect-PolicyDrift.ps1 is an Azure Automation PowerShell 7.2 runbook that:
    1. Authenticates using the Automation Account's system-assigned managed identity.
    2. Reads all Intune configuration policies, device configurations, and endpoint
       security intents from Microsoft Graph.
    3. On first run, stores a normalised baseline snapshot to Azure Blob Storage.
    4. On subsequent runs, compares the live policy state against the stored baseline
       and writes one TenantPolicyDriftEvents table entity per changed policy.
    5. Writes a heartbeat / summary row to TenantAuditTrail on every run.
    6. Saves a per-run changes index and individual changed-policy blobs under
       changes/<timestamp>/ for historical audit purposes.
    7. Rolls the baseline forward to the current snapshot after recording drift so
       that the next run only surfaces new changes.

  Required RBAC assignments on the Automation Account managed identity:
    - Storage Table Data Contributor  (scope: storage account)
    - Storage Blob Data Contributor   (scope: storage account)
    - DeviceManagementConfiguration.Read.All (Microsoft Graph application permission)

.PARAMETER TenantId
  The Entra ID tenant identifier.  Used as PartitionKey in all table
  entities so rows are scoped per tenant.

.PARAMETER StorageAccountName
  Name of the Azure Storage account that holds the policy-drift blob container
  and the TenantAuditTrail / TenantPolicyDriftEvents tables.

.PARAMETER ContainerName
  Blob container that stores baseline and change artifacts.  Defaults to 'policy-drift'.

.PARAMETER GraphBaseUrl
  Microsoft Graph base URL.  Override for sovereign clouds, e.g.
  'https://graph.microsoft.us'.  Defaults to 'https://graph.microsoft.com'.

.PARAMETER BaselinePrefix
  Virtual folder inside the container for baseline blobs.  Defaults to 'baseline'.

.PARAMETER ChangesPrefix
  Virtual folder inside the container for per-run change artifacts.  Defaults to 'changes'.

.PARAMETER TempPrefix
  Virtual folder inside the container for in-flight snapshots.  Defaults to 'temp'.

.NOTES
  Runtime : PowerShell 7.2 (Azure Automation)
  Modules : Az.Accounts (bundled with Azure Automation runtime)
  Author  : inchange drift-detection pipeline
  Version : 2.0
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$TenantId,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$StorageAccountName,

  [string]$ContainerName  = 'policy-drift',
  [string]$GraphBaseUrl   = 'https://graph.microsoft.com',
  [string]$BaselinePrefix = 'baseline',
  [string]$ChangesPrefix  = 'changes',
  [string]$TempPrefix     = 'temp'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

#region ── Helpers ─────────────────────────────────────────────────────────────

function Get-ManagedIdentityToken {
  <#
  .SYNOPSIS Acquires an OAuth2 access token for the given resource using the
            Automation Account managed identity via Get-AzAccessToken.
  #>
  param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceUrl
  )

  $tokenObj = Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString:$false
  if ([string]::IsNullOrWhiteSpace($tokenObj.Token)) {
    throw "Failed to acquire access token for resource '$ResourceUrl'."
  }
  return $tokenObj.Token
}

function Invoke-GraphPagedGet {
  <#
  .SYNOPSIS Pages through a Graph collection endpoint and returns all items as
            a flat array, following @odata.nextLink automatically.
  #>
  param(
    [Parameter(Mandatory = $true)] [string]$Path,
    [Parameter(Mandatory = $true)] [string]$Token
  )

  $url   = "$GraphBaseUrl$Path"
  $items = [System.Collections.Generic.List[object]]::new()

  while ($url) {
    $response = Invoke-RestMethod -Method GET -Uri $url `
      -Headers @{ Authorization = "Bearer $Token"; ConsistencyLevel = 'eventual' }

    if ($response.value) {
      foreach ($item in $response.value) { $items.Add($item) }
    }
    $url = $response.'@odata.nextLink'
  }

  return , $items.ToArray()
}

function ConvertTo-NormalizedObject {
  <#
  .SYNOPSIS Recursively sorts object properties and strips OData metadata keys
            so that two semantically identical objects always serialise to the
            same JSON string regardless of property ordering.
  #>
  param(
    [Parameter(ValueFromPipeline = $true)]
    $InputObject
  )

  # Scalar pass-through
  if ($null -eq $InputObject)                      { return $null }
  if ($InputObject -is [bool])                     { return $InputObject }
  if ($InputObject -is [string])                   { return $InputObject }
  if ($InputObject -is [int]   -or
      $InputObject -is [long]  -or
      $InputObject -is [double]-or
      $InputObject -is [decimal]) { return $InputObject }

  # Array / list
  if ($InputObject -is [System.Collections.IEnumerable] -and
      -not ($InputObject -is [hashtable]) -and
      -not ($InputObject -is [string])) {
    $arr = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $InputObject) { $arr.Add((ConvertTo-NormalizedObject $item)) }
    return , $arr.ToArray()
  }

  # Object / hashtable — sort keys and strip OData noise
  $oDataKeys = '@odata.context', '@odata.nextLink', '@odata.etag',
               '@odata.type', '@odata.id', '@odata.count'

  $sourceKeys = if ($InputObject -is [hashtable]) {
    $InputObject.Keys
  } else {
    $InputObject.PSObject.Properties.Name
  }

  $sorted = [ordered]@{}
  foreach ($key in ($sourceKeys | Where-Object { $_ -notin $oDataKeys } | Sort-Object)) {
    $val = if ($InputObject -is [hashtable]) { $InputObject[$key] } else { $InputObject.$key }
    $sorted[$key] = ConvertTo-NormalizedObject $val
  }
  return $sorted
}

function Get-TextHash {
  <#
  .SYNOPSIS Returns a lowercase hex SHA-256 digest of the supplied UTF-8 string.
  #>
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text
  )

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function Build-PolicyMap {
  <#
  .SYNOPSIS Converts a raw Graph collection into a keyed hashtable suitable for
            hash-based diff comparison.  Key format: "<policyType>:<id>".
  #>
  param(
    [Parameter(Mandatory = $true)] [string]$PolicyType,
    [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [array]$Items
  )

  $map = @{}
  foreach ($item in $Items) {
    $id = [string]$item.id
    if ([string]::IsNullOrWhiteSpace($id)) { continue }

    # Resolve display name — Graph uses 'name' or 'displayName' depending on endpoint
    $name = if (-not [string]::IsNullOrWhiteSpace([string]$item.name)) {
      [string]$item.name
    } elseif (-not [string]::IsNullOrWhiteSpace([string]$item.displayName)) {
      [string]$item.displayName
    } else {
      $id
    }

    $normalized = ConvertTo-NormalizedObject $item
    $json       = $normalized | ConvertTo-Json -Depth 100 -Compress

    $map["$PolicyType`:$id"] = [pscustomobject]@{
      policyType = $PolicyType
      policyId   = $id
      policyName = $name
      hash       = Get-TextHash -Text $json
      normalized = $normalized
      json       = $json
    }
  }

  return $map
}

function Merge-PolicyMaps {
  <#
  .SYNOPSIS Merges multiple policy-type hashtables into a single unified map.
  #>
  param(
    [Parameter(Mandatory = $true)]
    [hashtable[]]$Maps
  )

  $all = @{}
  foreach ($m in $Maps) {
    foreach ($k in $m.Keys) { $all[$k] = $m[$k] }
  }
  return $all
}

function Get-DriftEvents {
  <#
  .SYNOPSIS Compares two policy maps and returns an array of drift event objects
            describing added, removed, and modified policies.
  #>
  param(
    [Parameter(Mandatory = $true)] [hashtable]$Baseline,
    [Parameter(Mandatory = $true)] [hashtable]$Current,
    [Parameter(Mandatory = $true)] [string]$Timestamp
  )

  $allKeys = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($k in $Baseline.Keys) { [void]$allKeys.Add($k) }
  foreach ($k in $Current.Keys)  { [void]$allKeys.Add($k) }

  $events = [System.Collections.Generic.List[pscustomobject]]::new()

  foreach ($k in $allKeys) {
    $prev = $Baseline[$k]
    $cur  = $Current[$k]

    # ── Added ────────────────────────────────────────────────────────────────
    if ($null -eq $prev -and $null -ne $cur) {
      $events.Add([pscustomobject]@{
        policyKey    = $k
        policyId     = $cur.policyId
        policyType   = $cur.policyType
        policyName   = $cur.policyName
        modifiedAt   = $Timestamp
        changeType   = 'added'
        previousHash = ''
        currentHash  = $cur.hash
        changedFields = @()
        driftItems   = @()
      })
      continue
    }

    # ── Removed ──────────────────────────────────────────────────────────────
    if ($null -ne $prev -and $null -eq $cur) {
      $events.Add([pscustomobject]@{
        policyKey    = $k
        policyId     = $prev.policyId
        policyType   = $prev.policyType
        policyName   = $prev.policyName
        modifiedAt   = $Timestamp
        changeType   = 'removed'
        previousHash = $prev.hash
        currentHash  = ''
        changedFields = @()
        driftItems   = @()
      })
      continue
    }

    # ── Unchanged ────────────────────────────────────────────────────────────
    if ($prev.hash -eq $cur.hash) { continue }

    # ── Modified — diff top-level fields ─────────────────────────────────────
    # Round-trip through JSON to get comparable hashtables regardless of
    # whether the source was a pscustomobject or already a hashtable (baseline
    # read-back scenario).
    $prevHt = $prev.normalized | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $curHt  = $cur.normalized  | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable

    $fieldSet = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($f in $prevHt.Keys) { [void]$fieldSet.Add($f) }
    foreach ($f in $curHt.Keys)  { [void]$fieldSet.Add($f) }

    $changedFields = [System.Collections.Generic.List[string]]::new()
    $driftItems    = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($f in $fieldSet) {
      $aJson = $prevHt[$f] | ConvertTo-Json -Depth 100 -Compress
      $bJson = $curHt[$f]  | ConvertTo-Json -Depth 100 -Compress
      if ($aJson -ne $bJson) {
        $changedFields.Add($f)
        $driftItems.Add(@{
          field          = $f
          previousValue  = $aJson
          currentValue   = $bJson
        })
        if ($changedFields.Count -ge 40) { break }   # guard against very wide objects
      }
    }

    $events.Add([pscustomobject]@{
      policyKey    = $k
      policyId     = $cur.policyId
      policyType   = $cur.policyType
      policyName   = $cur.policyName
      modifiedAt   = $Timestamp
      changeType   = 'modified'
      previousHash = $prev.hash
      currentHash  = $cur.hash
      changedFields = $changedFields.ToArray()
      driftItems   = $driftItems.ToArray()
    })
  }

  return , $events.ToArray()
}

function Write-StorageBlob {
  <#
  .SYNOPSIS Writes UTF-8 text as a BlockBlob via Azure Blob Storage REST API.
  #>
  param(
    [Parameter(Mandatory = $true)] [string]$Token,
    [Parameter(Mandatory = $true)] [string]$BlobPath,
    [Parameter(Mandatory = $true)] [string]$Text,
    [string]$ContentType = 'application/json; charset=utf-8'
  )

  $uri   = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$BlobPath"
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)

  Invoke-RestMethod -Method PUT -Uri $uri -Headers @{
    Authorization     = "Bearer $Token"
    'x-ms-version'    = '2021-12-02'
    'x-ms-blob-type'  = 'BlockBlob'
    'Content-Type'    = $ContentType
  } -Body $bytes | Out-Null
}

function Write-TableEntity {
  <#
  .SYNOPSIS Inserts a new row into an Azure Table Storage table via REST API.
  #>
  param(
    [Parameter(Mandatory = $true)] [string]$Token,
    [Parameter(Mandatory = $true)] [string]$TableName,
    [Parameter(Mandatory = $true)] [hashtable]$Entity
  )

  $uri = "https://$StorageAccountName.table.core.windows.net/$TableName"
  Invoke-RestMethod -Method POST -Uri $uri -Headers @{
    Authorization        = "Bearer $Token"
    'x-ms-version'       = '2019-02-02'
    Accept               = 'application/json;odata=nometadata'
    DataServiceVersion   = '3.0'
    MaxDataServiceVersion = '3.0'
    'Content-Type'       = 'application/json;odata=nometadata'
    Prefer               = 'return-no-content'
  } -Body ($Entity | ConvertTo-Json -Depth 100 -Compress) | Out-Null
}

function New-AuditRow {
  <#
  .SYNOPSIS Builds a TenantAuditTrail entity hashtable for the heartbeat / summary row.
  #>
  param(
    [string]$Note,
    [string]$DriftSummary,
    [string]$DriftData = '[]',
    [string]$Timestamp
  )
  return @{
    PartitionKey  = $TenantId
    RowKey        = [guid]::NewGuid().ToString()
    policyId      = 'tenant-drift-monitor'
    policyType    = 'system'
    policyName    = 'Tenant Drift Monitor'
    modifiedBy    = 'automation-account'
    modifiedAt    = $Timestamp
    note          = $Note
    driftSummary  = $DriftSummary
    driftData     = $DriftData
    source        = 'system'
    timestamp     = $Timestamp
  }
}

#endregion

#region ── Main ────────────────────────────────────────────────────────────────

Write-Output "=== Detect-PolicyDrift  $(Get-Date -Format 'u') ==="

# ── 1. Authenticate ──────────────────────────────────────────────────────────
Write-Output "Authenticating with managed identity..."
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity | Out-Null

$graphToken   = Get-ManagedIdentityToken -ResourceUrl 'https://graph.microsoft.com'
$storageToken = Get-ManagedIdentityToken -ResourceUrl 'https://storage.azure.com'
$now          = [DateTime]::UtcNow
$stamp        = $now.ToString('yyyyMMddTHHmmssZ')
$nowIso       = $now.ToString('o')

# ── 2. Collect live policy data from Graph ───────────────────────────────────
Write-Output "Querying Microsoft Graph for Intune policies..."
try {
  $configPolicies  = Invoke-GraphPagedGet -Path '/beta/deviceManagement/configurationPolicies?$top=999' -Token $graphToken
  $deviceConfigs   = Invoke-GraphPagedGet -Path '/v1.0/deviceManagement/deviceConfigurations?$top=999'  -Token $graphToken
  $securityPolicies = Invoke-GraphPagedGet -Path '/beta/deviceManagement/intents?$top=999'               -Token $graphToken
} catch {
  $errMsg = "Graph query failed: $_"
  Write-Error $errMsg
  Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
    -Note          $errMsg `
    -DriftSummary  'Run failed — Graph query error' `
    -Timestamp     $nowIso)
  throw
}

Write-Output "  configurationPolicies : $($configPolicies.Count)"
Write-Output "  deviceConfigurations  : $($deviceConfigs.Count)"
Write-Output "  security intents      : $($securityPolicies.Count)"

# ── 3. Build normalised current-state map ────────────────────────────────────
$currentMap = Merge-PolicyMaps -Maps @(
  (Build-PolicyMap -PolicyType 'configuration' -Items $configPolicies),
  (Build-PolicyMap -PolicyType 'device'        -Items $deviceConfigs),
  (Build-PolicyMap -PolicyType 'security'      -Items $securityPolicies)
)
Write-Output "Total policies in scope: $($currentMap.Count)"

$currentSnapshot = [ordered]@{
  capturedAt   = $nowIso
  tenantId     = $TenantId
  policyCount  = $currentMap.Count
  policies     = $currentMap
}
$currentSnapshotJson = $currentSnapshot | ConvertTo-Json -Depth 100

# Write in-flight snapshot so it can be inspected if the run aborts mid-way
$currentPath = "$TempPrefix/$stamp/current.json"
Write-StorageBlob -Token $storageToken -BlobPath $currentPath -Text $currentSnapshotJson

# ── 4. Check for existing baseline ──────────────────────────────────────────
$baselinePath = "$BaselinePrefix/current.json"
$baselineUri  = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$baselinePath"

$baselineExists = $false
try {
  Invoke-RestMethod -Method HEAD -Uri $baselineUri -Headers @{
    Authorization  = "Bearer $storageToken"
    'x-ms-version' = '2021-12-02'
  } | Out-Null
  $baselineExists = $true
} catch {
  # 404 = no baseline yet; any other error re-throws below after logging
  if ($_.Exception.Response.StatusCode.value__ -ne 404) {
    $errMsg = "Baseline HEAD check failed: $_"
    Write-Error $errMsg
    Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
      -Note         $errMsg `
      -DriftSummary 'Run failed — baseline read error' `
      -Timestamp    $nowIso)
    throw
  }
}

# ── 5. First run — establish baseline ───────────────────────────────────────
if (-not $baselineExists) {
  Write-Output "No baseline found. Establishing initial baseline..."
  Write-StorageBlob -Token $storageToken -BlobPath $baselinePath -Text $currentSnapshotJson
  Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
    -Note         'Initial baseline established.' `
    -DriftSummary "Baseline created with $($currentMap.Count) policies" `
    -Timestamp    $nowIso)
  Write-Output "Baseline created — run complete."
  return
}

# ── 6. Read stored baseline ──────────────────────────────────────────────────
Write-Output "Reading stored baseline for comparison..."
$baselineResponse = Invoke-WebRequest -Method GET -Uri $baselineUri -Headers @{
  Authorization  = "Bearer $storageToken"
  'x-ms-version' = '2021-12-02'
}
$baseline    = ([string]$baselineResponse.Content) | ConvertFrom-Json -AsHashtable
$baselineMap = $baseline.policies   # hashtable keyed by "<type>:<id>"

# ── 7. Compute drift ─────────────────────────────────────────────────────────
$events = Get-DriftEvents -Baseline $baselineMap -Current $currentMap -Timestamp $nowIso

# ── 8a. No drift — write heartbeat and exit ──────────────────────────────────
if ($events.Count -eq 0) {
  Write-Output "No drift detected. Writing heartbeat."
  Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
    -Note         'Baseline compare complete — no changes.' `
    -DriftSummary "0 changes across $($currentMap.Count) policies" `
    -Timestamp    $nowIso)
  return
}

# ── 8b. Drift detected — persist artifacts and table rows ────────────────────
Write-Output "Drift detected: $($events.Count) event(s). Persisting artifacts..."
$changesRoot = "$ChangesPrefix/$stamp"

foreach ($event in $events) {
  $safeId      = ($event.policyId -replace '[^a-zA-Z0-9\-]', '_')
  $changedBlob = "$changesRoot/$($event.policyType)/$safeId.json"

  # Blob payload: full current object for added/modified; tombstone for removed
  if ($event.changeType -eq 'removed') {
    $blobBody = [ordered]@{
      policyId      = $event.policyId
      policyType    = $event.policyType
      policyName    = $event.policyName
      changeType    = 'removed'
      previousHash  = $event.previousHash
      currentHash   = ''
      changedFields = @()
      modifiedAt    = $event.modifiedAt
    }
  } else {
    $blobBody = $currentMap[$event.policyKey]
  }

  Write-StorageBlob -Token $storageToken -BlobPath $changedBlob `
    -Text ($blobBody | ConvertTo-Json -Depth 100)

  # One TenantPolicyDriftEvents row per changed policy.
  # driftData serialises as a JSON array of {field, previousValue, currentValue}
  # matching the PolicyDriftItem interface consumed by the React app.
  $driftDataJson = if ($event.driftItems.Count -gt 0) {
    $event.driftItems | ConvertTo-Json -Depth 10 -Compress
  } else {
    # added / removed have no field-level diff — emit a single summary item
    @(@{
      field         = 'changeType'
      previousValue = $event.previousHash
      currentValue  = $event.currentHash
    }) | ConvertTo-Json -Compress
  }

  Write-TableEntity -Token $storageToken -TableName 'TenantPolicyDriftEvents' -Entity @{
    PartitionKey  = $TenantId
    RowKey        = [guid]::NewGuid().ToString()
    policyId      = $event.policyId
    policyType    = $event.policyType
    policyName    = $event.policyName
    modifiedBy    = 'automation-account'
    modifiedAt    = $event.modifiedAt
    driftSummary  = "$($event.changeType.ToUpperInvariant()) [$($event.policyType)] — $($event.policyName)"
    driftData     = $driftDataJson
    source        = 'system'
    timestamp     = $nowIso
  }

  Write-Output "  [$($event.changeType.ToUpper())] $($event.policyType):$($event.policyId) — $($event.policyName)"
}

# Run index blob (human-readable summary of the run)
$indexDoc = [ordered]@{
  runAt        = $nowIso
  tenantId     = $TenantId
  changeCount  = $events.Count
  baselinePath = $baselinePath
  tempPath     = $currentPath
  changes      = $events | Select-Object policyKey, policyId, policyType, policyName, changeType, modifiedAt, changedFields
}
Write-StorageBlob -Token $storageToken -BlobPath "$changesRoot/index.json" `
  -Text ($indexDoc | ConvertTo-Json -Depth 10)

# Audit trail summary row
Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
  -Note         "Drift run complete. $($events.Count) event(s) stored under $changesRoot." `
  -DriftSummary "$($events.Count) change(s) across $($currentMap.Count) policies" `
  -DriftData    (@{ changesRoot = $changesRoot; changeCount = $events.Count } | ConvertTo-Json -Compress) `
  -Timestamp    $nowIso)

# ── 9. Roll the baseline forward ─────────────────────────────────────────────
# Writing the current snapshot as the new baseline means the next scheduled run
# only surfaces policies that changed *after* this run — not the same ones again.
Write-Output "Rolling baseline forward to current snapshot..."
Write-StorageBlob -Token $storageToken -BlobPath $baselinePath -Text $currentSnapshotJson

Write-Output "=== Run complete. $($events.Count) drift event(s) recorded. ==="

#endregion
