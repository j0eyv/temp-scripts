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

$ScriptVersion = '2.11-debug'
$VerbosePreference = 'Continue'

function Write-RunbookLog {
  param(
    [Parameter(Mandatory = $true)] [string]$Message,
    [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')] [string]$Level = 'INFO'
  )

  $ts = (Get-Date).ToUniversalTime().ToString('o')
  Write-Output "[$ts][$Level] $Message"
}

function Write-ExceptionDetails {
  param(
    [Parameter(Mandatory = $true)] [System.Management.Automation.ErrorRecord]$ErrorRecord
  )

  Write-Output "[EXCEPTION] Type      : $($ErrorRecord.Exception.GetType().FullName)"
  Write-Output "[EXCEPTION] Message   : $($ErrorRecord.Exception.Message)"
  if ($ErrorRecord.InvocationInfo) {
    Write-Output "[EXCEPTION] Command   : $($ErrorRecord.InvocationInfo.MyCommand)"
    Write-Output "[EXCEPTION] Script    : $($ErrorRecord.InvocationInfo.ScriptName)"
    Write-Output "[EXCEPTION] Line      : $($ErrorRecord.InvocationInfo.ScriptLineNumber)"
    Write-Output "[EXCEPTION] Position  : $($ErrorRecord.InvocationInfo.OffsetInLine)"
    Write-Output "[EXCEPTION] LineText  : $($ErrorRecord.InvocationInfo.Line)"
  }
  if ($ErrorRecord.ScriptStackTrace) {
    Write-Output "[EXCEPTION] Stack     : $($ErrorRecord.ScriptStackTrace)"
  }
}

function ConvertTo-TokenString {
  param(
    [Parameter(Mandatory = $true)] $TokenValue
  )

  if ($TokenValue -is [securestring]) {
    return [System.Net.NetworkCredential]::new('', $TokenValue).Password
  }

  return [string]$TokenValue
}

function Is-ExpiredTokenError {
  param(
    [Parameter(Mandatory = $true)] $ErrorRecord
  )

  $text = [string]$ErrorRecord
  if ($text -match 'ExpiredAuthenticationToken|Authentication token has expired|access token expiry') {
    return $true
  }

  if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Message -match 'ExpiredAuthenticationToken|Authentication token has expired|access token expiry') {
    return $true
  }

  return $false
}

function Is-ThrottlingError {
  param(
    [Parameter(Mandatory = $true)] $ErrorRecord
  )

  try {
    $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
    return $statusCode -eq 429
  } catch {
    return $false
  }
}

function Get-RetryAfterSeconds {
  param(
    [Parameter(Mandatory = $true)] $ErrorRecord,
    [int]$DefaultSeconds = 5
  )

  try {
    $retryAfter = $ErrorRecord.Exception.Response.Headers['Retry-After']
    if ($retryAfter -and [int]::TryParse([string]$retryAfter, [ref]0)) {
      return [int]$retryAfter
    }
  } catch {}

  return $DefaultSeconds
}

trap {
  Write-RunbookLog -Level 'ERROR' -Message 'Unhandled terminating error in runbook.'
  Write-ExceptionDetails -ErrorRecord $_
  throw
}

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

  try {
    # Avoid -AsSecureString for compatibility with older Az.Accounts versions in Automation.
    [void](Write-RunbookLog -Level 'DEBUG' -Message "Acquiring token for resource: $ResourceUrl")
    $tokenObj = Get-AzAccessToken -ResourceUrl $ResourceUrl
  } catch {
    [void](Write-RunbookLog -Level 'ERROR' -Message "Get-AzAccessToken failed for resource: $ResourceUrl")
    [void](Write-ExceptionDetails -ErrorRecord $_)
    throw
  }

  # Log the token type so we can diagnose future version changes in Az.Accounts.
  $rawToken = $tokenObj.Token
  [void](Write-RunbookLog -Level 'DEBUG' -Message "Token type returned by Get-AzAccessToken: $($rawToken.GetType().FullName)")

  # Convert to plain string regardless of whether Az.Accounts returns SecureString or String.
  $token = ConvertTo-TokenString -TokenValue $rawToken

  if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Failed to acquire access token for resource '$ResourceUrl'."
  }

  [void](Write-RunbookLog -Level 'DEBUG' -Message "Token acquired for resource: $ResourceUrl")
  return $token
}

function Invoke-GraphPagedGet {
  <#
  .SYNOPSIS Pages through a Graph collection endpoint and returns all items as
            a flat array, following @odata.nextLink automatically.
            Implements exponential backoff retry for 429 throttling errors.
  #>
  param(
    [Parameter(Mandatory = $true)] [string]$Path,
    [Parameter(Mandatory = $true)] $Token,
    [int]$MaxRetries = 5
  )

  $tokenString = ConvertTo-TokenString -TokenValue $Token

  $url   = "$GraphBaseUrl$Path"
  $items = [System.Collections.Generic.List[object]]::new()
  $pageCount = 0

  while ($url) {
    $retryCount = 0
    $requestCompleted = $false

    while (-not $requestCompleted -and $retryCount -lt $MaxRetries) {
      try {
        $response = Invoke-RestMethod -Method GET -Uri $url `
          -Headers @{ Authorization = "Bearer $tokenString"; ConsistencyLevel = 'eventual' }
        $requestCompleted = $true
      } catch {
        if (Is-ExpiredTokenError -ErrorRecord $_) {
          Write-RunbookLog -Level 'WARN' -Message 'Graph token expired during paging; refreshing and retrying current page.'
          $tokenString = Get-ManagedIdentityToken -ResourceUrl 'https://graph.microsoft.com'
          # Retry immediately without incrementing retry count for token expiry
          continue
        } elseif (Is-ThrottlingError -ErrorRecord $_) {
          $retryCount++
          if ($retryCount -ge $MaxRetries) {
            Write-RunbookLog -Level 'ERROR' -Message "Graph request throttled (429). Max retries ($MaxRetries) exceeded."
            throw
          }
          $waitSeconds = Get-RetryAfterSeconds -ErrorRecord $_ -DefaultSeconds ([Math]::Pow(2, $retryCount - 1))
          Write-RunbookLog -Level 'WARN' -Message "Graph request throttled (429). Retry $retryCount/$MaxRetries after $waitSeconds seconds."
          Start-Sleep -Seconds $waitSeconds
          # Retry the request
          continue
        } else {
          throw
        }
      }
    }

    if (-not $requestCompleted) {
      throw "Graph request failed after $MaxRetries retries."
    }

    $pageCount++

    $value = $null
    if ($response -is [System.Collections.IDictionary]) {
      foreach ($key in $response.Keys) {
        if ([string]$key -ieq 'value') {
          $value = $response[$key]
          break
        }
      }
    }

    if ($null -eq $value) {
      $valueProp = $response.PSObject.Properties['value']
      if (-not $valueProp) {
        $valueProp = $response.PSObject.Properties['Value']
      }
      if ($valueProp) {
        $value = $valueProp.Value
      }
    }

    if ($null -ne $value) {
      if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        foreach ($item in $value) { $items.Add($item) }
      } else {
        # Defensive fallback: Graph collection payload should always be an array.
        # If it is not, still add the single object so the run doesn't silently drop it.
        $items.Add($value)
      }
    } elseif (
      $response -is [System.Collections.IEnumerable] -and
      -not ($response -is [string]) -and
      -not ($response -is [System.Collections.IDictionary])
    ) {
      foreach ($item in $response) { $items.Add($item) }
    }

    $nextLink = $null
    if ($response -is [System.Collections.IDictionary]) {
      foreach ($key in $response.Keys) {
        if ([string]$key -ieq '@odata.nextLink' -or [string]$key -ieq 'odata.nextLink') {
          $nextLink = [string]$response[$key]
          break
        }
      }
    } else {
      $nextLinkProp = $response.PSObject.Properties['@odata.nextLink']
      if (-not $nextLinkProp) {
        $nextLinkProp = $response.PSObject.Properties['odata.nextLink']
      }
      if (-not $nextLinkProp) {
        $nextLinkProp = $response.PSObject.Properties['@odata.nextlink']
      }
      if ($nextLinkProp) {
        $nextLink = [string]$nextLinkProp.Value
      }
    }

    if (-not [string]::IsNullOrWhiteSpace($nextLink)) {
      $url = $nextLink
    } else {
      $url = $null
    }
  }

  Write-RunbookLog -Level 'DEBUG' -Message "Graph collection '$Path' pages: $pageCount, items: $($items.Count)"

  return , $items.ToArray()
}

function Get-PolicyTypeCounts {
  <#
  .SYNOPSIS Returns a hashtable with policy counts by policyType from a policy map.
  #>
  param(
    [Parameter(Mandatory = $true)] [hashtable]$PolicyMap
  )

  $counts = @{
    configuration = 0
    device        = 0
    security      = 0
    compliance    = 0
  }

  foreach ($entry in $PolicyMap.Values) {
    $type = [string]$entry.policyType
    if ($counts.ContainsKey($type)) {
      $counts[$type] = [int]$counts[$type] + 1
    }
  }

  return $counts
}

function ConvertTo-NormalizedObject {
  <#
  .SYNOPSIS Recursively sorts object properties and strips OData metadata keys
            so that two semantically identical objects always serialise to the
            same JSON string regardless of property ordering.
  #>
  param(
    [Parameter(ValueFromPipeline = $true)]
    $InputObject,

    [int]$CurrentDepth = 0,
    [int]$MaxDepth = 40,
    [hashtable]$Visited = $null
  )

  if ($CurrentDepth -ge $MaxDepth) {
    return '[MaxDepthReached]'
  }

  if ($null -eq $Visited) {
    $Visited = @{}
  }

  # Scalar pass-through
  if ($null -eq $InputObject)                      { return $null }
  if ($InputObject -is [bool])                     { return $InputObject }
  if ($InputObject -is [string])                   { return $InputObject }
  if ($InputObject -is [datetime] -or $InputObject -is [guid]) { return $InputObject }
  if ($InputObject -is [int]   -or
      $InputObject -is [long]  -or
      $InputObject -is [double]-or
      $InputObject -is [decimal]) { return $InputObject }

  $objectId = $null
  $trackObject = $false

  if (-not ($InputObject -is [ValueType])) {
    $trackObject = $true
    $objectId = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($InputObject)
    if ($Visited.ContainsKey($objectId)) {
      return '[CircularReference]'
    }
    $Visited[$objectId] = $true
  }

  try {
    # Array / list
    if ($InputObject -is [System.Collections.IEnumerable] -and
        -not ($InputObject -is [hashtable]) -and
        -not ($InputObject -is [string])) {
      $arr = [System.Collections.Generic.List[object]]::new()
      foreach ($item in $InputObject) {
        $arr.Add((ConvertTo-NormalizedObject -InputObject $item -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -Visited $Visited))
      }
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
      $sorted[$key] = ConvertTo-NormalizedObject -InputObject $val -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -Visited $Visited
    }
    return $sorted
  } finally {
    if ($trackObject -and $null -ne $objectId) {
      [void]$Visited.Remove($objectId)
    }
  }
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
    $id = if ($item -is [hashtable]) {
      [string]$item['id']
    } else {
      $idProp = $item.PSObject.Properties['id']
      if ($idProp) { [string]$idProp.Value } else { '' }
    }

    if ([string]::IsNullOrWhiteSpace($id)) { continue }

    # Resolve display name — Graph uses 'name' or 'displayName' depending on endpoint
    $name = if ($item -is [hashtable]) {
      $candidateName = [string]$item['name']
      $candidateDisplayName = [string]$item['displayName']
      if (-not [string]::IsNullOrWhiteSpace($candidateName)) {
        $candidateName
      } elseif (-not [string]::IsNullOrWhiteSpace($candidateDisplayName)) {
        $candidateDisplayName
      } else {
        $id
      }
    } else {
      $nameProp = $item.PSObject.Properties['name']
      $displayNameProp = $item.PSObject.Properties['displayName']
      $candidateName = if ($nameProp) { [string]$nameProp.Value } else { '' }
      $candidateDisplayName = if ($displayNameProp) { [string]$displayNameProp.Value } else { '' }

      if (-not [string]::IsNullOrWhiteSpace($candidateName)) {
        $candidateName
      } elseif (-not [string]::IsNullOrWhiteSpace($candidateDisplayName)) {
        $candidateDisplayName
      } else {
        $id
      }
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

    $leafDrifts = @(Get-LeafDriftItems -Previous $prevHt -Current $curHt -MaxDepth 20 -MaxDiffs 40)
    $changedFields = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $leafDrifts) {
      $changedFields.Add([string]$entry.field)
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
      driftItems   = $leafDrifts
    })
  }

  return , $events.ToArray()
}

function Add-LeafDiffs {
  <#
  .SYNOPSIS Recursively compares two normalized values and appends leaf-level
            field differences into the provided list.
  #>
  param(
    $Previous,
    $Current,
    [string]$Path,
    [int]$Depth,
    [int]$MaxDepth,
    [int]$MaxDiffs,
    [System.Collections.Generic.List[hashtable]]$Diffs
  )

  if ($Diffs.Count -ge $MaxDiffs) { return }

  $toJson = {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    return $Value | ConvertTo-Json -Depth 20 -Compress
  }

  if ($Depth -ge $MaxDepth) {
    $aJson = & $toJson $Previous
    $bJson = & $toJson $Current
    if ($aJson -ne $bJson) {
      $Diffs.Add(@{
        field = if ([string]::IsNullOrWhiteSpace($Path)) { '(root)' } else { $Path }
        previousValue = $aJson
        currentValue = $bJson
      })
    }
    return
  }

  $prevIsObject = $null -ne $Previous -and ($Previous -is [hashtable])
  $curIsObject  = $null -ne $Current  -and ($Current  -is [hashtable])

  if ($prevIsObject -and $curIsObject) {
    $keys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($k in $Previous.Keys) { [void]$keys.Add([string]$k) }
    foreach ($k in $Current.Keys)  { [void]$keys.Add([string]$k) }

    foreach ($key in ($keys | Sort-Object)) {
      if ($Diffs.Count -ge $MaxDiffs) { break }
      $nextPath = if ([string]::IsNullOrWhiteSpace($Path)) { $key } else { "$Path.$key" }
      Add-LeafDiffs -Previous $Previous[$key] -Current $Current[$key] -Path $nextPath -Depth ($Depth + 1) -MaxDepth $MaxDepth -MaxDiffs $MaxDiffs -Diffs $Diffs
    }
    return
  }

  $prevIsArray = $null -ne $Previous -and ($Previous -is [System.Collections.IEnumerable]) -and -not ($Previous -is [string]) -and -not ($Previous -is [hashtable])
  $curIsArray  = $null -ne $Current  -and ($Current  -is [System.Collections.IEnumerable]) -and -not ($Current  -is [string]) -and -not ($Current  -is [hashtable])

  if ($prevIsArray -and $curIsArray) {
    $prevArr = @($Previous)
    $curArr  = @($Current)
    $maxLen = [Math]::Max($prevArr.Count, $curArr.Count)

    for ($i = 0; $i -lt $maxLen; $i++) {
      if ($Diffs.Count -ge $MaxDiffs) { break }
      $a = if ($i -lt $prevArr.Count) { $prevArr[$i] } else { $null }
      $b = if ($i -lt $curArr.Count)  { $curArr[$i] } else { $null }
      $nextPath = if ([string]::IsNullOrWhiteSpace($Path)) { "[$i]" } else { "$Path[$i]" }
      Add-LeafDiffs -Previous $a -Current $b -Path $nextPath -Depth ($Depth + 1) -MaxDepth $MaxDepth -MaxDiffs $MaxDiffs -Diffs $Diffs
    }
    return
  }

  $left = & $toJson $Previous
  $right = & $toJson $Current
  if ($left -ne $right) {
    $Diffs.Add(@{
      field = if ([string]::IsNullOrWhiteSpace($Path)) { '(root)' } else { $Path }
      previousValue = $left
      currentValue = $right
    })
  }
}

function Get-LeafDriftItems {
  <#
  .SYNOPSIS Returns leaf-level drift items with field paths for two normalized
            hashtable values.
  #>
  param(
    [hashtable]$Previous,
    [hashtable]$Current,
    [int]$MaxDepth = 20,
    [int]$MaxDiffs = 40
  )

  $diffs = [System.Collections.Generic.List[hashtable]]::new()
  Add-LeafDiffs -Previous $Previous -Current $Current -Path '' -Depth 0 -MaxDepth $MaxDepth -MaxDiffs $MaxDiffs -Diffs $diffs
  return , $diffs.ToArray()
}

function Build-DriftDataJson {
  <#
  .SYNOPSIS Builds a size-safe JSON payload for table storage driftData.
  #>
  param(
    $DriftItems,
    [string]$FallbackPrevious,
    [string]$FallbackCurrent,
    [int]$MaxChars = 30000,
    [int]$MaxItemValueChars = 1200,
    [int]$MaxItems = 20
  )

  $truncate = {
    param([string]$Value, [int]$Limit)
    if ($null -eq $Value) { return '' }
    if ($Value.Length -le $Limit) { return $Value }
    return $Value.Substring(0, $Limit) + '...[truncated]'
  }

  $sourceItems = if ($null -ne $DriftItems -and @($DriftItems).Count -gt 0) {
    @($DriftItems)
  } else {
    @(@{
      field         = 'changeType'
      previousValue = $FallbackPrevious
      currentValue  = $FallbackCurrent
    })
  }

  $safeItems = [System.Collections.Generic.List[hashtable]]::new()
  foreach ($item in $sourceItems) {
    if ($safeItems.Count -ge $MaxItems) { break }

    $field = if ($item -is [hashtable]) { [string]$item['field'] } else { [string]$item.field }
    $previousValue = if ($item -is [hashtable]) { [string]$item['previousValue'] } else { [string]$item.previousValue }
    $currentValue = if ($item -is [hashtable]) { [string]$item['currentValue'] } else { [string]$item.currentValue }

    if ([string]::IsNullOrWhiteSpace($field)) { $field = 'unknown' }

    $safeItems.Add(@{
      field         = (& $truncate $field 300)
      previousValue = (& $truncate $previousValue $MaxItemValueChars)
      currentValue  = (& $truncate $currentValue $MaxItemValueChars)
    })
  }

  $json = $safeItems | ConvertTo-Json -Compress
  while ($json.Length -gt $MaxChars -and $safeItems.Count -gt 1) {
    $safeItems.RemoveAt($safeItems.Count - 1)
    $json = $safeItems | ConvertTo-Json -Compress
  }

  if ($json.Length -gt $MaxChars -and $safeItems.Count -eq 1) {
    $single = $safeItems[0]
    $single['previousValue'] = (& $truncate ([string]$single['previousValue']) 400)
    $single['currentValue'] = (& $truncate ([string]$single['currentValue']) 400)
    $json = @($single) | ConvertTo-Json -Compress
  }

  return $json
}

function Write-StorageBlob {
  <#
  .SYNOPSIS Writes UTF-8 text as a BlockBlob via Azure Blob Storage REST API.
  #>
  param(
    [Parameter(Mandatory = $true)] $Token,
    [Parameter(Mandatory = $true)] [string]$BlobPath,
    [Parameter(Mandatory = $true)] [string]$Text,
    [string]$ContentType = 'application/json; charset=utf-8'
  )

  $tokenString = ConvertTo-TokenString -TokenValue $Token

  $uri   = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$BlobPath"
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)

  try {
    Invoke-RestMethod -Method PUT -Uri $uri -Headers @{
      Authorization     = "Bearer $tokenString"
      'x-ms-version'    = '2021-12-02'
      'x-ms-blob-type'  = 'BlockBlob'
      'Content-Type'    = $ContentType
    } -Body $bytes | Out-Null
  } catch {
    if (Is-ExpiredTokenError -ErrorRecord $_) {
      Write-RunbookLog -Level 'WARN' -Message 'Storage token expired during blob write; refreshing and retrying.'
      $tokenString = Get-ManagedIdentityToken -ResourceUrl 'https://storage.azure.com'
      Invoke-RestMethod -Method PUT -Uri $uri -Headers @{
        Authorization     = "Bearer $tokenString"
        'x-ms-version'    = '2021-12-02'
        'x-ms-blob-type'  = 'BlockBlob'
        'Content-Type'    = $ContentType
      } -Body $bytes | Out-Null
    } else {
      throw
    }
  }
}

function Write-TableEntity {
  <#
  .SYNOPSIS Inserts a new row into an Azure Table Storage table via REST API.
  #>
  param(
    [Parameter(Mandatory = $true)] $Token,
    [Parameter(Mandatory = $true)] [string]$TableName,
    [Parameter(Mandatory = $true)] [hashtable]$Entity
  )

  $tokenString = ConvertTo-TokenString -TokenValue $Token

  $uri = "https://$StorageAccountName.table.core.windows.net/$TableName"
  $payload = $Entity | ConvertTo-Json -Depth 100 -Compress

  try {
    Invoke-RestMethod -Method POST -Uri $uri -Headers @{
      Authorization        = "Bearer $tokenString"
      'x-ms-version'       = '2019-02-02'
      Accept               = 'application/json;odata=nometadata'
      DataServiceVersion   = '3.0'
      MaxDataServiceVersion = '3.0'
      'Content-Type'       = 'application/json;odata=nometadata'
      Prefer               = 'return-no-content'
    } -Body $payload | Out-Null
  } catch {
    if (Is-ExpiredTokenError -ErrorRecord $_) {
      Write-RunbookLog -Level 'WARN' -Message "Storage token expired during table write to '$TableName'; refreshing and retrying."
      $tokenString = Get-ManagedIdentityToken -ResourceUrl 'https://storage.azure.com'
      Invoke-RestMethod -Method POST -Uri $uri -Headers @{
        Authorization        = "Bearer $tokenString"
        'x-ms-version'       = '2019-02-02'
        Accept               = 'application/json;odata=nometadata'
        DataServiceVersion   = '3.0'
        MaxDataServiceVersion = '3.0'
        'Content-Type'       = 'application/json;odata=nometadata'
        Prefer               = 'return-no-content'
      } -Body $payload | Out-Null
      return
    }

    $statusCode = 'unknown'
    $responseBody = ''
    if ($_.Exception.Response) {
      try { $statusCode = [string][int]$_.Exception.Response.StatusCode } catch {}
      try {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        $reader.Dispose()
      } catch {}
    }

    $preview = if ($payload.Length -gt 1200) { $payload.Substring(0, 1200) + '...[truncated]' } else { $payload }
    throw "Table write failed for '$TableName' (HTTP $statusCode). Response: $responseBody PayloadPreview: $preview"
  }
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

Write-RunbookLog -Message "=== Detect-PolicyDrift $(Get-Date -Format 'u') version=$ScriptVersion ==="
Write-RunbookLog -Message "Input parameters: TenantId='$TenantId' StorageAccountName='$StorageAccountName' ContainerName='$ContainerName' GraphBaseUrl='$GraphBaseUrl' BaselinePrefix='$BaselinePrefix' ChangesPrefix='$ChangesPrefix' TempPrefix='$TempPrefix'"

try {
  $azAccessTokenCmd = Get-Command Get-AzAccessToken -ErrorAction Stop
  $source = if ($azAccessTokenCmd.Source) { $azAccessTokenCmd.Source } else { 'unknown' }
  Write-RunbookLog -Message "Get-AzAccessToken command type '$($azAccessTokenCmd.CommandType)' source '$source'."
} catch {
  Write-RunbookLog -Level 'WARN' -Message 'Could not resolve Get-AzAccessToken command metadata.'
  Write-ExceptionDetails -ErrorRecord $_
}

# ── 1. Authenticate ──────────────────────────────────────────────────────────
Write-RunbookLog -Message 'Authenticating with managed identity...'
try {
  Disable-AzContextAutosave -Scope Process | Out-Null
  Write-RunbookLog -Level 'DEBUG' -Message 'Disable-AzContextAutosave completed.'
  Connect-AzAccount -Identity | Out-Null
  Write-RunbookLog -Level 'DEBUG' -Message 'Connect-AzAccount -Identity completed.'
} catch {
  Write-RunbookLog -Level 'ERROR' -Message 'Managed identity authentication failed.'
  Write-ExceptionDetails -ErrorRecord $_
  throw
}

Write-RunbookLog -Level 'DEBUG' -Message 'Attempting to acquire Graph token...'
try {
  $graphToken = Get-ManagedIdentityToken -ResourceUrl 'https://graph.microsoft.com'
  Write-RunbookLog -Level 'DEBUG' -Message "Graph token acquired. Type: $($graphToken.GetType().FullName)"
} catch {
  Write-RunbookLog -Level 'ERROR' -Message 'Failed to acquire Graph token.'
  Write-ExceptionDetails -ErrorRecord $_
  throw
}

Write-RunbookLog -Level 'DEBUG' -Message 'Attempting to acquire Storage token...'
try {
  $storageToken = Get-ManagedIdentityToken -ResourceUrl 'https://storage.azure.com'
  Write-RunbookLog -Level 'DEBUG' -Message "Storage token acquired. Type: $($storageToken.GetType().FullName)"
} catch {
  Write-RunbookLog -Level 'ERROR' -Message 'Failed to acquire Storage token.'
  Write-ExceptionDetails -ErrorRecord $_
  throw
}

$now          = [DateTime]::UtcNow
$stamp        = $now.ToString('yyyyMMddTHHmmssZ')
$nowIso       = $now.ToString('o')

# ── 2. Collect live policy data from Graph ───────────────────────────────────
Write-RunbookLog -Message 'Querying Microsoft Graph for Intune policies...'
try {
  Write-RunbookLog -Level 'DEBUG' -Message 'Fetching configuration policies...'
  $configPolicies  = Invoke-GraphPagedGet -Path '/beta/deviceManagement/configurationPolicies?$top=999' -Token $graphToken
  Write-RunbookLog -Level 'DEBUG' -Message "Configuration policies returned: $($configPolicies.Count)"
  
  Write-RunbookLog -Level 'DEBUG' -Message 'Fetching device configurations...'
  $deviceConfigs   = Invoke-GraphPagedGet -Path '/v1.0/deviceManagement/deviceConfigurations?$top=999' -Token $graphToken
  Write-RunbookLog -Level 'DEBUG' -Message "Device configurations returned: $($deviceConfigs.Count)"
  
  Write-RunbookLog -Level 'DEBUG' -Message 'Fetching security intents...'
  $securityPolicies = Invoke-GraphPagedGet -Path '/beta/deviceManagement/intents?$top=999' -Token $graphToken
  Write-RunbookLog -Level 'DEBUG' -Message "Security intents returned: $($securityPolicies.Count)"
  
  Write-RunbookLog -Level 'DEBUG' -Message 'Fetching security compliance policies...'
  $compliancePolicies = Invoke-GraphPagedGet -Path '/beta/deviceManagement/deviceCompliancePolicies?$top=999' -Token $graphToken
  Write-RunbookLog -Level 'DEBUG' -Message "Compliance policies returned: $($compliancePolicies.Count)"
} catch {
  $errMsg = "Graph query failed: $_"
  Write-RunbookLog -Level 'ERROR' -Message $errMsg
  try {
    Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
      -Note          $errMsg `
      -DriftSummary  'Run failed — Graph query error' `
      -Timestamp     $nowIso)
  } catch {
    Write-RunbookLog -Level 'WARN' -Message "Failed to write Graph error audit row: $($_.Exception.Message)"
  }
  throw
}

Write-RunbookLog -Message "  configurationPolicies : $($configPolicies.Count)"
Write-RunbookLog -Message "  deviceConfigurations  : $($deviceConfigs.Count)"
Write-RunbookLog -Message "  security intents      : $($securityPolicies.Count)"
Write-RunbookLog -Message "  compliance policies   : $($compliancePolicies.Count)"

# ── 3. Build normalised current-state map ────────────────────────────────────
$currentMap = Merge-PolicyMaps -Maps @(
  (Build-PolicyMap -PolicyType 'configuration' -Items $configPolicies),
  (Build-PolicyMap -PolicyType 'device'        -Items $deviceConfigs),
  (Build-PolicyMap -PolicyType 'security'      -Items $securityPolicies),
  (Build-PolicyMap -PolicyType 'compliance'    -Items $compliancePolicies)
)

$rawGraphTotal = $configPolicies.Count + $deviceConfigs.Count + $securityPolicies.Count + $compliancePolicies.Count
if ($rawGraphTotal -gt 0 -and $currentMap.Count -eq 0) {
  $shapeError = 'Graph payload parse mismatch: endpoint counts were non-zero but normalized policy map is empty. Aborting to avoid creating an invalid baseline.'
  Write-RunbookLog -Level 'ERROR' -Message $shapeError
  try {
    Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
      -Note         $shapeError `
      -DriftSummary 'Run failed — graph payload parse mismatch' `
      -DriftData    (@{ configuration = $configPolicies.Count; device = $deviceConfigs.Count; security = $securityPolicies.Count; compliance = $compliancePolicies.Count } | ConvertTo-Json -Compress) `
      -Timestamp    $nowIso)
  } catch {
    Write-RunbookLog -Level 'WARN' -Message "Failed to write payload-shape error audit row: $($_.Exception.Message)"
  }
  throw $shapeError
}

Write-RunbookLog -Message "Total policies in scope: $($currentMap.Count)"

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
    Write-RunbookLog -Level 'ERROR' -Message $errMsg
    try {
      Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
        -Note         $errMsg `
        -DriftSummary 'Run failed — baseline read error' `
        -Timestamp    $nowIso)
    } catch {
      Write-RunbookLog -Level 'WARN' -Message "Failed to write baseline error audit row: $($_.Exception.Message)"
    }
    throw
  }
}

# ── 5. First run — establish baseline ───────────────────────────────────────
if (-not $baselineExists) {
  Write-RunbookLog -Message 'No baseline found. Establishing initial baseline...'
  Write-StorageBlob -Token $storageToken -BlobPath $baselinePath -Text $currentSnapshotJson
  Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
    -Note         'Initial baseline established.' `
    -DriftSummary "Baseline created with $($currentMap.Count) policies" `
    -Timestamp    $nowIso)
  Write-RunbookLog -Message 'Baseline created - run complete.'
  return
}

# ── 6. Read stored baseline ──────────────────────────────────────────────────
Write-RunbookLog -Message 'Reading stored baseline for comparison...'
$baselineResponse = Invoke-WebRequest -Method GET -Uri $baselineUri -Headers @{
  Authorization  = "Bearer $storageToken"
  'x-ms-version' = '2021-12-02'
}
$baseline    = ([string]$baselineResponse.Content) | ConvertFrom-Json -AsHashtable
$baselineMap = $baseline.policies   # hashtable keyed by "<type>:<id>"

# Guardrail: if current snapshot is unexpectedly much smaller than baseline,
# skip drift projection to avoid false mass-removals from partial Graph reads.
$baselineCounts = Get-PolicyTypeCounts -PolicyMap $baselineMap
$currentCounts  = Get-PolicyTypeCounts -PolicyMap $currentMap

Write-RunbookLog -Message "Baseline policy counts: configuration=$($baselineCounts.configuration), device=$($baselineCounts.device), security=$($baselineCounts.security), compliance=$($baselineCounts.compliance), total=$($baselineMap.Count)"
Write-RunbookLog -Message "Current policy counts : configuration=$($currentCounts.configuration), device=$($currentCounts.device), security=$($currentCounts.security), compliance=$($currentCounts.compliance), total=$($currentMap.Count)"

$currentCoverage = if ($baselineMap.Count -gt 0) { [double]$currentMap.Count / [double]$baselineMap.Count } else { 1.0 }
$isSuspiciousDrop = $baselineMap.Count -ge 50 -and $currentCoverage -lt 0.6

if ($isSuspiciousDrop) {
  $coveragePct = [Math]::Round($currentCoverage * 100, 2)
  $warnMessage = "Snapshot integrity check failed: current snapshot has $($currentMap.Count) policies vs baseline $($baselineMap.Count) (${coveragePct}% coverage). Skipping drift projection to prevent false removals."
  Write-RunbookLog -Level 'WARN' -Message $warnMessage
  Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
    -Note         $warnMessage `
    -DriftSummary 'Run skipped — incomplete Graph snapshot' `
    -DriftData    (@{ baselineCount = $baselineMap.Count; currentCount = $currentMap.Count; coverage = $currentCoverage } | ConvertTo-Json -Compress) `
    -Timestamp    $nowIso)
  return
}

# ── 7. Compute drift ─────────────────────────────────────────────────────────
$events = Get-DriftEvents -Baseline $baselineMap -Current $currentMap -Timestamp $nowIso

# ── 8a. No drift — write heartbeat and exit ──────────────────────────────────
if ($events.Count -eq 0) {
  Write-RunbookLog -Message 'No drift detected. Writing heartbeat.'
  Write-TableEntity -Token $storageToken -TableName 'TenantAuditTrail' -Entity (New-AuditRow `
    -Note         'Baseline compare complete — no changes.' `
    -DriftSummary "0 changes across $($currentMap.Count) policies" `
    -Timestamp    $nowIso)
  return
}

# ── 8b. Drift detected — persist artifacts and table rows ────────────────────
Write-RunbookLog -Message "Drift detected: $($events.Count) event(s). Persisting artifacts..."
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
  $driftDataJson = Build-DriftDataJson `
    -DriftItems $event.driftItems `
    -FallbackPrevious $event.previousHash `
    -FallbackCurrent $event.currentHash

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

  Write-RunbookLog -Message "  [$($event.changeType.ToUpper())] $($event.policyType):$($event.policyId) - $($event.policyName)"
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
Write-RunbookLog -Message 'Rolling baseline forward to current snapshot...'
Write-StorageBlob -Token $storageToken -BlobPath $baselinePath -Text $currentSnapshotJson

Write-RunbookLog -Message "=== Run complete. $($events.Count) drift event(s) recorded. ==="

#endregion
