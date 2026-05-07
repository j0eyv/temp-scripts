param(
  [Parameter(Mandatory = $true)] [string]$TenantId,
  [Parameter(Mandatory = $true)] [string]$StorageAccountName,
  [string]$ContainerName = 'policy-drift',
  [string]$GraphBaseUrl = 'https://graph.microsoft.com',
  [string]$BaselinePrefix = 'baseline',
  [string]$ChangesPrefix = 'changes',
  [string]$TempPrefix = 'temp'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$ScriptVersion = '3.7'
$StorageApiVersion = '2023-11-03'
$NowUtc = (Get-Date).ToUniversalTime()
$TimestampFolder = $NowUtc.ToString('yyyyMMdd-HHmmss')

function Write-RunbookLog {
  param(
    [Parameter(Mandatory = $false)] [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')] [string]$Level = 'INFO',
    [Parameter(Mandatory = $true)] [string]$Message
  )

  $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
  Write-Information "[$ts][$Level] $Message"
}

function Write-ExceptionDetails {
  param(
    [Parameter(Mandatory = $true)] $Exception,
    [Parameter(Mandatory = $false)] [string]$Context = ''
  )

  if (-not [string]::IsNullOrWhiteSpace($Context)) {
    Write-RunbookLog -Level 'ERROR' -Message $Context
  }

  Write-Information "[EXCEPTION] Type      : $($Exception.GetType().FullName)"
  Write-Information "[EXCEPTION] Message   : $($Exception.Message)"

  if ($Exception.PSObject.Properties.Name -contains 'InvocationInfo' -and $Exception.InvocationInfo) {
    Write-Information "[EXCEPTION] Command   : $($Exception.InvocationInfo.MyCommand)"
    Write-Information "[EXCEPTION] Line      : $($Exception.InvocationInfo.ScriptLineNumber)"
    Write-Information "[EXCEPTION] Position  : $($Exception.InvocationInfo.OffsetInLine)"
    Write-Information "[EXCEPTION] LineText  : $($Exception.InvocationInfo.Line)"
  }
}

function Get-HttpStatusCode {
  param([Parameter(Mandatory = $true)] $ErrorRecord)

  if ($null -eq $ErrorRecord) { return $null }

  $exception = $ErrorRecord.Exception
  if ($null -eq $exception) { return $null }

  if ($exception.PSObject.Properties.Name -contains 'Response' -and $exception.Response) {
    try {
      return [int]$exception.Response.StatusCode
    } catch {
      return $null
    }
  }

  if ($exception.PSObject.Properties.Name -contains 'StatusCode') {
    try {
      return [int]$exception.StatusCode
    } catch {
      return $null
    }
  }

  return $null
}

function Convert-TokenToPlainText {
  param(
    [Parameter(Mandatory = $true)] $TokenValue
  )

  if ($null -eq $TokenValue) {
    return ''
  }

  if ($TokenValue -is [string]) {
    return [string]$TokenValue
  }

  if ($TokenValue -is [System.Security.SecureString]) {
    $ptr = [System.IntPtr]::Zero
    try {
      $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($TokenValue)
      return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
      if ($ptr -ne [System.IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
      }
    }
  }

  return [string]$TokenValue
}

function Get-ManagedIdentityToken {
  param(
    [Parameter(Mandatory = $true)] [string]$ResourceUrl
  )

  Write-RunbookLog -Level 'DEBUG' -Message "Attempting to acquire token for '$ResourceUrl'"

  $token = $null

  try {
    $tokenResult = Get-AzAccessToken -ResourceUrl $ResourceUrl -TenantId $TenantId
    if ($tokenResult -and $tokenResult.Token) {
      $token = Convert-TokenToPlainText -TokenValue $tokenResult.Token
    }
  } catch {
    Write-RunbookLog -Level 'WARN' -Message "Get-AzAccessToken with -TenantId failed for '$ResourceUrl'. Retrying without tenant."
    try {
      $tokenResult = Get-AzAccessToken -ResourceUrl $ResourceUrl
      if ($tokenResult -and $tokenResult.Token) {
        $token = Convert-TokenToPlainText -TokenValue $tokenResult.Token
      }
    } catch {
      Write-ExceptionDetails -Exception $_.Exception -Context "Unable to acquire token for '$ResourceUrl'."
      throw
    }
  }

  if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Managed identity token was empty for resource '$ResourceUrl'."
  }

  return $token
}

function Normalize-TokenInput {
  param(
    [Parameter(Mandatory = $true)] $TokenInput,
    [Parameter(Mandatory = $false)] [string]$TokenName = 'token'
  )

  $value = $TokenInput
  if ($value -is [System.Array]) {
    if ($value.Count -gt 0) {
      $value = $value[$value.Count - 1]
    } else {
      $value = ''
    }
  }

  $normalized = Convert-TokenToPlainText -TokenValue $value
  if ([string]::IsNullOrWhiteSpace($normalized)) {
    throw "Normalized $TokenName is empty."
  }

  return $normalized
}

function Invoke-GraphRequest {
  param(
    [Parameter(Mandatory = $true)] [string]$Url,
    [Parameter(Mandatory = $true)] [string]$Token
  )

  $headers = @{ Authorization = "Bearer $Token" }
  $attempt = 0

  while ($true) {
    $attempt++
    try {
      return Invoke-RestMethod -Method Get -Uri $Url -Headers $headers -ErrorAction Stop
    } catch {
      $statusCode = Get-HttpStatusCode -ErrorRecord $_
      $isRetryable = $statusCode -in @(429, 500, 502, 503, 504)
      if (-not $isRetryable -or $attempt -ge 8) {
        throw
      }

      $retryAfter = 0
      if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.Headers) {
        $retryAfterValues = $null
        if ($_.Exception.Response.Headers.TryGetValues('Retry-After', [ref]$retryAfterValues)) {
          [void][int]::TryParse(($retryAfterValues | Select-Object -First 1), [ref]$retryAfter)
        }
      }

      if ($retryAfter -le 0) {
        $retryAfter = [math]::Min([int][math]::Pow(2, $attempt), 30)
      }

      Write-RunbookLog -Level 'WARN' -Message "Graph request throttled/failed (HTTP $statusCode). Retrying in $retryAfter second(s)."
      Start-Sleep -Seconds $retryAfter
    }
  }
}

function Invoke-GraphPagedGet {
  param(
    [Parameter(Mandatory = $true)] [string]$Path,
    [Parameter(Mandatory = $true)] [string]$Token
  )

  $items = [System.Collections.Generic.List[object]]::new()
  if ($Path.StartsWith('http')) {
    $next = $Path
  } else {
    $next = "$GraphBaseUrl$Path"
  }

  while (-not [string]::IsNullOrWhiteSpace($next)) {
    $response = Invoke-GraphRequest -Url $next -Token $Token

    if ($response.PSObject.Properties.Name -contains 'value' -and $response.value) {
      foreach ($item in $response.value) {
        [void]$items.Add($item)
      }
    }

    $next = $null
    if ($response.PSObject.Properties.Name -contains '@odata.nextLink' -and $response.'@odata.nextLink') {
      $next = [string]$response.'@odata.nextLink'
    }
  }

  return @($items)
}

function Invoke-GraphGet {
  param(
    [Parameter(Mandatory = $true)] [string]$Path,
    [Parameter(Mandatory = $true)] [string]$Token
  )

  $url = if ($Path.StartsWith('http')) { $Path } else { "$GraphBaseUrl$Path" }
  return Invoke-GraphRequest -Url $url -Token $Token
}

function Get-ObjectId {
  param([Parameter(Mandatory = $true)][AllowNull()] $Object)

  if ($null -eq $Object) { return '' }

  $id = $null
  if ($Object -is [System.Collections.IDictionary]) {
    if ($Object.Contains('id')) { $id = $Object['id'] }
  } else {
    $prop = $Object.PSObject.Properties['id']
    if ($prop) { $id = $prop.Value }
  }

  if ($null -eq $id) { return '' }
  return [string]$id
}

function Get-ObjectName {
  param([Parameter(Mandatory = $true)][AllowNull()] $Object)

  if ($null -eq $Object) { return '' }

  $candidateProps = @('displayName', 'name', 'title')
  foreach ($propName in $candidateProps) {
    if ($Object -is [System.Collections.IDictionary]) {
      if ($Object.Contains($propName) -and -not [string]::IsNullOrWhiteSpace([string]$Object[$propName])) {
        return [string]$Object[$propName]
      }
    } else {
      $prop = $Object.PSObject.Properties[$propName]
      if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
        return [string]$prop.Value
      }
    }
  }

  return ''
}

function ConvertTo-Hashtable {
  param([Parameter(Mandatory = $true)][AllowNull()] $InputObject)

  if ($null -eq $InputObject) {
    return @{}
  }

  return ($InputObject | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json -AsHashtable)
}

function Try-Invoke-GraphCollection {
  param(
    [Parameter(Mandatory = $true)] [string]$Path,
    [Parameter(Mandatory = $true)] [string]$Token,
    [Parameter(Mandatory = $true)] [string]$Label,
    [Parameter(Mandatory = $false)] [bool]$Optional = $true
  )

  try {
    return Invoke-GraphPagedGet -Path $Path -Token $Token
  } catch {
    $statusCode = Get-HttpStatusCode -ErrorRecord $_
    if ($Optional -and $statusCode -in @(400, 403, 404)) {
      Write-RunbookLog -Level 'WARN' -Message "Skipping optional Graph collection '$Label' ($Path). HTTP $statusCode."
      return @()
    }

    throw
  }
}

function Invoke-GraphDetailOptional {
  param(
    [Parameter(Mandatory = $true)] [string]$Path,
    [Parameter(Mandatory = $true)] [string]$Token,
    [Parameter(Mandatory = $true)] [string]$Label
  )

  try {
    return Invoke-GraphGet -Path $Path -Token $Token
  } catch {
    $statusCode = Get-HttpStatusCode -ErrorRecord $_
    if ($statusCode -in @(400, 403, 404)) {
      Write-RunbookLog -Level 'WARN' -Message "Skipping optional detail '$Label' ($Path). HTTP $statusCode."
      return $null
    }

    throw
  }
}

function Get-PolicyFamilies {
  $families = @(
    [ordered]@{
      type = 'configuration'
      listPath = '/beta/deviceManagement/configurationPolicies?$top=200'
      detailPathTemplate = '/beta/deviceManagement/configurationPolicies/{id}'
      settingsPathTemplate = '/beta/deviceManagement/configurationPolicies/{id}/settings?`$top=1000'
      assignmentsPathTemplate = '/beta/deviceManagement/configurationPolicies/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $false
    },
    [ordered]@{
      type = 'deviceConfiguration'
      listPath = '/beta/deviceManagement/deviceConfigurations?$top=200'
      detailPathTemplate = '/beta/deviceManagement/deviceConfigurations/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/deviceConfigurations/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $false
    },
    [ordered]@{
      type = 'securityIntent'
      listPath = '/beta/deviceManagement/intents?$top=200'
      detailPathTemplate = '/beta/deviceManagement/intents/{id}'
      settingsPathTemplate = '/beta/deviceManagement/intents/{id}/settings?`$top=1000'
      assignmentsPathTemplate = '/beta/deviceManagement/intents/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $false
    },
    [ordered]@{
      type = 'compliance'
      listPath = '/beta/deviceManagement/deviceCompliancePolicies?$top=200'
      detailPathTemplate = '/beta/deviceManagement/deviceCompliancePolicies/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/deviceCompliancePolicies/{id}/assignments?`$top=1000'
      extraCollections = @{ '_scheduledActionsForRule' = '/beta/deviceManagement/deviceCompliancePolicies/{id}/scheduledActionsForRule?`$top=1000' }
      optional = $false
    },
    [ordered]@{
      type = 'groupPolicy'
      listPath = '/beta/deviceManagement/groupPolicyConfigurations?$top=200'
      detailPathTemplate = '/beta/deviceManagement/groupPolicyConfigurations/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/groupPolicyConfigurations/{id}/assignments?`$top=1000'
      extraCollections = @{ '_definitionValues' = '/beta/deviceManagement/groupPolicyConfigurations/{id}/definitionValues?`$top=1000' }
      optional = $true
    },
    [ordered]@{
      type = 'updateRing'
      listPath = '/beta/deviceManagement/deviceConfigurations?$filter=isof(''microsoft.graph.windowsUpdateForBusinessConfiguration'')&$top=200'
      detailPathTemplate = '/beta/deviceManagement/deviceConfigurations/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/deviceConfigurations/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'featureUpdate'
      listPath = '/beta/deviceManagement/windowsFeatureUpdateProfiles?$top=200'
      detailPathTemplate = '/beta/deviceManagement/windowsFeatureUpdateProfiles/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/windowsFeatureUpdateProfiles/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'qualityUpdate'
      listPath = '/beta/deviceManagement/windowsQualityUpdateProfiles?$top=200'
      detailPathTemplate = '/beta/deviceManagement/windowsQualityUpdateProfiles/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/windowsQualityUpdateProfiles/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'driverUpdate'
      listPath = '/beta/deviceManagement/windowsDriverUpdateProfiles?$top=200'
      detailPathTemplate = '/beta/deviceManagement/windowsDriverUpdateProfiles/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/windowsDriverUpdateProfiles/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'script'
      listPath = '/beta/deviceManagement/deviceManagementScripts?$top=200'
      detailPathTemplate = '/beta/deviceManagement/deviceManagementScripts/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/deviceManagementScripts/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'healthScript'
      listPath = '/beta/deviceManagement/deviceHealthScripts?$top=200'
      detailPathTemplate = '/beta/deviceManagement/deviceHealthScripts/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/deviceHealthScripts/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'shellScript'
      listPath = '/beta/deviceManagement/deviceShellScripts?$top=200'
      detailPathTemplate = '/beta/deviceManagement/deviceShellScripts/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/deviceShellScripts/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'enrollment'
      listPath = '/beta/deviceManagement/deviceEnrollmentConfigurations?$top=200'
      detailPathTemplate = '/beta/deviceManagement/deviceEnrollmentConfigurations/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/deviceEnrollmentConfigurations/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'autopilot'
      listPath = '/beta/deviceManagement/windowsAutopilotDeploymentProfiles?$top=200'
      detailPathTemplate = '/beta/deviceManagement/windowsAutopilotDeploymentProfiles/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceManagement/windowsAutopilotDeploymentProfiles/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'appProtection'
      listPath = '/beta/deviceAppManagement/managedAppPolicies?$top=200'
      detailPathTemplate = '/beta/deviceAppManagement/managedAppPolicies/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = '/beta/deviceAppManagement/managedAppPolicies/{id}/assignments?`$top=1000'
      extraCollections = @{}
      optional = $true
    },
    [ordered]@{
      type = 'conditionalAccess'
      listPath = '/v1.0/identity/conditionalAccess/policies?$top=200'
      detailPathTemplate = '/v1.0/identity/conditionalAccess/policies/{id}'
      settingsPathTemplate = ''
      assignmentsPathTemplate = ''
      extraCollections = @{}
      optional = $true
    }
  )

  return $families
}

function Resolve-PolicyContent {
  param(
    [Parameter(Mandatory = $true)] $Family,
    [Parameter(Mandatory = $true)] $Policy,
    [Parameter(Mandatory = $true)] [string]$Token
  )

  $policyId = Get-ObjectId -Object $Policy
  if ([string]::IsNullOrWhiteSpace($policyId)) {
    throw "Policy in family '$($Family.type)' has no id."
  }

  $fallback = ConvertTo-Hashtable -InputObject $Policy
  $content = @{}

  $detailPath = ''
  if (-not [string]::IsNullOrWhiteSpace([string]$Family.detailPathTemplate)) {
    $detailPath = ([string]$Family.detailPathTemplate).Replace('{id}', $policyId)
  }

  if (-not [string]::IsNullOrWhiteSpace($detailPath)) {
    $detailObj = Invoke-GraphDetailOptional -Path $detailPath -Token $Token -Label "$($Family.type)-detail"
    if ($null -ne $detailObj) {
      $content = ConvertTo-Hashtable -InputObject $detailObj
    } else {
      $content = $fallback
    }
  } else {
    $content = $fallback
  }

  if (-not $content.ContainsKey('id') -or [string]::IsNullOrWhiteSpace([string]$content['id'])) {
    $content['id'] = $policyId
  }

  $settingsTemplate = [string]$Family.settingsPathTemplate
  if (-not [string]::IsNullOrWhiteSpace($settingsTemplate)) {
    $settingsPath = $settingsTemplate.Replace('{id}', $policyId)
    try {
      $settings = Try-Invoke-GraphCollection -Path $settingsPath -Token $Token -Label "$($Family.type)-settings" -Optional $true
      if (@($settings).Count -gt 0) {
        $content['_settings'] = @($settings)
      }
    } catch {
      Write-RunbookLog -Level 'WARN' -Message "Unable to load settings for '$($Family.type)' id '$policyId'."
    }
  }

  $assignmentsTemplate = [string]$Family.assignmentsPathTemplate
  if (-not [string]::IsNullOrWhiteSpace($assignmentsTemplate)) {
    $assignmentsPath = $assignmentsTemplate.Replace('{id}', $policyId)
    try {
      $assignments = Try-Invoke-GraphCollection -Path $assignmentsPath -Token $Token -Label "$($Family.type)-assignments" -Optional $true
      if (@($assignments).Count -gt 0) {
        $content['_assignments'] = @($assignments)
      }
    } catch {
      Write-RunbookLog -Level 'WARN' -Message "Unable to load assignments for '$($Family.type)' id '$policyId'."
    }
  }

  foreach ($extraKey in $Family.extraCollections.Keys) {
    $extraTemplate = [string]$Family.extraCollections[$extraKey]
    $extraPath = $extraTemplate.Replace('{id}', $policyId)
    try {
      $items = Try-Invoke-GraphCollection -Path $extraPath -Token $Token -Label "$($Family.type)-$extraKey" -Optional $true
      if (@($items).Count -gt 0) {
        $content[$extraKey] = @($items)
      }
    } catch {
      Write-RunbookLog -Level 'WARN' -Message "Unable to load '$extraKey' for '$($Family.type)' id '$policyId'."
    }
  }

  return $content
}

function Get-AllIntunePolicies {
  param(
    [Parameter(Mandatory = $true)] [string]$Token
  )

  $all = [System.Collections.Generic.List[object]]::new()
  $families = Get-PolicyFamilies

  foreach ($family in $families) {
    Write-RunbookLog -Level 'INFO' -Message "Fetching family '$($family.type)' ..."
    $items = Try-Invoke-GraphCollection -Path ([string]$family.listPath) -Token $Token -Label ([string]$family.type) -Optional ([bool]$family.optional)
    Write-RunbookLog -Level 'INFO' -Message "Family '$($family.type)' returned $(@($items).Count) item(s)."

    $i = 0
    $total = @($items).Count
    foreach ($item in $items) {
      $i++
      if (($i % 20) -eq 0 -or $i -eq $total) {
        Write-RunbookLog -Level 'DEBUG' -Message "Resolving content for '$($family.type)': $i/$total"
      }

      $policyId = Get-ObjectId -Object $item
      if ([string]::IsNullOrWhiteSpace($policyId)) {
        Write-RunbookLog -Level 'WARN' -Message "Skipping item without id in family '$($family.type)'."
        continue
      }

      $resolved = Resolve-PolicyContent -Family $family -Policy $item -Token $Token
      $policyName = Get-ObjectName -Object $resolved

      $record = [ordered]@{
        policyType = [string]$family.type
        policyId = [string]$policyId
        policyName = [string]$policyName
        content = $resolved
      }

      [void]$all.Add($record)
    }
  }

  return @($all)
}

function Get-StorageHeaders {
  param(
    [Parameter(Mandatory = $true)] [string]$Token,
    [Parameter(Mandatory = $false)] [string]$ContentType = ''
  )

  $headers = @{
    Authorization = "Bearer $Token"
    'x-ms-version' = $StorageApiVersion
    'x-ms-date' = (Get-Date).ToUniversalTime().ToString('R')
  }

  if (-not [string]::IsNullOrWhiteSpace($ContentType)) {
    $headers['Content-Type'] = $ContentType
  }

  return $headers
}

function New-BlobUrl {
  param(
    [Parameter(Mandatory = $true)] [string]$BlobPath,
    [Parameter(Mandatory = $false)] [string]$Query = ''
  )

  $encodedPath = ($BlobPath -split '/') | ForEach-Object { [System.Uri]::EscapeDataString($_) } | Join-String -Separator '/'
  $url = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$encodedPath"
  if (-not [string]::IsNullOrWhiteSpace($Query)) {
    return "$url`?$Query"
  }

  return $url
}

function Write-JsonBlob {
  param(
    [Parameter(Mandatory = $true)] [string]$BlobPath,
    [Parameter(Mandatory = $true)] $Data,
    [Parameter(Mandatory = $true)] [string]$StorageToken,
    [Parameter(Mandatory = $false)] [bool]$SkipIfExists = $false
  )

  if ($SkipIfExists -and (Test-BlobExists -BlobPath $BlobPath -StorageToken $StorageToken)) {
    return $false
  }

  $json = $Data | ConvertTo-Json -Depth 100
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $headers = Get-StorageHeaders -Token $StorageToken -ContentType 'application/json; charset=utf-8'
  $headers['x-ms-blob-type'] = 'BlockBlob'

  $url = New-BlobUrl -BlobPath $BlobPath
  Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $bytes -ErrorAction Stop | Out-Null
  return $true
}

function Test-BlobExists {
  param(
    [Parameter(Mandatory = $true)] [string]$BlobPath,
    [Parameter(Mandatory = $true)] [string]$StorageToken
  )

  $headers = Get-StorageHeaders -Token $StorageToken
  $url = New-BlobUrl -BlobPath $BlobPath

  try {
    Invoke-WebRequest -Method Head -Uri $url -Headers $headers -UseBasicParsing -ErrorAction Stop | Out-Null
    return $true
  } catch {
    $statusCode = Get-HttpStatusCode -ErrorRecord $_
    if ($statusCode -eq 404) {
      return $false
    }

    throw
  }
}

function Read-JsonBlob {
  param(
    [Parameter(Mandatory = $true)] [string]$BlobPath,
    [Parameter(Mandatory = $true)] [string]$StorageToken
  )

  $headers = Get-StorageHeaders -Token $StorageToken
  $url = New-BlobUrl -BlobPath $BlobPath
  return Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
}

function Get-BlobNamesByPrefix {
  param(
    [Parameter(Mandatory = $true)] [string]$Prefix,
    [Parameter(Mandatory = $true)] [string]$StorageToken
  )

  $headers = Get-StorageHeaders -Token $StorageToken
  $names = [System.Collections.Generic.List[string]]::new()
  $marker = ''

  while ($true) {
    $query = "restype=container&comp=list&prefix=$([System.Uri]::EscapeDataString($Prefix))&maxresults=5000"
    if (-not [string]::IsNullOrWhiteSpace($marker)) {
      $query = "$query&marker=$([System.Uri]::EscapeDataString($marker))"
    }

    $url = "https://$StorageAccountName.blob.core.windows.net/$ContainerName`?$query"
    $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop

    $resultRoot = $response
    if ($response -is [System.Xml.XmlDocument] -and $response.EnumerationResults) {
      $resultRoot = $response.EnumerationResults
    } elseif ($response.PSObject.Properties.Name -contains 'EnumerationResults' -and $response.EnumerationResults) {
      $resultRoot = $response.EnumerationResults
    }

    if ($resultRoot.Blobs -and $resultRoot.Blobs.Blob) {
      foreach ($blob in @($resultRoot.Blobs.Blob)) {
        [void]$names.Add([string]$blob.Name)
      }
    }

    $nextMarker = [string]$resultRoot.NextMarker
    if ([string]::IsNullOrWhiteSpace($nextMarker)) {
      break
    }

    $marker = $nextMarker
  }

  return @($names)
}

function Remove-Blob {
  param(
    [Parameter(Mandatory = $true)] [string]$BlobPath,
    [Parameter(Mandatory = $true)] [string]$StorageToken
  )

  $headers = Get-StorageHeaders -Token $StorageToken
  $url = New-BlobUrl -BlobPath $BlobPath
  Invoke-RestMethod -Method Delete -Uri $url -Headers $headers -ErrorAction Stop | Out-Null
}

function Remove-BlobsByPrefix {
  param(
    [Parameter(Mandatory = $true)] [string]$Prefix,
    [Parameter(Mandatory = $true)] [string]$StorageToken
  )

  $blobNames = Get-BlobNamesByPrefix -Prefix $Prefix -StorageToken $StorageToken
  $removed = 0

  foreach ($blobName in $blobNames) {
    Remove-Blob -BlobPath $blobName -StorageToken $StorageToken
    $removed++
  }

  return $removed
}

function ConvertTo-NormalizedObject {
  param([Parameter(Mandatory = $true)][AllowNull()] $InputObject)

  if ($null -eq $InputObject) { return $null }

  if ($InputObject -is [System.Collections.IDictionary]) {
    $ordered = [ordered]@{}
    foreach ($key in ($InputObject.Keys | Sort-Object)) {
      $ordered[[string]$key] = ConvertTo-NormalizedObject -InputObject $InputObject[$key]
    }

    return $ordered
  }

  if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
    $arr = @()
    foreach ($x in $InputObject) {
      $arr += ,(ConvertTo-NormalizedObject -InputObject $x)
    }

    return $arr
  }

  return $InputObject
}

function Get-NormalizedJson {
  param([Parameter(Mandatory = $true)] $Object)

  $normalized = ConvertTo-NormalizedObject -InputObject $Object
  return ($normalized | ConvertTo-Json -Depth 100 -Compress)
}

function Build-PolicyKey {
  param(
    [Parameter(Mandatory = $true)] [string]$PolicyType,
    [Parameter(Mandatory = $true)] [string]$PolicyId
  )

  return ($PolicyType + ':' + $PolicyId)
}

function Save-PoliciesToPrefix {
  param(
    [Parameter(Mandatory = $true)] [array]$Policies,
    [Parameter(Mandatory = $true)] [string]$Prefix,
    [Parameter(Mandatory = $true)] [string]$StorageToken,
    [Parameter(Mandatory = $false)] [bool]$SkipIfExists = $false
  )

  $savedCount = 0

  foreach ($policy in $Policies) {
    $type = [string]$policy.policyType
    $id = [string]$policy.policyId
    $blobPath = "$Prefix/$type/$id.json"

    $wrote = Write-JsonBlob -BlobPath $blobPath -Data $policy.content -StorageToken $StorageToken -SkipIfExists $SkipIfExists
    if ($wrote) {
      $savedCount++
    }
  }

  return $savedCount
}

function Compare-And-WriteChanges {
  param(
    [Parameter(Mandatory = $true)] [array]$TempPolicies,
    [Parameter(Mandatory = $true)] [string]$BaselinePrefix,
    [Parameter(Mandatory = $true)] [string]$ChangesPrefix,
    [Parameter(Mandatory = $true)] [string]$StorageToken,
    [Parameter(Mandatory = $true)] [string]$TimestampFolder
  )

  $changesWritten = 0
  $currentKeys = [System.Collections.Generic.HashSet[string]]::new()

  foreach ($policy in $TempPolicies) {
    $type = [string]$policy.policyType
    $id = [string]$policy.policyId
    $name = [string]$policy.policyName

    $key = Build-PolicyKey -PolicyType $type -PolicyId $id
    [void]$currentKeys.Add($key)

    $baselinePath = "$BaselinePrefix/$type/$id.json"
    $changePath = "$ChangesPrefix/$TimestampFolder/$type/$id.json"

    $baselineExists = Test-BlobExists -BlobPath $baselinePath -StorageToken $StorageToken
    $currentJson = Get-NormalizedJson -Object $policy.content

    if (-not $baselineExists) {
      $doc = [ordered]@{
        changeType = 'added'
        policyType = $type
        policyId = $id
        policyName = $name
        detectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        baselineExists = $false
        current = $policy.content
      }

      [void](Write-JsonBlob -BlobPath $changePath -Data $doc -StorageToken $StorageToken)
      $changesWritten++
      continue
    }

    $baselineContent = Read-JsonBlob -BlobPath $baselinePath -StorageToken $StorageToken
    $baselineJson = Get-NormalizedJson -Object $baselineContent

    if ($baselineJson -ne $currentJson) {
      $doc = [ordered]@{
        changeType = 'modified'
        policyType = $type
        policyId = $id
        policyName = $name
        detectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        baseline = $baselineContent
        current = $policy.content
      }

      [void](Write-JsonBlob -BlobPath $changePath -Data $doc -StorageToken $StorageToken)
      $changesWritten++
    }
  }

  $baselineBlobNames = Get-BlobNamesByPrefix -Prefix "$BaselinePrefix/" -StorageToken $StorageToken
  foreach ($baselineBlob in $baselineBlobNames) {
    if ($baselineBlob -like '*/_baseline.complete.json') { continue }
    if ($baselineBlob -notlike '*.json') { continue }

    $relative = $baselineBlob.Substring(("$BaselinePrefix/").Length)
    $slash = $relative.IndexOf('/')
    if ($slash -lt 1) { continue }

    $type = $relative.Substring(0, $slash)
    $fileName = $relative.Substring($slash + 1)
    if (-not $fileName.EndsWith('.json')) { continue }

    $id = $fileName.Substring(0, $fileName.Length - 5)
    $key = Build-PolicyKey -PolicyType $type -PolicyId $id

    if ($currentKeys.Contains($key)) { continue }

    $baselineContent = Read-JsonBlob -BlobPath $baselineBlob -StorageToken $StorageToken
    $changePath = "$ChangesPrefix/$TimestampFolder/$type/$id.json"

    $doc = [ordered]@{
      changeType = 'removed'
      policyType = $type
      policyId = $id
      policyName = (Get-ObjectName -Object $baselineContent)
      detectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
      baseline = $baselineContent
      current = $null
    }

    [void](Write-JsonBlob -BlobPath $changePath -Data $doc -StorageToken $StorageToken)
    $changesWritten++
  }

  return $changesWritten
}

try {
  Write-RunbookLog -Message "=== Detect-PolicyDrift $($NowUtc.ToString('yyyy-MM-dd HH:mm:ssZ')) version=$ScriptVersion ==="
  Write-RunbookLog -Message "Input parameters: TenantId='$TenantId' StorageAccountName='$StorageAccountName' ContainerName='$ContainerName' GraphBaseUrl='$GraphBaseUrl' BaselinePrefix='$BaselinePrefix' ChangesPrefix='$ChangesPrefix' TempPrefix='$TempPrefix'"

  Write-RunbookLog -Level 'INFO' -Message 'Authenticating with managed identity...'
  Disable-AzContextAutosave -Scope Process | Out-Null
  Connect-AzAccount -Identity -Tenant $TenantId | Out-Null

  $graphTokenRaw = Get-ManagedIdentityToken -ResourceUrl 'https://graph.microsoft.com/'
  $storageTokenRaw = Get-ManagedIdentityToken -ResourceUrl 'https://storage.azure.com/'
  $graphToken = Normalize-TokenInput -TokenInput $graphTokenRaw -TokenName 'graph token'
  $storageToken = Normalize-TokenInput -TokenInput $storageTokenRaw -TokenName 'storage token'

  $baselineMarkerPath = "$BaselinePrefix/_baseline.complete.json"
  $baselineExists = Test-BlobExists -BlobPath $baselineMarkerPath -StorageToken $storageToken

  if (-not $baselineExists) {
    Write-RunbookLog -Level 'INFO' -Message "Baseline marker not found. Creating one-time baseline under '$BaselinePrefix/' only."

    Write-RunbookLog -Level 'INFO' -Message 'Collecting full Intune policy backup from Microsoft Graph for baseline...'
    $policies = Get-AllIntunePolicies -Token $graphToken
    Write-RunbookLog -Level 'INFO' -Message "Resolved total policy objects for baseline: $(@($policies).Count)"

    $baselineSaved = Save-PoliciesToPrefix -Policies $policies -Prefix $BaselinePrefix -StorageToken $storageToken -SkipIfExists $true

    $baselineDoc = [ordered]@{
      createdAtUtc = (Get-Date).ToUniversalTime().ToString('o')
      scriptVersion = $ScriptVersion
      totalPolicies = @($policies).Count
      baselinePrefix = $BaselinePrefix
      note = 'Baseline is write-once. Existing baseline policy files are not overwritten.'
    }

    [void](Write-JsonBlob -BlobPath $baselineMarkerPath -Data $baselineDoc -StorageToken $storageToken -SkipIfExists $true)
    Write-RunbookLog -Level 'INFO' -Message "Baseline initialized. New baseline policy files written: $baselineSaved"
    Write-RunbookLog -Level 'INFO' -Message 'Runbook completed successfully (baseline-only run).'
    return
  }

  Write-RunbookLog -Level 'INFO' -Message "Baseline exists at '$BaselinePrefix/'. Running temp snapshot, diff, and cleanup flow."

  Write-RunbookLog -Level 'INFO' -Message 'Collecting full Intune policy backup from Microsoft Graph...'
  $policies = Get-AllIntunePolicies -Token $graphToken
  Write-RunbookLog -Level 'INFO' -Message "Resolved total policy objects: $(@($policies).Count)"

  $tempRoot = "$TempPrefix/$TimestampFolder"
  $tempSaved = Save-PoliciesToPrefix -Policies $policies -Prefix $tempRoot -StorageToken $storageToken -SkipIfExists $false

  $tempManifest = [ordered]@{
    scriptVersion = $ScriptVersion
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    totalPolicies = @($policies).Count
    tempRoot = $tempRoot
  }
  [void](Write-JsonBlob -BlobPath "$tempRoot/_manifest.json" -Data $tempManifest -StorageToken $storageToken)
  Write-RunbookLog -Level 'INFO' -Message "Temp snapshot written: '$tempRoot' with $tempSaved policy JSON file(s)."

  $changesWritten = Compare-And-WriteChanges -TempPolicies $policies -BaselinePrefix $BaselinePrefix -ChangesPrefix $ChangesPrefix -StorageToken $storageToken -TimestampFolder $TimestampFolder

  $changesSummary = [ordered]@{
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    scriptVersion = $ScriptVersion
    baselinePrefix = $BaselinePrefix
    tempRoot = $tempRoot
    changesRoot = "$ChangesPrefix/$TimestampFolder"
    totalPoliciesEvaluated = @($policies).Count
    changedPolicies = $changesWritten
  }

  [void](Write-JsonBlob -BlobPath "$ChangesPrefix/$TimestampFolder/_summary.json" -Data $changesSummary -StorageToken $storageToken)
  Write-RunbookLog -Level 'INFO' -Message "Changes written: $changesWritten file(s) under '$ChangesPrefix/$TimestampFolder/'."

  try {
    $removedTemp = Remove-BlobsByPrefix -Prefix "$tempRoot/" -StorageToken $storageToken
    Write-RunbookLog -Level 'INFO' -Message "Temp cleanup complete. Removed $removedTemp blob(s) from '$tempRoot/'."
  } catch {
    Write-RunbookLog -Level 'WARN' -Message "Temp cleanup failed for '$tempRoot/'."
    Write-ExceptionDetails -Exception $_.Exception
  }

  Write-RunbookLog -Level 'INFO' -Message 'Runbook completed successfully.'
} catch {
  Write-RunbookLog -Level 'ERROR' -Message 'Unhandled terminating error in runbook.'
  Write-ExceptionDetails -Exception $_.Exception
  throw
}
