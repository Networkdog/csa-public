#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('snapshot', 'diff')]
    [string]$Mode = 'snapshot',
    [string]$ManagementGroup,
    [string]$Output,
    [string]$Before,
    [string]$After,
    [ValidateRange(1, 2147483647)]
    [int]$MaxAttempts = 3,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

class RaRetryableError : System.Exception {
    RaRetryableError([string]$message) : base($message) {}
}

$script:RaMgPrefix = '/providers/Microsoft.Management/managementGroups/'
$script:RaMarker = '/providers/microsoft.authorization/roleassignments/'
$script:RaFields = @(
    'RoleAssignmentId', 'ManagementGroupName', 'SubscriptionName', 'ResourceGroupName',
    'ResourceName', 'RoleName', 'Scope', 'ScopeType', 'ManagementGroupId',
    'SubscriptionId', 'RoleDefinitionId', 'PrincipalId'
)
$script:RaInitialPartitions = 1
$script:RaRowLimit = 1000
$script:RaMaxModulus = 1048576
$script:RaContext = $null
$script:RaStage = 'initialization'
$script:RaAssignmentsQuery = @'
AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| where properties.principalType =~ 'User'
| project id, scope=tostring(properties.scope),
    roleDefinitionId=tostring(properties.roleDefinitionId),
    principalId=tostring(properties.principalId),
    principalType=tostring(properties.principalType)
| order by id asc
'@
$script:RaRolesQuery = @'
AuthorizationResources
| where type =~ 'microsoft.authorization/roledefinitions'
| project id, roleName=tostring(properties.roleName)
| order by id asc
'@
$script:RaSubscriptionsQuery = @'
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions'
| project id
| order by id asc
'@

function Assert-Ra {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw [System.InvalidOperationException]::new($Message) }
}

function Get-RaProperty {
    param($Value, [string]$Name)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Contains($Name)) { return ,$Value[$Name] }
        return $null
    }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -ne $property) { return ,$property.Value }
    return $null
}

function Get-RaText {
    param($Value, [string]$Label)
    Assert-Ra ($Value -is [string] -and -not [string]::IsNullOrWhiteSpace($Value)) "Missing/invalid $Label."
    return $Value.Trim()
}

function Get-RaCanonical {
    param([string]$Value)
    return $Value.Trim().TrimEnd('/').ToLowerInvariant()
}

function Get-RaGuid {
    param([string]$Value)
    $parsed = [guid]::Empty
    Assert-Ra ([guid]::TryParse($Value, [ref]$parsed)) "Invalid GUID: $Value"
    return $parsed.ToString('D')
}

function Get-RaRoleGuid {
    param([string]$Value)
    $key = Get-RaCanonical $Value
    Assert-Ra ($key -match '^/(?:[^/?#]+/)*providers/microsoft\.authorization/roledefinitions/[0-9a-f-]{36}$') "Invalid role definition ID: $Value"
    return Get-RaGuid $key.Substring($key.LastIndexOf('/') + 1)
}

function Get-RaGroup {
    param([string]$Value)
    if ($Value.StartsWith($script:RaMgPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $Value = $Value.Substring($script:RaMgPrefix.Length).TrimEnd('/')
    }
    Assert-Ra ($Value -cmatch '^[A-Za-z0-9_.()-]{1,90}$') 'Use the management group ID or its full ARM ID, not its display name.'
    return $Value
}

function Get-RaStamp {
    return [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.ffffffzzz', [Globalization.CultureInfo]::InvariantCulture)
}

function Resolve-RaFilePath {
    param([string]$Path)
    $provider = $null
    $drive = $null
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        (Get-RaText $Path 'file path'), [ref]$provider, [ref]$drive
    )
    Assert-Ra ($provider.Name -ceq 'FileSystem') 'CSV paths must use the FileSystem provider.'
    return $resolved
}

function Write-RaStage {
    param([string]$Stage)
    $script:RaStage = $Stage
    [Console]::Error.WriteLine("INFO: $Stage")
}

function Get-RaHash {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function ConvertFrom-RaJsonElement {
    param([System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind.ToString()) {
        'Object' {
            $result = @{}
            foreach ($property in $Element.EnumerateObject()) {
                Assert-Ra (-not $result.ContainsKey($property.Name)) 'Duplicate JSON property.'
                $result[$property.Name] = ConvertFrom-RaJsonElement $property.Value
            }
            return $result
        }
        'Array' {
            $result = [Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) { $result.Add((ConvertFrom-RaJsonElement $item)) }
            return ,$result.ToArray()
        }
        'String' { return $Element.GetString() }
        'Number' {
            $integer = 0L
            if ($Element.TryGetInt64([ref]$integer)) { return $integer }
            return $Element.GetDouble()
        }
        'True' { return $true }
        'False' { return $false }
        'Null' { return $null }
        default { throw 'Unsupported JSON value.' }
    }
}

function ConvertFrom-RaJson {
    param([string]$Json)
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 100
    $document = [System.Text.Json.JsonDocument]::Parse($Json, $options)
    try { return ,(ConvertFrom-RaJsonElement $document.RootElement) }
    finally { $document.Dispose() }
}

function Get-RaIdentity {
    $context = Get-AzContext -ErrorAction Stop
    Assert-Ra ($null -ne $context) 'Run Connect-AzAccount with an Entra user account first.'
    $account = Get-RaProperty $context 'Account'
    Assert-Ra ((Get-RaProperty $account 'Type') -ceq 'User') 'Only an Entra user account is supported.'
    Assert-Ra ((Get-RaProperty (Get-RaProperty $context 'Environment') 'Name') -ceq 'AzureCloud') 'Only AzureCloud is supported.'
    $tenant = Get-RaGuid (Get-RaText (Get-RaProperty (Get-RaProperty $context 'Tenant') 'Id') 'tenantId')
    $user = (Get-RaText (Get-RaProperty $account 'Id') 'account ID').ToLowerInvariant()
    $script:RaContext = $context
    return @{ tenantId = $tenant; accountFingerprint = Get-RaHash ([Text.Encoding]::UTF8.GetBytes($user)) }
}

function Invoke-RaRest {
    param([string]$Path, [System.Collections.IDictionary]$Body)
    Assert-Ra ($Path.StartsWith('/') -and -not $Path.StartsWith('//')) 'Invalid ARM path.'
    $parameters = @{ Path = $Path; Method = 'GET'; DefaultProfile = $script:RaContext; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $parameters.Method = 'POST'
        $parameters.Payload = ConvertTo-Json -InputObject $Body -Depth 50 -Compress
    }
    try { $response = Invoke-AzRestMethod @parameters }
    catch [System.TimeoutException] { throw [RaRetryableError]::new('Azure PowerShell request timed out.') }
    Assert-Ra ([int](Get-RaProperty $response 'StatusCode') -eq 200) "ARM request failed: HTTP $(Get-RaProperty $response 'StatusCode')."
    $data = ConvertFrom-RaJson (Get-RaText (Get-RaProperty $response 'Content') 'ARM JSON')
    Assert-Ra ($data -is [System.Collections.IDictionary]) 'ARM returned a non-object response.'
    return $data
}

function Get-RaPartition {
    param([string]$Group, [string]$Query, [string]$ScopeFilter, [int]$Bucket, [int]$Modulus, [int]$Attempts)
    $queryName = if ($Query -ceq $script:RaAssignmentsQuery) { 'AuthorizationResources.roleassignments' }
                 elseif ($Query -ceq $script:RaRolesQuery) { 'AuthorizationResources.roledefinitions' }
                 elseif ($Query -ceq $script:RaSubscriptionsQuery) { 'ResourceContainers.subscriptions' }
                 else { 'ARG query' }
    $label = "query=$queryName, partition=$Bucket/$Modulus"
    $partitionQuery = $Query + "`n| where hash(tolower(id)) % $Modulus == $Bucket"
    $attempt = 1
    while ($true) {
        try {
            Write-Verbose "ARG request: $label, attempt=$attempt/$Attempts"
            $page = Invoke-RaRest '/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01' @{
                managementGroups = @($Group); query = $partitionQuery
                options = @{
                    '$top' = $script:RaRowLimit; resultFormat = 'objectArray'
                    allowPartialScopes = $false; authorizationScopeFilter = $ScopeFilter
                }
            }
            $data = Get-RaProperty $page 'data'
            $count = Get-RaProperty $page 'count'
            $total = Get-RaProperty $page 'totalRecords'
            Assert-Ra ($data -is [array]) "ARG returned invalid data: $label."
            Assert-Ra (($count -is [int] -or $count -is [long]) -and $count -eq $data.Count -and $count -le $script:RaRowLimit) "ARG partition count mismatch: $label."
            Assert-Ra (($total -is [int] -or $total -is [long]) -and $total -ge $count) "ARG returned invalid totalRecords: $label."
            $truncated = Get-RaProperty $page 'resultTruncated'
            Assert-Ra ($truncated -is [bool] -or ($truncated -is [string] -and $truncated -cin @('true', 'false'))) "ARG omitted resultTruncated: $label."
            $token = Get-RaProperty $page '$skipToken'
            Assert-Ra ($null -eq $token -or $token -is [string]) "ARG returned invalid token: $label."
            $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($row in $data) {
                Assert-Ra ($row -is [System.Collections.IDictionary]) "ARG returned invalid row: $label."
                $id = Get-RaCanonical (Get-RaText (Get-RaProperty $row 'id') 'ARG id')
                Assert-Ra ($ids.Add($id)) "ARG returned duplicate IDs within partition: $label."
            }
            if ($total -gt $script:RaRowLimit) { return @{ split = $true; rows = @() } }
            $isTruncated = ($truncated -is [bool] -and $truncated) -or ($truncated -is [string] -and $truncated -ceq 'true')
            if ($count -ne $total -or $isTruncated -or $token) {
                throw [RaRetryableError]::new("ARG partition is incomplete: $label, count=$count, totalRecords=$total.")
            }
            Write-Verbose "ARG complete: $label, rows=$count"
            return @{ split = $false; rows = $data }
        }
        catch [RaRetryableError] {
            if ($attempt -ge $Attempts) {
                throw [System.InvalidOperationException]::new("ARG partition failed after $Attempts attempts: $label. No snapshot was written. $($_.Exception.Message)")
            }
            $delay = [Math]::Min(10L * $attempt, 60)
            [Console]::Error.WriteLine("WARNING: $($_.Exception.Message) attempt=$attempt/$Attempts; retrying only this partition in ${delay}s.")
            Start-Sleep -Seconds $delay
            $attempt++
        }
    }
}

function Get-RaQuery {
    param([string]$Group, [string]$Query, [string]$ScopeFilter = 'AtScopeAndBelow', [int]$Attempts = 3)
    $pending = [Collections.Generic.Stack[object]]::new()
    for ($bucket = $script:RaInitialPartitions - 1; $bucket -ge 0; $bucket--) {
        $pending.Push(@{ bucket = $bucket; modulus = $script:RaInitialPartitions })
    }
    $rows = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    while ($pending.Count) {
        $partition = $pending.Pop()
        $result = Get-RaPartition $Group $Query $ScopeFilter $partition.bucket $partition.modulus $Attempts
        if ($result.split) {
            Assert-Ra ($partition.modulus -lt $script:RaMaxModulus) 'ARG partition remains oversized at the split limit. No snapshot was written.'
            [Console]::Error.WriteLine("WARNING: Splitting oversized ARG partition $($partition.bucket)/$($partition.modulus).")
            $pending.Push(@{ bucket = $partition.bucket + $partition.modulus; modulus = $partition.modulus * 2 })
            $pending.Push(@{ bucket = $partition.bucket; modulus = $partition.modulus * 2 })
            continue
        }
        foreach ($row in $result.rows) {
            $key = Get-RaCanonical $row.id
            Assert-Ra (-not $rows.ContainsKey($key)) 'ARG returned duplicate IDs across partitions.'
            $rows.Add($key, $row)
        }
    }
    $keys = [string[]]@($rows.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $ordered = [Collections.Generic.List[object]]::new()
    foreach ($key in $keys) { $ordered.Add($rows[$key]) }
    return ,$ordered.ToArray()
}

function Add-RaHierarchyNode {
    param([System.Collections.IDictionary]$Node, [string]$Parent, [System.Collections.IDictionary]$Result)
    $key = Get-RaCanonical (Get-RaText (Get-RaProperty $Node 'id') 'hierarchy ID')
    Assert-Ra (-not $Result.Contains($key)) 'Duplicate hierarchy ID.'
    $properties = Get-RaProperty $Node 'properties'
    if ($null -eq $properties) { $properties = $Node }
    $name = Get-RaText (Get-RaProperty $properties 'displayName') 'hierarchy display name'
    if ($key.StartsWith($script:RaMgPrefix.ToLowerInvariant())) {
        Assert-Ra (-not $key.Substring($script:RaMgPrefix.Length).Contains('/')) 'Invalid MG hierarchy ID.'
        $kind = 'ManagementGroup'
    }
    else {
        Assert-Ra ($key -match '^/subscriptions/[0-9a-f-]{36}$') "Unexpected hierarchy resource: $key"
        $null = Get-RaGuid $key.Substring($key.LastIndexOf('/') + 1)
        $kind = 'Subscription'
    }
    $Result[$key] = @{ name = $name; parent = $Parent; kind = $kind }
    $children = Get-RaProperty $properties 'children'
    if ($null -ne $children) {
        Assert-Ra ($children -is [array]) 'Invalid hierarchy children.'
        foreach ($child in $children) {
            Assert-Ra ($child -is [System.Collections.IDictionary]) 'Invalid hierarchy child.'
            Add-RaHierarchyNode $child $key $Result
        }
    }
}

function Get-RaHierarchy {
    param([string]$Group, [string]$Tenant)
    $payload = Invoke-RaRest "$($script:RaMgPrefix)${Group}?api-version=2020-05-01&`$expand=children&`$recurse=true"
    Assert-Ra ((Get-RaCanonical (Get-RaText (Get-RaProperty $payload 'id') 'root MG ID')) -ceq (Get-RaCanonical ($script:RaMgPrefix + $Group))) 'MG response ID mismatch.'
    Assert-Ra ((Get-RaCanonical (Get-RaText (Get-RaProperty (Get-RaProperty $payload 'properties') 'tenantId') 'MG tenant')) -ceq $Tenant) 'MG tenant does not match Connect-AzAccount.'
    $result = @{}
    Add-RaHierarchyNode $payload '' $result
    Assert-Ra (@($result.Values | Where-Object { $_.kind -ceq 'Subscription' }).Count -le 10000) 'At most 10,000 subscriptions are supported.'
    return $result
}

function Get-RaTopology {
    param([System.Collections.IDictionary]$Hierarchy)
    $result = @{}
    foreach ($key in $Hierarchy.Keys) { $result[$key] = $Hierarchy[$key].parent }
    return $result
}

function Test-RaMapEqual {
    param($Left, $Right)
    if ($Left -isnot [System.Collections.IDictionary] -or $Right -isnot [System.Collections.IDictionary] -or $Left.Count -ne $Right.Count) { return $false }
    foreach ($key in $Left.Keys) {
        if (-not $Right.Contains($key) -or $Left[$key] -cne $Right[$key]) { return $false }
    }
    return $true
}

function Get-RaAssignmentKey {
    param([string]$Value, [string]$Scope)
    $id = Get-RaCanonical (Get-RaText $Value 'RoleAssignmentId')
    $scopeKey = Get-RaCanonical (Get-RaText $Scope 'Scope')
    Assert-Ra ($scopeKey.StartsWith('/')) 'Invalid snapshot scope.'
    if ($id.StartsWith('/')) {
        $position = $id.LastIndexOf($script:RaMarker, [StringComparison]::Ordinal)
        Assert-Ra ($position -ge 0 -and $id.Substring(0, $position) -ceq $scopeKey) 'Invalid snapshot assignment ID.'
        $id = $id.Substring($position + $script:RaMarker.Length)
    }
    return $scopeKey + $script:RaMarker + (Get-RaGuid $id)
}

function Get-RaAssignmentRow {
    param([System.Collections.IDictionary]$Assignment, [System.Collections.IDictionary]$Hierarchy, [System.Collections.IDictionary]$Roles)
    $id = Get-RaText (Get-RaProperty $Assignment 'id') 'Role Assignment ID'
    Assert-Ra ($id.StartsWith('/')) 'Expected a full Role Assignment ARM ID.'
    $scope = Get-RaText (Get-RaProperty $Assignment 'scope') 'Role Assignment scope'
    $null = Get-RaAssignmentKey $id $scope
    $key = Get-RaCanonical $scope
    $roleId = Get-RaText (Get-RaProperty $Assignment 'roleDefinitionId') 'roleDefinitionId'
    $roleGuid = Get-RaRoleGuid $roleId
    Assert-Ra ($Roles.Contains($roleGuid)) "Role name was not resolved: $roleId"
    $subscriptionId = ''; $subscriptionName = ''; $rgName = ''; $resourceName = ''
    if ($Hierarchy.Contains($key) -and $Hierarchy[$key].kind -ceq 'ManagementGroup') {
        $mgId = $key; $scopeType = 'ManagementGroup'
    }
    else {
        $segments = $scope.Trim('/').Split('/')
        Assert-Ra ($segments.Count -ge 2 -and $segments[0] -ieq 'subscriptions') "Assignment outside hierarchy: $scope"
        $subscriptionId = Get-RaGuid $segments[1]
        $subscriptionKey = '/subscriptions/' + $subscriptionId
        Assert-Ra ($Hierarchy.Contains($subscriptionKey)) "Unknown subscription: $subscriptionId"
        $subscriptionName = $Hierarchy[$subscriptionKey].name
        $mgId = $Hierarchy[$subscriptionKey].parent
        $scopeType = 'Subscription'
        if ($segments.Count -gt 2) {
            $resourceStart = 2
            if ($segments[2] -ieq 'resourceGroups') {
                Assert-Ra ($segments.Count -ge 4) "Invalid RG scope: $scope"
                $rgName = $segments[3]; $scopeType = 'ResourceGroup'; $resourceStart = 4
            }
            if ($segments.Count -gt $resourceStart) {
                Assert-Ra ($segments[$resourceStart] -ieq 'providers' -and $segments.Count -ge $resourceStart + 4) "Invalid resource scope: $scope"
                $resourceName = $segments[-1]; $scopeType = 'Resource'
            }
        }
    }
    Assert-Ra ($Hierarchy.Contains($mgId)) "Unknown parent MG: $mgId"
    return [ordered]@{
        RoleAssignmentId = $id; ManagementGroupName = $Hierarchy[$mgId].name
        SubscriptionName = $subscriptionName; ResourceGroupName = $rgName; ResourceName = $resourceName
        RoleName = $Roles[$roleGuid]; Scope = $scope; ScopeType = $scopeType
        ManagementGroupId = $mgId.Substring($script:RaMgPrefix.Length); SubscriptionId = $subscriptionId
        RoleDefinitionId = $roleId; PrincipalId = Get-RaGuid (Get-RaText (Get-RaProperty $Assignment 'principalId') 'principalId')
    }
}

function ConvertTo-RaCsvCell {
    param([AllowEmptyString()][string]$Value)
    if ($Value -match '^[=+\-@\t\r\n]') { $Value = "'" + $Value }
    if ($Value -match '[,"\r\n]') { return '"' + $Value.Replace('"', '""') + '"' }
    return $Value
}

function Save-RaCsv {
    param([string]$Path, [array]$Rows, [System.Collections.IDictionary]$Metadata)
    $fullPath = Resolve-RaFilePath $Path
    $companion = $fullPath + '.metadata.json'
    Assert-Ra ([IO.Path]::GetExtension($fullPath) -ieq '.csv') 'Output must end in .csv.'
    Assert-Ra (-not [IO.File]::Exists($fullPath) -and -not [IO.File]::Exists($companion)) 'Output already exists; choose a new filename.'
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fullPath))
    $builder = [Text.StringBuilder]::new()
    $null = $builder.Append(($script:RaFields -join ',') + "`r`n")
    foreach ($row in $Rows) {
        $key = Get-RaAssignmentKey $row.RoleAssignmentId $row.Scope
        $cells = foreach ($field in $script:RaFields) {
            Assert-Ra ($row[$field] -is [string]) "Missing CSV field: $field"
            $value = if ($field -ceq 'RoleAssignmentId') { $key.Substring($key.LastIndexOf('/') + 1) } else { $row[$field] }
            ConvertTo-RaCsvCell $value
        }
        $null = $builder.Append(($cells -join ',') + "`r`n")
    }
    $bytes = [byte[]](@(0xEF, 0xBB, 0xBF) + [Text.Encoding]::UTF8.GetBytes($builder.ToString()))
    $metadataCopy = @{}
    foreach ($key in $Metadata.Keys) { $metadataCopy[$key] = $Metadata[$key] }
    $metadataCopy.schemaVersion = if ($metadataCopy.ContainsKey('principalTypeFilter')) { 3 } else { 2 }
    $metadataCopy.rowCount = $Rows.Count
    $metadataCopy.csvSha256 = Get-RaHash $bytes
    Write-RaStage "Writing CSV: $fullPath"
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    Write-RaStage "Writing metadata: $companion"
    $stream = [IO.File]::Open($companion, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    try { $writer.Write((ConvertTo-Json -InputObject $metadataCopy -Depth 50) + "`n") }
    finally { $writer.Dispose() }
}

function Read-RaCsv {
    param([string]$Path)
    $fullPath = Resolve-RaFilePath $Path
    Write-RaStage "Reading snapshot: $fullPath"
    $bytes = [IO.File]::ReadAllBytes($fullPath)
    $metadata = ConvertFrom-RaJson ([IO.File]::ReadAllText($fullPath + '.metadata.json'))
    Assert-Ra ($metadata -is [System.Collections.IDictionary] -and (Get-RaProperty $metadata 'schemaVersion') -in @(1, 2, 3) -and (Get-RaProperty $metadata 'kind') -ceq 'snapshot') 'Input is not a supported snapshot.'
    if ($metadata.schemaVersion -eq 3) {
        Assert-Ra ((Get-RaProperty $metadata 'principalTypeFilter') -ceq 'User') 'Schema 3 requires the User principal filter.'
    }
    else {
        Assert-Ra (-not $metadata.Contains('principalTypeFilter')) 'Legacy snapshots cannot declare a principal filter.'
    }
    Assert-Ra ((Get-RaProperty $metadata 'csvSha256') -ceq (Get-RaHash $bytes)) "CSV checksum mismatch: $Path"
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xFEFF)
    $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new([IO.StringReader]::new($text))
    $parser.SetDelimiters(@(','))
    $parser.HasFieldsEnclosedInQuotes = $true; $parser.TrimWhiteSpace = $false
    $rows = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    try {
        $headers = $parser.ReadFields()
        Assert-Ra ($null -ne $headers -and $headers.Count -eq $script:RaFields.Count) 'Snapshot CSV header mismatch.'
        for ($index = 0; $index -lt $headers.Count; $index++) {
            Assert-Ra ($headers[$index] -ceq $script:RaFields[$index]) 'Snapshot CSV header mismatch.'
        }
        while (-not $parser.EndOfData) {
            $fields = $parser.ReadFields()
            Assert-Ra ($fields.Count -eq $headers.Count) 'Malformed snapshot row.'
            $row = [ordered]@{}
            for ($index = 0; $index -lt $headers.Count; $index++) { $row[$headers[$index]] = $fields[$index] }
            if ($metadata.schemaVersion -eq 1) {
                Assert-Ra ($row.RoleAssignmentId.StartsWith('/')) 'Schema 1 requires a full assignment ID.'
            }
            else { $null = Get-RaGuid $row.RoleAssignmentId }
            $key = Get-RaAssignmentKey $row.RoleAssignmentId $row.Scope
            Assert-Ra (-not $rows.ContainsKey($key)) 'Duplicate RoleAssignmentId in snapshot.'
            $row.RoleAssignmentId = $key; $rows.Add($key, $row)
        }
    }
    finally { $parser.Dispose() }
    Assert-Ra ((Get-RaProperty $metadata 'rowCount') -eq $rows.Count) 'Snapshot row count mismatch.'
    return @{ rows = $rows; metadata = $metadata }
}

function Get-RaInstant {
    param($Value)
    if ($Value -is [DateTimeOffset]) { return $Value }
    if ($Value -is [DateTime]) {
        Assert-Ra ($Value.Kind -ne [DateTimeKind]::Unspecified) 'Snapshot timestamps need a timezone.'
        return [DateTimeOffset]::new($Value)
    }
    $valueText = Get-RaText $Value 'snapshot timestamp'
    Assert-Ra ($valueText -match '(Z|[+-]\d\d:\d\d)$') 'Snapshot timestamps need a timezone.'
    return [DateTimeOffset]::Parse($valueText, [Globalization.CultureInfo]::InvariantCulture)
}

function Invoke-RaSnapshot {
    param([string]$Group, [string]$Path, [int]$Attempts = 3)
    $Path = Resolve-RaFilePath $Path
    $started = Get-RaStamp
    Write-RaStage 'Checking Azure PowerShell user context'
    $identity = Get-RaIdentity
    Write-RaStage 'Reading management group hierarchy'
    $hierarchy = Get-RaHierarchy $Group $identity.tenantId
    Write-RaStage 'Collecting ARG subscriptions'
    $subscriptions = Get-RaQuery $Group $script:RaSubscriptionsQuery 'AtScopeAndBelow' $Attempts
    $actual = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($row in $subscriptions) { $null = $actual.Add((Get-RaCanonical $row.id)) }
    $expected = @($hierarchy.Keys | Where-Object { $hierarchy[$_].kind -ceq 'Subscription' })
    Assert-Ra ($actual.SetEquals([string[]]$expected)) 'ARM hierarchy and ARG subscription coverage differ.'
    Write-RaStage 'Collecting ARG role assignments (direct User assignments only)'
    $assignments = Get-RaQuery $Group $script:RaAssignmentsQuery 'AtScopeAndBelow' $Attempts
    foreach ($assignment in $assignments) {
        Assert-Ra ((Get-RaProperty $assignment 'principalType') -ieq 'User') 'ARG returned a non-User assignment for the User-only query.'
    }
    $roles = @{}
    if ($assignments.Count) {
        Write-RaStage 'Collecting ARG role definitions and resolving role names'
        foreach ($row in (Get-RaQuery $Group $script:RaRolesQuery 'AtScopeAboveAndBelow' $Attempts)) {
            $key = Get-RaRoleGuid (Get-RaText (Get-RaProperty $row 'id') 'role ID')
            $name = Get-RaText (Get-RaProperty $row 'roleName') 'roleName'
            Assert-Ra (-not $roles.ContainsKey($key) -or $roles[$key] -ceq $name) "Conflicting role names: $key"
            $roles[$key] = $name
        }
        foreach ($assignment in $assignments) {
            $roleId = Get-RaText (Get-RaProperty $assignment 'roleDefinitionId') 'roleDefinitionId'
            $key = Get-RaRoleGuid $roleId
            if (-not $roles.ContainsKey($key)) {
                [Console]::Error.WriteLine("WARNING: ARG role name missing; resolving with ARM: $key")
                $role = Invoke-RaRest ($roleId + '?api-version=2022-04-01')
                Assert-Ra ((Get-RaRoleGuid (Get-RaText (Get-RaProperty $role 'id') 'ARM role ID')) -ceq $key) 'ARM role ID mismatch.'
                $roles[$key] = Get-RaText (Get-RaProperty (Get-RaProperty $role 'properties') 'roleName') 'ARM roleName'
            }
        }
    }
    $rows = [Collections.Generic.List[object]]::new()
    Write-RaStage 'Building CSV rows and checking hierarchy and identity'
    foreach ($assignment in $assignments) { $rows.Add((Get-RaAssignmentRow $assignment $hierarchy $roles)) }
    Assert-Ra (Test-RaMapEqual (Get-RaTopology (Get-RaHierarchy $Group $identity.tenantId)) (Get-RaTopology $hierarchy)) 'MG hierarchy changed during collection.'
    Assert-Ra (Test-RaMapEqual (Get-RaIdentity) $identity) 'Azure PowerShell identity changed during collection.'
    Save-RaCsv $Path $rows.ToArray() @{
        kind = 'snapshot'; tenantId = $identity.tenantId; accountFingerprint = $identity.accountFingerprint
        managementGroupId = $Group.ToLowerInvariant(); startedAt = $started; completedAt = Get-RaStamp
        topology = Get-RaTopology $hierarchy; authorizationScopeFilter = 'AtScopeAndBelow'
        principalTypeFilter = 'User'
    }
    Write-Output "Snapshot: $Path ($($rows.Count) assignments)"
    [Console]::Error.WriteLine('WARNING: ARG reflects readable, indexed state, not an atomic backup. Keep read permissions fixed and recheck absence with ARM/Activity Log.')
}

function Invoke-RaDiff {
    param([string]$BeforePath, [string]$AfterPath, [string]$OutputPath)
    $BeforePath = Resolve-RaFilePath $BeforePath
    $AfterPath = Resolve-RaFilePath $AfterPath
    $OutputPath = Resolve-RaFilePath $OutputPath
    $old = Read-RaCsv $BeforePath; $new = Read-RaCsv $AfterPath
    Write-RaStage 'Checking snapshot compatibility and comparing assignments'
    $oldFilter = if ($old.metadata.schemaVersion -eq 3) { $old.metadata.principalTypeFilter } else { 'All' }
    $newFilter = if ($new.metadata.schemaVersion -eq 3) { $new.metadata.principalTypeFilter } else { 'All' }
    Assert-Ra ($oldFilter -ceq $newFilter) 'Snapshots are not comparable: principalTypeFilter differs. Capture both snapshots with the same scope.'
    foreach ($field in @('tenantId', 'accountFingerprint', 'managementGroupId', 'topology', 'authorizationScopeFilter')) {
        Assert-Ra ($old.metadata.Contains($field) -and $new.metadata.Contains($field)) "Missing comparison field: $field"
        $equal = if ($field -ceq 'topology') { Test-RaMapEqual $old.metadata[$field] $new.metadata[$field] } else { $old.metadata[$field] -ceq $new.metadata[$field] }
        Assert-Ra $equal "Snapshots are not comparable: $field differs."
    }
    $oldStart = Get-RaInstant (Get-RaProperty $old.metadata 'startedAt')
    $oldEnd = Get-RaInstant (Get-RaProperty $old.metadata 'completedAt')
    $newStart = Get-RaInstant (Get-RaProperty $new.metadata 'startedAt')
    $newEnd = Get-RaInstant (Get-RaProperty $new.metadata 'completedAt')
    Assert-Ra ($oldStart -le $oldEnd -and $oldEnd -le $newStart -and $newStart -le $newEnd -and $oldStart -lt $newStart) 'Use non-overlapping snapshots in chronological order.'
    $keys = [string[]]@($old.rows.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $deleted = [Collections.Generic.List[object]]::new()
    foreach ($key in $keys) { if (-not $new.rows.ContainsKey($key)) { $deleted.Add($old.rows[$key]) } }
    $added = @($new.rows.Keys | Where-Object { -not $old.rows.ContainsKey($_) }).Count
    $metadata = @{
        kind = 'diff'; createdAt = Get-RaStamp; before = $BeforePath
        after = $AfterPath; beforeSha256 = $old.metadata.csvSha256
        afterSha256 = $new.metadata.csvSha256
        meaning = 'Present before, absent after in ARG; not proof of deletion actor or cause.'
    }
    if ($oldFilter -ceq 'User') { $metadata.principalTypeFilter = 'User' }
    Save-RaCsv $OutputPath $deleted.ToArray() $metadata
    Write-Output "Removed from snapshot: $($deleted.Count); added: $added; CSV: $OutputPath"
    [Console]::Error.WriteLine('WARNING: Absence in ARG is a deletion candidate, not proof of a successful delete operation.')
}

function Invoke-RaMain {
    if ($Help) {
        Write-Output @'
PowerShell 7+; snapshot requires Az.Accounts and an existing Connect-AzAccount user session.
.\verify_role_deletions.ps1 -Mode snapshot -ManagementGroup <mg-id> -Output <new.csv> [-MaxAttempts 3]
.\verify_role_deletions.ps1 -Mode diff -Before <before.csv> -After <after.csv> -Output <deleted.csv>
Keep each CSV together with its .metadata.json companion. Existing outputs are never overwritten.
Run using & or .\file.ps1, not dot-source (. file.ps1). Add -Verbose for per-partition diagnostics.
Relative paths use Get-Location; the resolved output path is printed when execution starts.
Snapshots include only direct User assignments (not Group, ServicePrincipal or Managed Identity).
Collection starts with one partition; only results exceeding 1,000 rows are split.
Use new snapshots for both before and after. Schema 3 User snapshots cannot be compared with older All snapshots.
'@
        return
    }
    Write-RaStage 'Validating arguments and output path'
    $path = Resolve-RaFilePath $Output
    Assert-Ra ([IO.Path]::GetExtension($path) -ieq '.csv') 'Output must end in .csv.'
    Assert-Ra (-not [IO.File]::Exists($path) -and -not [IO.File]::Exists($path + '.metadata.json')) 'Output already exists.'
    [Console]::Error.WriteLine("INFO: Output: $path")
    if ($Mode -ieq 'snapshot') {
        $group = Get-RaGroup (Get-RaText $ManagementGroup 'ManagementGroup')
        Write-RaStage 'Loading Az.Accounts'
        if (-not (Get-Module -Name Az.Accounts)) { Import-Module Az.Accounts -ErrorAction Stop }
        Invoke-RaSnapshot $group $path $MaxAttempts
    }
    else {
        Invoke-RaDiff (Get-RaText $Before 'Before') (Get-RaText $After 'After') $path
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-RaMain }
    catch {
        [Console]::Error.WriteLine("ERROR: stage=$script:RaStage; $($_.Exception.Message)")
        exit 1
    }
}
elseif ($PSBoundParameters.Count -gt 0) {
    throw 'Do not dot-source this tool with execution arguments. Run & .\verify_role_deletions.ps1 with the same parameters.'
}
