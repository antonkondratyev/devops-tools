[CmdletBinding()]
Param (
    [Parameter()] [string] $TFS_URL,
    [Parameter()] [string] $TFS_COLLECTION,
    [Parameter()] [string] $TFS_PROJECT,
    [Parameter()] [string] $TFS_TOKEN,
    [Parameter()] [switch] $UseSystemAccessToken,

    [Parameter()] [string] $ReleaseDefinitionName,
    [Parameter()] [string] $ArtifactsPatchJson,
    [Parameter()] [string] $StagesPatchJson,
    [Parameter()] [string] $VariablesPatchJson
)

if (!$env:TF_BUILD -and !$env:TFS_URL) {
    Write-Host "`nMissing 'TFS_URL' Environment Variable."
    $env:TFS_URL = Read-Host -Prompt "`nTFS URL"
    [Environment]::SetEnvironmentVariable("TFS_URL", $env:TFS_URL, "User")
} elseif ($TFS_URL) {
    [Environment]::SetEnvironmentVariable("TFS_URL", $TFS_URL, "User")
}

if (!$env:TF_BUILD -and !$env:TFS_COLLECTION) {
    Write-Host "`nMissing 'TFS_COLLECTION' Environment Variable."
    $env:TFS_COLLECTION = Read-Host -Prompt "`nTFS Projects Collection"
    [Environment]::SetEnvironmentVariable("TFS_COLLECTION", $env:TFS_COLLECTION, "User")
} elseif ($TFS_COLLECTION) {
    [Environment]::SetEnvironmentVariable("TFS_COLLECTION", $TFS_COLLECTION, "User")
}

if (!$env:TF_BUILD -and !$env:TFS_PROJECT) {
    Write-Host "`nMissing 'TFS_PROJECT' Environment Variable."
    $env:TFS_PROJECT = Read-Host -Prompt "`nTFS Project"
    [Environment]::SetEnvironmentVariable("TFS_PROJECT", $env:TFS_PROJECT, "User")
} elseif ($TFS_PROJECT) {
    [Environment]::SetEnvironmentVariable("TFS_PROJECT", $TFS_PROJECT, "User")
}

if (!$env:TF_BUILD -and !$env:TFS_TOKEN) {
    Write-Host "`nMissing 'TFS_TOKEN' Environment Variable."
    $env:TFS_TOKEN = Read-Host -Prompt "`nPersonal Access Token"
    [Environment]::SetEnvironmentVariable("TFS_TOKEN", $env:TFS_TOKEN, "User")
} elseif ($TFS_TOKEN) {
    [Environment]::SetEnvironmentVariable("TFS_TOKEN", $TFS_TOKEN, "User")
}

function Main {
    [CmdletBinding()]
    Param (
        [Parameter()] [string] $ReleaseDefinitionName,
        [Parameter()] [string] $ArtifactsPatchJson,
        [Parameter()] [string] $StagesPatchJson,
        [Parameter()] [string] $VariablesPatchJson
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()

    try {
        if ($PSBoundParameters.Count -eq 0) {
            return Usage
        }

        if ($ReleaseDefinitionName) {
            $releaseDefinitions = GetReleaseDefinitions
            $releaseDefinition = ($releaseDefinitions.value).Where({ $_.Name -in $ReleaseDefinitionName })
            $releaseDefinition = GetReleaseDefinition($releaseDefinition.id)

            if ($ArtifactsPatchJson) {
                $artifactsPatch = ($ArtifactsPatchJson | ConvertFrom-Json).artifacts
                $artifactsPatch | ForEach-Object {
                    $releaseDefinition = UpdateReleaseDefinitionArtifacts -definition $releaseDefinition -artifactPatch $_
                }

                $releaseDefinition = UpdateReleaseDefinition($releaseDefinition) # to TFS

                Write-Host
                Write-Host "Release Definition Updated Successfully!" -ForegroundColor Green
                Write-Host
                Write-Host "Name: $($releaseDefinition.name)"
                Write-Host "Url: $($releaseDefinition._links.web.href)"
                Write-Host

                $artifactsPatch
            }

            if ($StagesPatchJson) {
                $stagesPatch = ($StagesPatchJson | ConvertFrom-Json).stages
                $stagesPatch | ForEach-Object {
                    $releaseDefinition = UpdateReleaseDefinitionStage -definition $releaseDefinition -stagePatch $_
                }

                $releaseDefinition = UpdateReleaseDefinition($releaseDefinition) # to TFS

                Write-Host
                Write-Host "Release Definition Updated Successfully!" -ForegroundColor Green
                Write-Host
                Write-Host "Name: $($releaseDefinition.name)"
                Write-Host "Url: $($releaseDefinition._links.web.href)"
                Write-Host

                $stagesPatch
            }

            if ($VariablesPatchJson) {
                $variablesPatch = ($VariablesPatchJson | ConvertFrom-Json).variables
                $variablesPatch | ForEach-Object {
                    $releaseDefinition = UpdateReleaseDefinitionVariables -definition $releaseDefinition -variablePatch $_
                }

                $releaseDefinition = UpdateReleaseDefinition($releaseDefinition) # to TFS

                Write-Host
                Write-Host "Release Definition Updated Successfully!" -ForegroundColor Green
                Write-Host
                Write-Host "Name: $($releaseDefinition.name)"
                Write-Host "Url: $($releaseDefinition._links.web.href)"
                Write-Host

                $variablesPatch
            }

            # TODO: if definition isn't change, exit without send PUT request to TFS
        }

        exit 0
    }
    catch {
        Write-Error $Error[0]
    }
    finally {
        $sw.Stop()
        Write-Host "Total Run Time: $($sw.Elapsed.ToString('hh\:mm\:ss\.fff'))`n" -ForegroundColor DarkGray
    }
}

function UpdateReleaseDefinitionArtifacts($definition, $artifactPatch) {
    $artifact = $definition.artifacts | Where-Object { $_.alias -eq $artifactPatch.name }

    if ($artifactPatch.branch) {
        $artifact.definitionReference.defaultVersionBranch.id = $artifactPatch.branch
        $artifact.definitionReference.defaultVersionBranch.name = $artifactPatch.branch
    }

    if ($artifactPatch.trigger) {
        $artifactTrigger = $definition.triggers | Where-Object { $_.artifactAlias -eq $artifactPatch.name }
        $triggerCondition = ($artifactTrigger.triggerConditions | Where-Object { $_.sourceBranch })[0]
        $triggerCondition.sourceBranch = $artifactPatch.trigger
    }

    return $definition
}

function UpdateReleaseDefinitionStage($definition, $stagePatch) {
    $stageConditions = ($definition.environments | Where-Object { $_.name -eq $stagePatch.name }).conditions
    $artifactCondition = $stageConditions | Where-Object { $_.name -eq $stagePatch.artifactFilter }
    $artifactFilter = $artifactCondition.value | ConvertFrom-Json

    if ($artifactFilter.sourceBranch -ne $stagePatch.buildBranch) {
        $artifactFilter.sourceBranch = $stagePatch.buildBranch
    }

    $artifactCondition.value = $artifactFilter | ConvertTo-Json -Compress

    return $definition
}

function UpdateReleaseDefinitionVariables($definition, $variablePatch) {
    if ($variable = $definition.variables | Where-Object { $_."$($variablePatch.name)" }) {
        ($variable."$($variablePatch.name)").value = $variablePatch.value
    }

    if ($variable = $definition.environments.variables | Where-Object { $_."$($variablePatch.name)" }) {
        ($variable."$($variablePatch.name)").value = $variablePatch.value
    }

    return $definition
}

function UpdateReleaseDefinition($definition) {
    $definitionURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/release/definitions?api-version=5.0"
    $body = $definition | ConvertTo-Json -Depth 10
    TFS_PutApi -url $definitionURL -body $body
}

function GetReleaseDefinition([int] $definitionId) {
    $definitionURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/release/definitions/$($definitionId)?api-version=5.0"
    $definition = TFS_GetApi($definitionURL)
    return $definition
}

function GetReleaseDefinitions() {
    $definitionsURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/release/definitions?api-version=5.0"
    $definitions = TFS_GetApi($definitionsURL)
    return $definitions
}

function TFS_GetApi([string] $url) {
    try {
        $headers = GenHeaders
        Invoke-RestMethod -Uri $url -Method GET -Headers $headers
    }
    catch [System.Exception] {
        throw $Error[0]
    }
}

function TFS_PutApi([string] $url, $body) {
    try {
        $headers = GenHeaders
        Invoke-RestMethod -Uri $url -Method PUT -Headers $headers -Body $body -ContentType "application/json"
    }
    catch [System.Exception] {
        throw $Error[0]
    }
}

function TFS_PatchApi([string] $url, $body) {
    try {
        $headers = GenHeaders
        Invoke-RestMethod -Uri $url -Method PATCH -Headers $headers -Body $body -ContentType "application/json"
    }
    catch [System.Exception] {
        throw $Error[0]
    }
}

function GenHeaders() {
    $token = $env:TFS_TOKEN

    if ($env:TF_BUILD -and $UseSystemAccessToken) {
        $token = $env:SYSTEM_ACCESSTOKEN
    }

    $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(":$token"))
    $headers = @{ Authorization = "Basic $encodedToken" }
    return $headers
}

function Usage() {
    $scriptName = (Get-Variable MyInvocation -Scope Script).Value.MyCommand

    Write-Host
    Write-Host "  Command line arguments:"
    Write-Host "    .\$($scriptName) -ReleaseDefinitionName <string> -ArtifactsPatchJson <JSON>"
    Write-Host "    .\$($scriptName) -ReleaseDefinitionName <string> -StagesPatchJson <JSON>"
    Write-Host "    .\$($scriptName) -ReleaseDefinitionName <string> -VariablesPatchJson <JSON>"
    Write-Host
    Write-Host "    -UseSystemAccessToken`t[if running on TFS CI with `$(System.AccessToken) variable]"
    Write-Host
    Write-Host "    -ArtifactsPatchJson format example:" -NoNewline
    Write-Host '
      {
        "artifacts": [
          {
            "name": "Dictionary_Exporter",
            "branch": "sprints/s5.full",
            "trigger": "sprints/s5.full"
          }
        ]
      }
    '
    Write-Host "    -StagesPatchJson format example:" -NoNewline
    Write-Host '
      {
        "stages": [
          {
            "name": "client-AppStorage-content2",
            "artifactFilter": "Client",
            "buildBranch": "sprints/s4.full"
          },
          {
            "name": "client-AppStorage-dev",
            "artifactFilter": "Client",
            "buildBranch": "sprints/s6.full"
          }
        ]
      }
    '
    Write-Host "    -VariablesPatchJson format example:" -NoNewline
    Write-Host '
      {
        "variables": [
          {
            "name": "content.branch",
            "value": "sprints/s5.content"
          }
        ]
      }
    '
}

$Params = @{}

if ($ReleaseDefinitionName) {
    $Params.Add("ReleaseDefinitionName", $ReleaseDefinitionName)
}

if ($ArtifactsPatchJson) {
    $Params.Add("ArtifactsPatchJson", $ArtifactsPatchJson)
}

if ($StagesPatchJson) {
    $Params.Add("StagesPatchJson", $StagesPatchJson)
}

if ($VariablesPatchJson) {
    $Params.Add("VariablesPatchJson", $VariablesPatchJson)
}

Main @Params