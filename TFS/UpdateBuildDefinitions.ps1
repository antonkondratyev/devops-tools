[CmdletBinding()]
Param (
    [Parameter()] [string] $TFS_URL,
    [Parameter()] [string] $TFS_COLLECTION,
    [Parameter()] [string] $TFS_PROJECT,
    [Parameter()] [string] $TFS_TOKEN,
    [Parameter()] [switch] $UseSystemAccessToken,

    [Parameter()] [switch] $Repositories,
    [Parameter()] [string] $RepositoryNames,
    [Parameter()] [string] $DefaultBranch,
    [Parameter()] [switch] $Environments,
    [Parameter()] [string] $Environment,
    [Parameter()] [int] $BuildDefinitionID,
    [Parameter()] [string] $BuildDefinitionNames,
    [Parameter()] [string] $ReleaseDefinitionName,
    [Parameter()] [string] $SourceBranchName,
    [Parameter()] [string] $Triggers,
    [Parameter()] [string] $Version
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

class DefinitionsFolder {
    [string] $id = ""
    [string] $name = ""
    [string] $filter = ""
}

function Main {
    [CmdletBinding()]
    Param (
        [Parameter()] [switch] $Repositories,
        [Parameter()] [string] $RepositoryNames,
        [Parameter()] [string] $DefaultBranch,
        [Parameter()] [switch] $Environments,
        [Parameter()] [string] $Environment,
        [Parameter()] [int] $BuildDefinitionID,
        [Parameter()] [string] $BuildDefinitionNames,
        [Parameter()] [string] $ReleaseDefinitionName,
        [Parameter()] [string] $SourceBranchName,
        [Parameter()] [string] $Triggers,
        [Parameter()] [string] $Version
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()

    try {
        if ($PSBoundParameters.Count -eq 0) {
            return Usage
        }

        $versionPattern = "^\d+\.\d+$"
        $buildVersion = $Version

        if ($buildVersion -and $buildVersion -notmatch $versionPattern) {
            Write-Host "`nVersion isn't correct. Needed format: 1.0"
            return Usage
        }

        if ($Repositories -and $RepositoryNames) {
            throw "`nUse only one argument 'Repositories' or 'Repository'`n"
        }

        if ($DefaultBranch -and !$RepositoryNames) {
            throw "`n'Repository' argument not defined.`n"
        }

        $repositoriesAll = GetRepositories

        if ($Repositories) {
            Write-Host "`nRepositories on '$($env:TFS_URL)' in '$($env:TFS_PROJECT)' project [$($repositoriesAll.Count)]:"
            OutputRepositoriesTable($repositoriesAll)
            exit 0
        }

        if ($RepositoryNames) {
            $repositoryList = $repositoriesAll.Where({ $_.name -in $RepositoryNames.Split(",") })

            if ($DefaultBranch) {
                $updatedRepository = UpdateDefaultBranch -repository $repositoryList.Where({ $_.defaultBranch -notmatch $DefaultBranch }) -defaultBranch $DefaultBranch

                Write-Host "`nUpdated Repositories on '$($env:TFS_URL)' [$($updatedRepository.Count)/$($repositoryList.Count)]:"
                OutputRepositoriesTable($updatedRepository)
            } else {
                Write-Host "`nSelected Repositories on '$($env:TFS_URL)' [$($repositoryList.Count)]:"
                OutputRepositoriesTable($repositoryList)
            }

            exit 0
        }

        $definitions = GetDefinitions

        if ($Environments) {
            OutputEnvironmentTable(GetEnvironments($definitions))
            exit 0
        }

        if ($Environment) {
            $environmentFolders = GetEnvironments($definitions)

            if ($Environment -notin $environmentFolders.name) {
                throw "`nNo definitions in '$($Environment)' environment.`n"
            }

            $definitionsFilter = $environmentFolders.Where({ $_.name -like $Environment }).filter
            $definitions = ($definitions.value).Where({ $_.path -like $definitionsFilter })
        }

        if ($BuildDefinitionID -and $BuildDefinitionID -in $definitions.value.id) {
            $definition = GetDefinition($BuildDefinitionID)

            if ($buildVersion) {
                $updatedDefinition = UpdateBuildVersion -definition $definition -newBuildVersion $buildVersion
            }

            if ($SourceBranchName -or $Triggers) {
                if ($SourceBranchName) {
                    $updatedDefinition = UpdateDefinitionBranch -definition $definition -sourceBranch $SourceBranchName
                }

                if ($Triggers) {
                    $updatedDefinition = UpdateDefinitionTriggers -definition $definition -triggers $Triggers.Split(",")
                }

                $updatedDefinition = UpdateDefinition($updatedDefinition)

                Write-Host "`nUpdated Definition on '$($env:TFS_URL)':"
                OutputDefinitionTable($updatedDefinition)
            }
            else {
                Write-Host "`nCurrent Definition:"
                OutputDefinitionTable($definition)
            }

            exit 0
        }

        if ($BuildDefinitionNames) {
            $definitions = ($definitions.value).Where({ $_.Name -in $BuildDefinitionNames.Split(",") })
        }

        $definitions = ($definitions).ForEach({ GetDefinition($_.id) })

        if ($Triggers) {
            $definitions = $definitions.ForEach({ UpdateDefinitionTriggers -definition $_ -triggers $Triggers.Split(",") })
        }

        if ($buildVersion) {
            $definitions.ForEach({ UpdateBuildVersion -definition $_ -newBuildVersion $buildVersion | Out-Null })
        }

        if ($SourceBranchName) {
            $definitions = @(UpdateDefinitionsBranch -definitions $definitions -sourceBranch $SourceBranchName)

            $updatedDefinitions = @(UpdateDefinitions($definitions))

            Write-Host "`nUpdated Definitions on '$($env:TFS_URL)' [$($updatedDefinitions.Count)]:"
            OutputDefinitionTable($updatedDefinitions)
        }
        else {
            Write-Host "`nCurrent Definitions on '$($env:TFS_URL)' [$($definitions.Count)]:"
            OutputDefinitionTable($definitions)
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

function HumanizeDataSize([int64] $size) {
    switch ($size) {
        { $_ -gt 1tb } { return "{0:n0} TB" -f ($_ / 1tb) }
        { $_ -gt 1gb } { return "{0:n0} GB" -f ($_ / 1gb) }
        { $_ -gt 1mb } { return "{0:n0} MB" -f ($_ / 1mb) }
        { $_ -gt 1kb } { return "{0:n0} KB" -f ($_ / 1kb) }
               default { return "{0} B" -f $_ }
    }
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

function GetRepository($repository) {
    $repositoryURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/git/repositories/$($repository.id)?api-version=5.0"
    $repository = TFS_GetApi($repositoryURL)
    return $repository
}

function GetRepositories() {
    $repositoriesURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/git/repositories?api-version=5.0"
    $repositories = TFS_GetApi($repositoriesURL)
    return $repositories.value
}

function UpdateDefaultBranch($repositoryList, [string] $defaultBranch) {
    $repositoryList.ForEach({ $_.defaultBranch = "refs/heads/$($defaultBranch)" })
    UpdateRepositories($repositoryList)
}

function UpdateRepository($repository) {
    $repositoryURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/git/repositories/$($repository.id)?api-version=5.0"
    $body = $repository | ConvertTo-Json -Depth 10
    TFS_PatchApi -url $repositoryURL -body $body
}

function UpdateRepositories($repositoryList) {
    $updatedRepositories = $repositoryList.ForEach({ UpdateRepository($_) })
    return $updatedRepositories
}

function GetDefinition([int] $definitionId) {
    $definitionURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/build/definitions/$($definitionId)?api-version=5.0"
    $definition = TFS_GetApi($definitionURL)
    return $definition
}

function GetDefinitions() {
    $definitionsURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/build/definitions?api-version=5.0"
    $definitions = TFS_GetApi($definitionsURL)
    return $definitions
}

function UpdateDefinition($definition) {
    $definitionURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/build/definitions/$($definition.id)?api-version=5.0"
    $body = $definition | ConvertTo-Json -Depth 10
    TFS_PutApi -url $definitionURL -body $body
}

function UpdateDefinitions($definitions) {
    $updatedDefinitions = ($definitions).ForEach({ UpdateDefinition($_) })
    return $updatedDefinitions
}

function UpdateDefinitionBranch($definition, [string] $sourceBranch) {
    if ($definition.repository.type -ne "TfsGit") {
        return $definition
    }

    if ($definition.repository.defaultBranch -eq "refs/heads/master") {
        return $definition
    }

    if ($definition.repository.defaultBranch -notlike $sourceBranch) {
        $definition.repository.defaultBranch = "refs/heads/$($sourceBranch)"
    }

    return $definition
}

function UpdateDefinitionTriggers($definition, [string[]] $triggers) {
    for ($i = 0; $i -lt $definition.triggers.Count; $i++) {
        if ($definition.triggers[$i].triggerType -eq "continuousIntegration") {
            $definition.triggers[$i].branchFilters = $triggers.ForEach({ "+refs/heads/$($_)" })
        }
    }

    return $definition
}

function UpdateDefinitionsBranch($definitions, $sourceBranch) {
    $updatedDefinitions = $definitions.ForEach({ UpdateDefinitionBranch -definition $_ -sourceBranch $sourceBranch })
    return $updatedDefinitions
}

function GetEnvironments($definitions) {
    $environmentFolders = $definitions.value.path.foreach({ $_.Split("\")[1] }) | Sort-Object | Get-Unique
    $foldersList = New-Object System.Collections.ArrayList

    $environmentFolders.ForEach({
        $folder = [DefinitionsFolder]::New()
        $folder.id = $environmentFolders.IndexOf($_) + 1
        $folder.name = $_
        $folder.filter = "\$($_)*"
        $foldersList.Add($folder) | Out-Null
    })

    return $foldersList
}

function OutputDefinitionTable($definitions) {
    if ($definitions.Count -eq 0) {
        return "No one definition has been changed."
    }

    return $definitions | Sort-Object -Property name | Format-Table `
        @{ Label = "ID"; Expression = { $_.id }}, `
        @{ Label = "Defenition Name"; Expression = { $_.name }}, `
        @{ Label = "Source Branch"; Expression = { $_.repository.defaultBranch.Replace("refs/heads/", "") }}, `
        @{ Label = "CI Trigger"; Expression = { $_.triggers.Where({ $_.triggerType -eq "continuousIntegration" }).branchFilters.Replace("+refs/heads/", "") }}, `
        @{ Label = "Version"; Expression = { GetBuildVersion($_) }}
}

function OutputEnvironmentTable($definitions) {
    return $definitions.Where({ $_.name -ne "" }) | Sort-Object -Property name | Format-Table `
        @{ Label = "Environments"; Expression = { $_.name }}
}

function OutputRepositoriesTable($repositories) {
    if ($repositories.Count -eq 0) {
        return "No one repository has been changed.`n"
    }

    return $repositories | Sort-Object -Property name | Format-Table `
        @{ Label = "Name"; Expression = { $_.name }}, `
        @{ Label = "Default Branch"; Expression = { $_.defaultBranch.Replace("refs/heads/", "") }}, `
        @{ Label = "Size"; Expression = { HumanizeDataSize($_.size) }; align="right" }, `
        @{ Label = "Url"; Expression = { $_.remoteUrl }}
}

function GetVariableGroup($groupId) {
    $variableGroupURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/distributedtask/variablegroups/$($groupId)?api-version=5.0-preview.1"
    $variableGroup = TFS_GetApi($variableGroupURL)
    return $variableGroup
}

function UpdateVariableGroup($variableGroup) {
    $variableGroupURL = "$($env:TFS_URL)/$($env:TFS_COLLECTION)/$($env:TFS_PROJECT)/_apis/distributedtask/variablegroups/$($variableGroup.id)?api-version=5.0-preview.1"
    $body = $variableGroup | ConvertTo-Json -Depth 10
    TFS_PutApi -url $variableGroupURL -body $body
}

function GetBuildVersion($definition) {
    if (!$definition.buildNumberFormat) {
        return
    }

    $buildVersionPattern = "^\$\(((?i)ver.+)\).+$"
    $buildVersion = [regex]::Match($definition.buildNumberFormat, $buildVersionPattern).Groups[1].Value

    if (!$buildVersion) {
        Write-Host "$($Version) variable not defined in definition options."
        return
    }

    if ($definition.variables.$buildVersion) {
        return $definition.variables.$buildVersion.value
    }
    elseif ($definition.variableGroups.Where({ $_.variables.$buildVersion })) {
        $variableGroup = $definition.variableGroups.Where({ $_.variables.$buildVersion })
        return $variableGroup.variables.$buildVersion.value
    }
    else {
        return "N/A"
    }
}

function UpdateBuildVersion($definition, $newBuildVersion) {
    if (!$definition.buildNumberFormat) {
        return
    }

    $buildVersionPattern = "^\$\(((?i)ver.+)\).+$"
    $buildVersion = [regex]::Match($definition.buildNumberFormat, $buildVersionPattern).Groups[1].Value

    if (!$buildVersion) {
        Write-Host "$($Version) variable not defined in definition options."
        return
    }

    if ($definition.variables.$buildVersion) {
        $currentBuildVersion = $definition.variables.$buildVersion.value

        if ($currentBuildVersion -ne $newBuildVersion) {
            $definition.variables.$buildVersion.value = $newBuildVersion
            return $definition
        }
    }
    elseif ($definition.variableGroups.Where({ $_.variables.$buildVersion })) {
        $variableGroup = $definition.variableGroups.Where({ $_.variables.$buildVersion })
        $currentBuildVersion = $variableGroup.variables.$buildVersion.value

        if ($currentBuildVersion -ne $newBuildVersion) {
            $variableGroup.variables.$buildVersion.value = $newBuildVersion
            UpdateVariableGroup($variableGroup)
            return $definition
        }
    }
}

function Usage() {
    $scriptName = (Get-Variable MyInvocation -Scope Script).Value.MyCommand

    Write-Host
    Write-Host "Script for changing Branches in Build Definitions and Repositories."
    Write-Host
    Write-Host "  Command line arguments:"
    Write-Host "    .\$($scriptName) -Repositories"
    Write-Host "    .\$($scriptName) -RepositoryNames <string[]> [-DefaultBranch <string>]"
    Write-Host
    Write-Host "    .\$($scriptName) -Environments"
    Write-Host "    .\$($scriptName) -Environment <string>"
    Write-Host
    Write-Host "    .\$($scriptName) -BuildDefinitionNames <string[]> [-SourceBranchName <string>] [-Version <string>]"
    Write-Host "    .\$($scriptName) -BuildDefinitionID <int> [-SourceBranchName <string>] [-Triggers <string>] [-Version <string>]"
    Write-Host
    Write-Host "  Example:"
    Write-Host "    .\$($scriptName) -RepositoryNames Client,Editor,GameServer -DefaultBranch releases/release.ms5"
    Write-Host "    .\$($scriptName) -Environment release -SourceBranchName master -Version 1.0"
    Write-Host "    .\$($scriptName) -BuildDefinitionID 42 -SourceBranchName releases/release.ms5 -Triggers sprints/s3.full,sprints/s5.full -Version 0.5"
    Write-Host
}

$Params = @{}

if ($Repositories) {
    $Params.Add("Repositories", $true)
}

if ($RepositoryNames) {
    $Params.Add("RepositoryNames", $RepositoryNames)
}

if ($DefaultBranch) {
    $Params.Add("DefaultBranch", $DefaultBranch)
}

if ($Environments) {
    $Params.Add("Environments", $true)
}

if ($Environment) {
    $Params.Add("Environment", $Environment)
}
elseif ($BuildDefinitionID) {
    $Params.Add("BuildDefinitionID", $BuildDefinitionID)
}
elseif ($BuildDefinitionNames) {
    $Params.Add("BuildDefinitionNames", $BuildDefinitionNames)
}

if ($ReleaseDefinitionName) {
    $Params.Add("ReleaseDefinitionName", $ReleaseDefinitionName)
}

if ($SourceBranchName) {
    $Params.Add("SourceBranchName", $SourceBranchName)
}

if ($Triggers) {
    $Params.Add("Triggers", $Triggers)
}

if ($Version) {
    $Params.Add("Version", $Version)
}

Main @Params