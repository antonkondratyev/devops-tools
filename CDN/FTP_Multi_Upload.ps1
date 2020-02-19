[CmdletBinding()]
Param (
    [Parameter()] [string] $Path,
    [Parameter()] [int] $Parts,
    [Parameter()] [int] $Depth,
    [Parameter()] [string] $FTP_Server,
    [Parameter()] [string] $FTP_Path,
    [Parameter()] [string] $FTP_Username,
    [Parameter()] [string] $FTP_Password
)

function Main {
    [CmdletBinding()]
    Param (
        [Parameter()] [string] $Path,
        [Parameter()] [int] $Parts,
        [Parameter()] [int] $Depth,
        [Parameter()] [string] $FTP_Server,
        [Parameter()] [string] $FTP_Path,
        [Parameter()] [string] $FTP_Username,
        [Parameter()] [string] $FTP_Password
    )

    try {
        Import-Module PSFTP
        $sw = [Diagnostics.Stopwatch]::StartNew()

        $Credential = [System.Management.Automation.PSCredential]::New($FTP_Username, (ConvertTo-SecureString -String $FTP_Password -AsPlainText -Force))
        Set-FTPConnection -Server $FTP_Server -Credentials $Credential -Session "CDNSession" -UsePassive | Out-Null
        $FTP_Session = Get-FTPConnection -Session "CDNSession"

        $ftpParentFolderPath = (Split-Path -Path $FTP_Path -Parent).Replace("\","/")
        $ftpParentFolders = (Get-FTPChildItem -Session $FTP_Session -Path $ftpParentFolderPath | Where-Object { $_.Dir -eq "d" }).Name
        $ftpLastFolderName = $FTP_Path.TrimEnd("/").Split("/")[-1]

        if ($ftpLastFolderName -notin $ftpParentFolders) {
            New-FTPItem -Session $FTP_Session -Path $ftpParentFolderPath -Name $ftpLastFolderName
        }

        $Items_Groups = Get_Items_Groups -Path $Path -Depth $Depth -Parts $Parts

        FTP_Multi_Upload -FTP_Server $FTP_Server -Credential $Credential -FTP_Path $FTP_Path -Items_Groups $Items_Groups

        Write-Host
        Write-Host "Done."
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

function Get_Items_Groups ([string] $Path, [int] $Depth, [int] $Parts) {
    $Items_List = (Get-ChildItem -Path $Path -Depth $Depth).FullName
    $Chunk_Size = [Math]::Ceiling($Items_List.Count / $Parts)

    $Counter = [PSCustomObject] @{ Value = 0 }
    $Items_Groups = $Items_List | Group-Object -Property { [Math]::Floor($Counter.Value++ / $Chunk_Size) }

    return $Items_Groups
}

function FTP_Upload ($FTP_Server, $Credential, $FTP_Path, $Items_Group) {
    Set-FTPConnection -Server $FTP_Server -Credentials $Credential -Session "CDNSession_$($Items_Group.Name)" -UsePassive -UseBinary -KeepAlive | Out-Null
    $FTP_Session = Get-FTPConnection -Session "CDNSession_$($Items_Group.Name)"

    foreach ($File in $Items_Group.Group) {
        Add-FTPItem -Session $FTP_Session -Path $FTP_Path -LocalPath $File -Overwrite
    }
}

workflow FTP_Multi_Upload {
    Param (
        [Parameter()] $FTP_Server,
        [Parameter()] $Credential,
        [Parameter()] $FTP_Path,
        [Parameter()] $Items_Groups
    )

    foreach -parallel ($Items_Group in $Items_Groups) {
        FTP_Upload -FTP_Server $FTP_Server -Credential $Credential -FTP_Path $FTP_Path -Items_Group $Items_Group
    }
}

$Params = @{}

if ($Path) {
    $Params.Add("Path", $Path)
}

if ($Parts) {
    $Params.Add("Parts", $Parts)
}

if ($Depth) {
    $Params.Add("Depth", $Depth)
}

if ($FTP_Server) {
    $Params.Add("FTP_Server", $FTP_Server)
}

if ($FTP_Path) {
    $Params.Add("FTP_Path", $FTP_Path)
}

if ($FTP_Username) {
    $Params.Add("FTP_Username", $FTP_Username)
}

if ($FTP_Password) {
    $Params.Add("FTP_Password", $FTP_Password)
}

Main @Params