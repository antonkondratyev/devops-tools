[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)] [string] $source_server_address,
    [Parameter(Mandatory = $false)] [string] $source_server_username,
    [Parameter(Mandatory = $false)] [string] $source_server_password,

    [Parameter(Mandatory = $false)] [string] $source_server_name,
    [Parameter(Mandatory = $false)] [string] $source_server_sql_username,
    [Parameter(Mandatory = $false)] [string] $source_server_sql_password,
    [Parameter(Mandatory = $false)] [string[]] $source_databases,

    [Parameter(Mandatory = $false)] [string] $storage_address,
    [Parameter(Mandatory = $false)] [string] $storage_path,
    [Parameter(Mandatory = $false)] [string] $storage_username,
    [Parameter(Mandatory = $false)] [string] $storage_password,
    [Parameter(Mandatory = $false)] [int64] $storage_size_allocation,

    [Parameter(Mandatory = $false)] [string] $test_server_address,
    [Parameter(Mandatory = $false)] [string] $test_server_username,
    [Parameter(Mandatory = $false)] [string] $test_server_password,

    [Parameter(Mandatory = $false)] [string] $test_server_name,
    [Parameter(Mandatory = $false)] [string] $test_server_sql_username,
    [Parameter(Mandatory = $false)] [string] $test_server_sql_password,

    [Parameter(Mandatory = $false)] [string[]] $stop_related_services,
    [Parameter(Mandatory = $false)] [string[]] $start_related_services,
    [Parameter(Mandatory = $false)] [string[]] $test_related_services,

    [Parameter(Mandatory = $false)] [string] $backup_temp_path,
    [Parameter(Mandatory = $false)] [bool] $backup_compression,
    [Parameter(Mandatory = $false)] [int] $backup_retention,
    [Parameter(Mandatory = $false)] [string[]] $backup_owners,

    [Parameter(Mandatory = $false)] [bool] $verify_files,
    [Parameter(Mandatory = $false)] [string] $report_path
)

class StorageCredentials {
    [PSCredential] $SSH
    [PSCredential] $SMB

    StorageCredentials([string] $username, [string] $password, [string] $address) {
        $this.SSH = CreateSecureCredentials -username $username -password $password
        $this.SMB = CreateSecureCredentials -username "$address\$username" -password $password
    }
}

function Main() {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [string] $SourceServerAddress,
        [Parameter(Mandatory = $true)] [string] $SourceServerUsername,
        [Parameter(Mandatory = $true)] [string] $SourceServerPassword,

        [Parameter(Mandatory = $true)] [string] $SourceServerName,
        [Parameter(Mandatory = $false)] [string] $SourceServerSqlUsername,
        [Parameter(Mandatory = $false)] [string] $SourceServerSqlPassword,
        [Parameter(Mandatory = $false)] [string[]] $SourceServerDatabases,

        [Parameter(Mandatory = $true)] [string] $StorageAddress,
        [Parameter(Mandatory = $true)] [string] $StoragePath,
        [Parameter(Mandatory = $true)] [string] $StorageUsername,
        [Parameter(Mandatory = $true)] [string] $StoragePassword,
        [Parameter(Mandatory = $false)] [int64] $StorageSizeAllocation,

        [Parameter(Mandatory = $true)] [string] $TestServerAddress,
        [Parameter(Mandatory = $true)] [string] $TestServerUsername,
        [Parameter(Mandatory = $true)] [string] $TestServerPassword,

        [Parameter(Mandatory = $true)] [string] $TestServerName,
        [Parameter(Mandatory = $true)] [string] $TestServerSqlUsername,
        [Parameter(Mandatory = $true)] [string] $TestServerSqlPassword,

        [Parameter(Mandatory = $false)] [string[]] $StopRelatedServices,
        [Parameter(Mandatory = $false)] [string[]] $StartRelatedServices,
        [Parameter(Mandatory = $false)] [string[]] $TestRelatedServices,

        [Parameter(Mandatory = $false)] [string] $BackupTempPath,
        [Parameter(Mandatory = $false)] [bool] $BackupCompression,
        [Parameter(Mandatory = $true)] [int] $BackupRetention,
        [Parameter(Mandatory = $false)] [string[]] $BackupOwners,

        [Parameter(Mandatory = $false)] [bool] $VerifyFiles,
        [Parameter(Mandatory = $false)] [string] $ReportPath
    )

    $global:ProgressPreference = "SilentlyContinue"

    $sw = [Diagnostics.Stopwatch]::StartNew()

    try {
        $SourceServerCredentials = CreateSecureCredentials -username $SourceServerUsername -password $SourceServerPassword
        $SourceServerPSSession = OpenPSSession -server $SourceServerAddress -credentials $SourceServerCredentials

        if ($SourceServerSqlUsername -and $SourceServerSqlPassword) {
            $SourceServerSqlCredentials = CreateSecureCredentials -username $SourceServerSqlUsername -password $SourceServerSqlPassword
        }

        $StorageCredentials = [StorageCredentials]::New($StorageUsername, $StoragePassword, $StorageAddress)

        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:PrepareSourceServer} -ArgumentList $SourceServerName,$SourceServerSqlCredentials
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:OpenSSHSession} -ArgumentList $StorageAddress,$StorageCredentials.SSH
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:PrepareStorageServer} -ArgumentList $StoragePath
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:MountStorage} -ArgumentList $StoragePath,$StorageCredentials.SMB
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:StopRelatedServices}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:BackupDatabase}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:StartRelatedServices}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:CheckTotalBackupsSize}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:CopyBackup}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:UnmountStorage}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:CheckBackupHash}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:CleanupLocalBackup}
        Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:CloseSSHSession}

        $jsonBackupReport = Invoke-Command -Session $SourceServerPSSession -ErrorAction Stop -ScriptBlock ${function:GetBackupReport}
        $backupReport = $jsonBackupReport | ConvertFrom-Json

        $backupList = $backupReport.BackupList.Where({ $_.Status -like "OK" }) | Select-Object Name,FileName,NetworkPath
        $storage = $backupReport.Storage | Select-Object Address,LocalPath,NetworkPath

        Remove-PSSession -Session $SourceServerPSSession

        $TestServerCredentials = CreateSecureCredentials -username $TestServerUsername -password $TestServerPassword
        $TestServerPSSession = OpenPSSession -server $TestServerAddress -credentials $TestServerCredentials
        $TestServerSqlCredentials = CreateSecureCredentials -username $TestServerSqlUsername -password $TestServerSqlPassword

        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:PrepareTestServer} -ArgumentList $TestServerName,$TestServerSqlCredentials,$backupList
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:MountStorage} -ArgumentList $StoragePath,$StorageCredentials.SMB
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:CopyToRestore}
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:RestoreDatabase}
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:CleanupTestBackup}
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:UnmountStorage}
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:TestRelatedServices}
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:DropTestDatabase}
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:OpenSSHSession} -ArgumentList $StorageAddress,$StorageCredentials.SSH
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:CleanupOldestBackups} -ArgumentList $storage,$BackupRetention
        Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:CloseSSHSession}

        $jsonRestoreReport = Invoke-Command -Session $TestServerPSSession -ErrorAction Stop -ScriptBlock ${function:GetRestoreReport}
        $restoreReport = $jsonRestoreReport | ConvertFrom-Json

        Remove-PSSession -Session $TestServerPSSession

        $report = CreateReport -backupReport $backupReport -restoreReport $restoreReport
        OutputReport($report)
    }
    catch {
        Write-Host $Error[0] -ForegroundColor Red
    }
    finally {
        if (Get-PSSession) {
            if ((Get-PSSession).ComputerName -like $SourceServerAddress) {
                Remove-PSSession -ComputerName $SourceServerAddress
            }

            if ((Get-PSSession).ComputerName -like $TestServerAddress) {
                Remove-PSSession -ComputerName $TestServerAddress
            }
        }

        $sw.Stop()
        Write-Host "`nTotal Run Time: $($sw.Elapsed.ToString('hh\:mm\:ss\.fff'))`n" -ForegroundColor DarkGray

        if ($Error.Count -ne 0) {
            Write-Host "Errors: $($Error.Count)"
            Write-Host
            $Error
        }
    }
}

function SetOK() {
    Write-Host " OK" -ForegroundColor Green
}

function SetFAIL() {
    Write-Host " FAIL" -ForegroundColor Red
}

function HumanizeFileSize([int64] $sizeInByte) {
    switch ($sizeInByte) {
        { $_ -gt 1tb } { return "{0:n0} TB" -f ($_ / 1tb) }
        { $_ -gt 1gb } { return "{0:n0} GB" -f ($_ / 1gb) }
        { $_ -gt 1mb } { return "{0:n0} MB" -f ($_ / 1mb) }
        { $_ -gt 1kb } { return "{0:n0} KB" -f ($_ / 1kb) }
               default { return "{0} B" -f $_ }
    }
}

function PathToArray([string] $path) {
    return $path.Split(([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar), [System.StringSplitOptions]::RemoveEmptyEntries)
}

function CreateSecureCredentials([string] $username, [string] $password) {
    return [System.Management.Automation.PSCredential]::New($username, (ConvertTo-SecureString -String $password -AsPlainText -Force))
}

function OpenPSSession([string] $server, [PSCredential] $credentials) {
    try {
        Write-Host "Trying connection to '$($server)'..." -NoNewline

        if (!(Test-NetConnection -ComputerName $server -Port 5985 -WarningAction SilentlyContinue -InformationLevel Quiet)) {
            throw "'$($server)' is offline."
        }

        $psSession = New-PSSession -ComputerName $server -Credential $credentials -ErrorAction SilentlyContinue -ErrorVariable Err

        if (!$psSession) {
            throw $Err.Exception.GetBaseException().Message
        }

        SetOK
    }
    catch {
        SetFAIL
        throw $Error[0]
    }

    return $psSession
}

function PrepareSourceServer([string] $instanceName, [PSCredential] $sqlCredentials) {
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Management.Common") | Out-Null

    function SetOK() {
        Write-Host " OK" -ForegroundColor Green
    }

    function SetFAIL() {
        Write-Host " FAIL" -ForegroundColor Red
    }

    $global:ProgressPreference = "SilentlyContinue"

    $timestamp = Get-Date -Format yyyy-MM-dd-HHmm

    $startJob = @{
        Date = Get-Date -Format yyyy-MM-dd
        Time = Get-Date -Format HH:mm:ss
    }

    try {
        Write-Host "Checking PackageProvider NuGet..." -NoNewline
        if (!(Get-PackageProvider).Where({ $_.Name -like "NuGet" })) {
            Write-Host " Installing..." -NoNewline
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -WarningAction SilentlyContinue | Out-Null
        }
        SetOK

        Write-Host "Checking Posh-SSH Module..." -NoNewline
        if (!(Get-Module -ListAvailable -Name Posh-SSH)) {
            Write-Host " Installing..." -NoNewline
            Install-Module Posh-SSH -Force -WarningAction SilentlyContinue -Scope CurrentUser
            Import-Module Posh-SSH
        }
        SetOK

        Write-Host "Trying connection to '$($instanceName)'..." -NoNewline
        $sqlServer = [Microsoft.SqlServer.Management.Smo.Server]::New($instanceName)
        if ($sqlCredentials) {
            $sqlServer.ConnectionContext.LoginSecure = $false
            $sqlServer.ConnectionContext.Login = $sqlCredentials.UserName
            $sqlServer.ConnectionContext.SecurePassword = $sqlCredentials.Password
        }
        $sqlServer.ConnectionContext.Connect()
        SetOK

        Write-Host "Geting databases..." -NoNewline
        $systemDatabases = @("master", "model", "msdb", "tempdb")
        $offlineDatabases = ($sqlServer.Databases["master"].ExecuteWithResults("SELECT name FROM sys.databases WHERE state_desc='OFFLINE'").Tables).name
        $execudeDatabases = $systemDatabases + $offlineDatabases
        $databases = $sqlServer.Databases.Where({ $execudeDatabases -notcontains $_.Name })
        SetOK
    }
    catch {
        SetFAIL
        throw $Error[0].Exception.GetBaseException()
    }
}

function OpenSSHSession([string] $server, [PSCredential] $credentials) {
    function RunInSSH($session, $command) {
        return (Invoke-SSHCommand -Index $session.sessionId -Command $command).Output
    }

    try {
        Write-Host "Trying connection to '$($server)'..." -NoNewline

        if (!(Test-NetConnection -ComputerName $server -Port 22 -WarningAction SilentlyContinue -InformationLevel Quiet)) {
            throw "'$($server)' is offline."
        }

        $sshSession = New-SSHSession -ComputerName $server -Credential $credentials -AcceptKey:$true

        SetOK
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function PrepareStorageServer([string] $StoragePath) {
    class StorageServer {
        [string] $Address
        [string] $NetworkPath
        [string] $LocalPath
        [int64] $AvailableSize
    }

    function HumanizeFileSize([int64] $sizeInByte) {
        switch ($sizeInByte) {
            { $_ -gt 1tb } { return "{0:n0} TB" -f ($_ / 1tb) }
            { $_ -gt 1gb } { return "{0:n0} GB" -f ($_ / 1gb) }
            { $_ -gt 1mb } { return "{0:n0} MB" -f ($_ / 1mb) }
            { $_ -gt 1kb } { return "{0:n0} KB" -f ($_ / 1kb) }
                   default { return "{0} B" -f $_ }
        }
    }

    function PathToArray([string] $path) {
        return $path.Split(([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar), [System.StringSplitOptions]::RemoveEmptyEntries)
    }

    try {
        $storage = [StorageServer]::New()
        $storage.NetworkPath = $StoragePath.TrimEnd([IO.Path]::DirectorySeparatorChar)

        $folderList = PathToArray($storage.NetworkPath)
        $storage.Address = $folderList[0]

        Write-Host "Geting available storage size..." -NoNewline
        $shareName = $folderList[1]
        $sambaConfigStoragePathCmd = "sed -n '/\['$($shareName)'\]/I,/\[/{/^\[.*$/!p}' /etc/samba/smb.conf | grep path | awk -F '=' '{print `$NF}'"
        $sharePath = (RunInSSH -session $sshSession -command $sambaConfigStoragePathCmd).Trim()

        $storage.LocalPath = $sharePath.Split([IO.Path]::AltDirectorySeparatorChar) + (0..($folderList.Count-1)).Where({ $_ -gt $folderList.IndexOf($shareName) }).ForEach({ $folderList[$_] }) -join [IO.Path]::AltDirectorySeparatorChar

        $storageAvailableSizeCmd = "df -B 1 $($sharePath) | awk -F ' ' '{print `$4}' | grep -vE 'Available'"
        $storage.AvailableSize = (RunInSSH -session $sshSession -command $storageAvailableSizeCmd)

        if ($using:StorageSizeAllocation -gt $storage.AvailableSize) {
            throw "Needed storage size allocation: {0}`nAvailable drive size on storage server: {1}" -f
                $(HumanizeFileSize -sizeInByte $using:StorageSizeAllocation),
                $(HumanizeFileSize -sizeInByte $storage.AvailableSize)
        }

        SetOK
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function StopRelatedServices() {
    if (!$using:StopRelatedServices) {
        break
    }

    try {
        Write-Host "Stoping related services..."

        foreach ($serviceName in ($using:StopRelatedServices)) {
            if ($service = Get-Service -Name $serviceName) {
                Write-Host "  $($serviceName)" -NoNewline

                Stop-Service -Name $service.DisplayName -Force -NoWait

                SetOK
            }
        }
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function StartRelatedServices() {
    if (!$using:StartRelatedServices) {
        break
    }

    try {
        Write-Host "Starting related services..."

        foreach ($serviceName in ($using:StartRelatedServices)) {
            if ($service = Get-Service -Name $serviceName) {
                Write-Host "  $($serviceName)" -NoNewline

                Start-Service -Name $service.DisplayName

                SetOK
            }
        }
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function MountStorage([string] $storagePath, [PSCredential] $smbCredentials) {
    try {
        Write-Host "Mounting storage..." -NoNewline

        $storageDriveName = "STORAGE"
        Remove-PSDrive $storageDriveName -Force -ErrorAction SilentlyContinue
        New-PSDrive -Name $storageDriveName -PSProvider FileSystem -Root $storagePath -Credential $smbCredentials | Out-Null

        SetOK
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function BackupDatabase() {
    class DatabaseBackup {
        [string] $Name
        [string] $FileName
        [string] $LocalPath
        [string] $StoragePath
        [string] $NetworkPath
        [string[]] $FileGroups
        [string] $LocalHash
        [string] $StorageHash
        [bool] $IsVerifed
        [string] $Status
        [int] $Size
    }

    Write-Host "Backuping databases..."
    $backupList = [System.Collections.ArrayList]::New()

    if ($using:SourceServerDatabases) {
        $databases = $databases.Where({ $_.Name -in $using:SourceServerDatabases })
    }

    $tempBackupDirectoryName = $timestamp + "_" + (Get-Random)

    foreach ($database in $databases) {
        try {
            Write-Host "  $($database.Name)" -NoNewline

            $backup = [DatabaseBackup]::New()
            $backup.Name = $database.Name
            $backup.FileName = $database.Name + "_" + $timestamp + ".bak"
            $backup.NetworkPath = [IO.Path]::Combine($storage.NetworkPath, $database.Name, $backup.FileName)

            if ($using:VerifyFiles) {
                if ($using:BackupTempPath) {
                    $backupDirectory = [IO.Path]::Combine($using:BackupTempPath, $tempBackupDirectoryName)
                }
                else {
                    $backupDirectory = [IO.Path]::Combine($sqlServer.BackupDirectory, $tempBackupDirectoryName)
                }

                $backup.LocalPath = [IO.Path]::Combine($backupDirectory, $backup.FileName)
                $backupPath = $backup.LocalPath
            }
            else {
                $backupDirectory = [IO.Path]::Combine($storage.NetworkPath, $backup.Name)
                $backupPath = $backup.NetworkPath
            }

            if (!(Test-Path $backupDirectory)) {
                New-Item -ItemType Directory $backupDirectory -Force | Out-Null
            }

            $databaseInfo = Get-SqlDatabase -ServerInstance $instanceName -Credential $sqlCredentials -Name $database.Name
            $backup.FileGroups += $databaseInfo.FileGroups.Files.FileName
            $backup.FileGroups += $databaseInfo.LogFiles.FileName

            Backup-SqlDatabase -ServerInstance $instanceName -Credential $sqlCredentials -Database $database.Name -BackupFile $backupPath

            if ($using:VerifyFiles) {
                $backup.Size = (Get-Item $backup.LocalPath).Length
            }

            $backup.StoragePath = ([IO.Path]::Combine($storage.LocalPath, $database.Name, $backup.FileName)).Replace([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
            $backup.Status = "OK"
            $backupList.Add($backup) | Out-Null
            SetOK
        }
        catch {
            $backup.Status = "FAIL"
            $backupList.Add($backup) | Out-Null
            SetFAIL
            $Error[0].Exception.GetBaseException()
        }
    }
}

function CheckTotalBackupsSize() {
    function HumanizeFileSize([int64] $sizeInByte) {
        switch ($sizeInByte) {
            { $_ -gt 1tb } { return "{0:n0} TB" -f ($_ / 1tb) }
            { $_ -gt 1gb } { return "{0:n0} GB" -f ($_ / 1gb) }
            { $_ -gt 1mb } { return "{0:n0} MB" -f ($_ / 1mb) }
            { $_ -gt 1kb } { return "{0:n0} KB" -f ($_ / 1kb) }
                   default { return "{0} B" -f $_ }
        }
    }

    if (!$using:VerifyFiles) {
        break
    }

    try {
        Write-Host "Checking total size of all backups with available storage size..." -NoNewline
        $backupsTotalSize = ($backupList.Size | Measure-Object -Sum).Sum

        if ($backupsTotalSize -gt $storage.AvailableSize) {
            throw "Total size of all backups: {0}`nAvailable drive size on storage server: {1}" -f
                $(HumanizeFileSize -sizeInByte $backupsTotalSize),
                $(HumanizeFileSize -sizeInByte $storage.AvailableSize)
        }

        SetOK
    }
    catch {
        SetFAIL
        throw
    }
}

function CopyBackup() {
    if (!$using:VerifyFiles) {
        break
    }

    try {
        Write-Host "Copying backups to storage..."

        foreach ($backup in $backupList.Where({ $_.Status -like "OK" })) {
            Write-Host "  $($backup.Name)" -NoNewline

            $storageFolder = [IO.Path]::Combine($storage.NetworkPath, $backup.Name)

            if (!(Test-Path $storageFolder)) {
                New-Item -ItemType Directory $storageFolder -Force | Out-Null
            }

            Copy-Item -Path $backup.LocalPath -Destination $backup.NetworkPath -Force
            SetOK
        }
    }
    catch {
        SetFAIL
        throw
    }
}

function UnmountStorage() {
    Write-Host "Unmounting storage..." -NoNewline

    Remove-PSDrive $storageDriveName -Force -ErrorAction SilentlyContinue

    SetOK
}

function CheckBackupHash() {
    function CheckHashes([string] $firstHash, [string] $secondHash) {
        return $(if ($firstHash -eq $secondHash) { $true } else { $false })
    }

    if (!$using:VerifyFiles) {
        break
    }

    try {
        Write-Host "Checking backups hash..."

        foreach ($backup in $backupList.Where({ $_.Status -like "OK" })) {
            Write-Host "  $($backup.Name)" -NoNewline

            $backup.LocalHash = (Get-FileHash -Path $backup.LocalPath).Hash

            $sha256sumCmd = "sha256sum $($backup.StoragePath) | awk -F ' ' '{print `$1}'"
            $backup.StorageHash = (RunInSSH -session $sshSession -command $sha256sumCmd).ToUpper()

            $backup.IsVerifed = CheckHashes -firstHash $backup.LocalHash -secondHash $backup.StorageHash

            if ($backup.IsVerifed) {
                SetOK
            }
            else {
                SetFAIL
            }
        }
    }
    catch {
        SetFAIL
        throw
    }
}

function CleanupLocalBackup() {
    if (!$using:VerifyFiles) {
        break
    }

    try {
        Write-Host "Removing temprary backups from MSSQL server..." -NoNewline

        Remove-Item -Path $backupDirectory -Recurse -Force

        SetOK
    }
    catch {
        SetFAIL
        throw
    }
}

function CloseSSHSession() {
    $sshCloseStatus = Remove-SSHSession -SSHSession $sshSession

    if (Get-SSHSession) {
        Get-SSHSession
    }
}

function GetBackupReport() {
    $report = @{}

    $endJob = @{
        Date = Get-Date -Format yyyy-MM-dd
        Time = Get-Date -Format HH:mm:ss
    }

    $jobTime = @{
        Start = $startJob
        End = $endJob
    }

    $report.Add("JobTime", $jobTime)
    $report.Add("Storage", $storage)
    $report.Add("BackupList", $backupList)

    return $report | ConvertTo-Json -Compress
}

function PrepareTestServer([string] $instanceName, [PSCredential] $sqlCredentials, $backupList) {
    function SetOK() {
        Write-Host " OK" -ForegroundColor Green
    }

    function SetFAIL() {
        Write-Host " FAIL" -ForegroundColor Red
    }

    $global:ProgressPreference = "SilentlyContinue"

    $startJob = @{
        Date = Get-Date -Format yyyy-MM-dd
        Time = Get-Date -Format HH:mm:ss
    }

    try {
        Write-Host "Checking PackageProvider NuGet..." -NoNewline
        if (!(Get-PackageProvider).Where({ $_.Name -like "NuGet" })) {
            Write-Host " Installing..." -NoNewline
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -WarningAction SilentlyContinue | Out-Null
        }
        SetOK

        Write-Host "Checking dbatools Module..." -NoNewline
        if (!(Get-Module -ListAvailable -Name dbatools)) {
            Write-Host " Installing..." -NoNewline
            Install-Module dbatools -Force -WarningAction SilentlyContinue -Scope CurrentUser
            Import-Module dbatools
        }
        SetOK

        Write-Host "Trying connection to '$($instanceName)'..." -NoNewline
        $dbaConnection = Test-DbaConnection -SqlInstance $instanceName -Credential $sqlCredentials -EnableException -ErrorVariable Err
        if (!$dbaConnection) {
            throw $Err.Exception.GetBaseException().Message
        }
        $backupDirectory = (Get-DbaDefaultPath -SqlInstance $instanceName -SqlCredential $sqlCredentials).Backup
        SetOK
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function CopyToRestore() {
    try {
        Write-Host "Copying backups from storage..."

        foreach ($backup in $backupList) {
            Write-Host "  $($backup.Name)" -NoNewline

            Copy-Item -Path $backup.NetworkPath -Destination $backupDirectory -Force

            SetOK
        }
    }
    catch {
        SetFAIL
        throw
    }
}

function RestoreDatabase() {
    Write-Host "Restoring databases..."

    $restoreList = [System.Collections.ArrayList]::New()

    foreach ($backup in $backupList) {
        try {
            Write-Host "  $($backup.Name)" -NoNewline

            $backupPath = [IO.Path]::Combine($backupDirectory, $backup.FileName)
            $restoreResult = Restore-DbaDatabase -SqlInstance $instanceName -SqlCredential $sqlCredentials -Path $backupPath -Database $backup.Name -WithReplace

            $restoreList.Add($restoreResult) | Out-Null

            Write-Host " [$($restoreResult.DatabaseRestoreTime)]" -NoNewline -ForegroundColor DarkGray
            SetOK
        }
        catch {
            SetFAIL
            $Error[0]
        }
    }
}

function CleanupTestBackup() {
    try {
        Write-Host "Removing temprary backups from test server..." -NoNewline

        Remove-Item -Path $restoreList.BackupFile -Force

        SetOK
    }
    catch {
        SetFAIL
        throw
    }
}

function TestRelatedServices() {
    if (!$using:TestRelatedServices) {
        break
    }

    try {
        Write-Host "Testing related services..."

        foreach ($serviceName in ($using:TestRelatedServices)) {
            Write-Host "  $($serviceName)" -NoNewline

            $service = Get-Service -Name $serviceName

            if ($service.Status -eq "Running") {
                SetOK
            }
            elseif ($service.Status -eq "Stopped") {
                SetFAIL
            }
        }
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function DropTestDatabase() {
    try {
        Write-Host "Droping test databases..."

        foreach ($backup in $backupList) {
            Write-Host "  $($backup.Name)" -NoNewline

            $dropResult = Remove-DbaDatabase -SqlInstance $instanceName -Credential $sqlCredentials -Database $restoreList.DatabaseName -Confirm:$false

            SetOK
        }
    }
    catch {
        SetFAIL
        throw $Error[0]
    }
}

function CleanupOldestBackups($storage, [int] $daysToStored) {
    try {
        Write-Host "Removing files older $($daysToStored) days from storage..." -NoNewline

        $deletedFilesCmd = "find $($storage.LocalPath) -type f -mtime +$($daysToStored) -print -delete | awk -F '/' '{print `$NF}'"
        $deletedFiles = (RunInSSH -session $sshSession -command $deletedFilesCmd)

        SetOK
    }
    catch {
        SetFAIL
        throw
    }
}

function GetRestoreReport() {
    $report = @{}

    $endJob = @{
        Date = Get-Date -Format yyyy-MM-dd
        Time = Get-Date -Format HH:mm:ss
    }

    $jobTime = @{
        Start = $startJob
        End = $endJob
    }

    $report.Add("JobTime", $jobTime)
    $report.Add("RestoreList", $restoreList)
    $report.Add("DeletedFiles", $deletedFiles)

    return $report | ConvertTo-Json -Compress
}

function CreateReport($backupReport, $restoreReport) {
    $report = @{}

    foreach($databaseName in $SourceServerDatabases) {
        $backup = $backupReport.BackupList.Where({ $_.Name -eq $databaseName })
        $restore = $restoreReport.RestoreList.Where({ $_.DatabaseName -eq $databaseName })

        $report.Add($backup.Name, @{
            Size = $backup.Size
            Hash = $backup.LocalHash
            SourcePath = $backup.FileGroups
            NetworkPath = $backup.NetworkPath
            StoragePath = $backup.StoragePath
            BackupStatus = $backup.Status
            RestoreStatus = if ($restore.RestoreComplete) { "OK" } else { "FAIL" }
            TestStatus = ""
            Verify = $backup.IsVerifed
            Tested = ""
            Compression = ""
            Duration = ""
            Retention_cleanup = ""
            Retention_at = ""
        })
    }

    return $report
}

function OutputReport($report) {
    Write-Host
    Write-Host "-------------------------------------"
    Write-Host "  Report"
    Write-Host "-------------------------------------"
    Write-Host "  Start:`t$($backupReport.JobTime.Start.Date) $($backupReport.JobTime.Start.Time)"
    Write-Host "  End:`t`t$($backupReport.JobTime.End.Date) $($backupReport.JobTime.End.Time)"
    Write-Host

    foreach ($databaseName in $report.Keys) {
        $database = $report.$databaseName

        Write-Host "Database: $($databaseName)"
        Write-Host "Size: $(HumanizeFileSize($database.Size))"
        Write-Host "SHA256 Hash: $($database.Hash)"
        Write-Host "Source Path: $($database.SourcePath)"
        Write-Host "Storage Path: $($database.NetworkPath)"
        Write-Host "Status: $($database.BackupStatus)"
        Write-Host "Verify: $($database.Verify)"
        Write-Host "Tested: "
        Write-Host "Compression: yes"
        Write-Host "Duration: "
        Write-Host "Retention_cleanup: "
        Write-Host "Retention_at: "
        Write-Host "-------------------------------------"
    }
}

$Params = @{
    SourceServerAddress     = $source_server_address
    SourceServerUsername    = $source_server_username
    SourceServerPassword    = $source_server_password

    SourceServerName        = $source_server_name
    SourceServerSqlUsername = $source_server_sql_username
    SourceServerSqlPassword = $source_server_sql_password
    SourceServerDatabases   = $source_databases

    StorageAddress          = $storage_address
    StoragePath             = $storage_path
    StorageUsername         = $storage_username
    StoragePassword         = $storage_password
    StorageSizeAllocation   = $storage_size_allocation

    TestServerAddress       = $test_server_address
    TestServerUsername      = $test_server_username
    TestServerPassword      = $test_server_password

    TestServerName          = $test_server_name
    TestServerSqlUsername   = $test_server_sql_username
    TestServerSqlPassword   = $test_server_sql_password

    StopRelatedServices     = $stop_related_services
    StartRelatedServices    = $start_related_services
    TestRelatedServices     = $test_related_services

    BackupTempPath          = $backup_temp_path
    BackupCompression       = $backup_compression
    BackupRetention         = $backup_retention
    BackupOwners            = $backup_owners

    VerifyFiles             = $verify_files
    ReportPath              = $report_path
}

Main @Params