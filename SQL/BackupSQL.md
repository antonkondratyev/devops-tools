## Usage

```powershell
.\BackupSQL.ps1
    -source_server_address "mssql-server-01.contoso.com"
    -source_server_name "mssql-server-01.contoso.com\mssqlserver14"
    -source_server_username "contoso\mateo_escobedo"
    -source_server_password "qwerty123456"
    -storage_path "\\storage-server-42.contoso.com\share\project\databases"
    -storage_username "storage_user"
    -storage_password "PaSSw0rd"
    -test_server_address "test-sql-server.contoso.com"
    -test_server_username "test_server_user"
    -test_server_password "PaSSw0rd"
    -test_server_name "mssql-server-01.contoso.com\mssqlserver14"
    -test_server_sql_username "contoso\mateo_escobedo"
    -test_server_sql_password "qwerty123456"
    -backup_retention 90
    -report_path "C:\Temp\BackupDatabaseReport.json"
```