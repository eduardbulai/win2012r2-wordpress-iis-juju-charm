#ps1_sysnative

# Copyright 2016 Zsys.ro
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

Import-Module JujuLogging
Import-Module JujuWindowsUtils
Import-Module JujuHelper
Import-Module JujuHooks
Import-Module JujuUtils

#####################
###### GLOBALS ######
#####################

$WPIURL = 'http://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi'
$VCREDISTURL = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe'
$WPCLIURL = 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'
$WWWROOT = Join-Path $env:SystemDrive 'inetpub\wwwroot' # IIS web root folder
$BACKUPDIR = Join-Path $env:SystemDrive 'config\backups' # the backups folder path

#######################
###### VARIABLES ######
#######################



#######################
###### FUNCTIONS ######
#######################

# Set paths to use the installed binaries:
# PHP, WP-CLI, MySQL, WPI(Microsoft Web Platform Installer)
function Set-Paths {
    Add-ToUserPath (Join-Path ${env:ProgramFiles} 'Microsoft\Web Platform Installer')
    Add-ToUserPath (Join-Path ${env:ProgramFiles(x86)} 'PHP\v5.5')
    Add-ToUserPath (Join-Path ${env:ProgramFiles} 'MySQL\MySQL Server 5.5\bin')
    Add-ToUserPath (Join-Path ${env:SystemDrive} 'wpcli')
}

# Generates a random alphanumeric password
# Default length is 32 chars
function Generate-Password {
    Param(
        [Parameter(Mandatory=$False)]
        [Int]$Length = 32
    )

    $output = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count $Length | % {[char][int]$_})
    return $output
}

# Generates the initial config and backs it up in the initial folder
# from the config backups folder (C:\config\backups\initial)
function Generate-InitialConfigFile {
    Write-JujuLog 'Generating juju config file'
    $configFile = (Join-Path $env:SystemDrive 'wordpress.conf')
    if (Test-Path $configFile) {
        Write-JujuLog 'Config file already exists'
    } else {
        $config = @("AppPath[@]Default Web Site/$(Get-JujuCharmConfig -Scope 'site-path')",
            "SitePath[@]$(Get-JujuCharmConfig -Scope 'site-path')",
            "SiteName[@]$(Get-JujuCharmConfig -Scope 'site-name')",
            "DbServer[@]localhost",
            "DbName[@]$(Get-JujuCharmConfig -Scope 'database-name')",
            "DbUsername[@]$(Get-JujuCharmConfig -Scope 'database-user-name')",
            "DbPassword[@]$(Generate-Password)",
            "DbAdminUsername[@]root",
            "DbAdminPassword[@]$(Generate-Password)",
            "AdminUserEmail[@]$(Get-JujuCharmConfig -Scope 'admin-mail')",
            "AdminUserPassword[@]$(Get-JujuCharmConfig -Scope 'admin-password')"
        )

        Set-Content $configFile -value $config
        New-Item -ItemType Directory -Path (Join-Path $BACKUPDIR 'initial')
        Set-Content (Join-Path $BACKUPDIR 'initial\wordpress.conf') -value $config
        Write-JujuLog 'Finished generating config file'
    }

}

# Writes the wordpress.conf file out of a Hashtable param
function Write-ConfigFile {
    Param(
      [Parameter(Mandatory=$true)]
      [HashTable]$Config
    )

    Write-JujuLog 'Generating new juju config file'
    $configFile = (Join-Path $env:SystemDrive 'wordpress.conf')
    $newConfig = ''
    $Config.GetEnumerator() | Foreach-Object {
        $newConfig += ("$($_.Key)[@]$($_.Value | Out-String)" )
    }

    $newConfig = $newConfig.TrimEnd()
    Set-Content $configFile -value $newConfig -Force
    Write-JujuLog 'Finished generating config file'

}

# Read the wordpress charm config file and return a Hashtable
# Note: this does not return the contents of the wp-config.php file
function Get-WordpressConfig {
    Param()

    $configFile = (Join-Path $env:SystemDrive 'wordpress.conf')
    $content = Get-Content $configFile
    $config = @{}

    foreach ($line in $content)
    {
        $readConf = $line -Split "\[@]"
        $config.Add($readConf[0], $readConf[1])
    }

    return $config

}

# Read the wordpress original config file and return a Hashtable
function Get-WordpressInitialConfig {
    Param()

    $configFile = (Join-Path $BACKUPDIR 'initial\wordpress.conf')
    $content = Get-Content $configFile
    $config = @{}

    foreach ($line in $content)
    {
        $readConf = $line -Split "\[@]"
        $config.Add($readConf[0], $readConf[1])
    }

    return $config

}

# Init function for first time use
function Start-InitCharm {
    Write-JujuLog 'Initializing charm'

    Start-TimeResync
    Install-IIS
    Install-WPI
    Generate-InitialConfigFile
    Install-Wordpress
    Install-WPCli
    Configure-Wordpress

    Write-JujuLog 'Initializing finished'
}

# Enabling IIS Server and required components
# Note: tested only on Windows Server 2012R2 amd64
function Install-IIS {
    Write-JujuLog 'Installing IIS'

    $iisWindowsFeatures = @( "Web-Server", "Web-Http-Redirect",
        "Web-DAV-Publishing", "Web-Custom-Logging", "Web-Log-Libraries",
        "Web-ODBC-Logging", "Web-Request-Monitor", "Web-Http-Tracing",
        "Web-Mgmt-Compat", "Web-Scripting-Tools",
        "Web-Mgmt-Service", "Web-CGI" )
    Install-WindowsFeature $iisWindowsFeatures

    Write-JujuLog 'Finished installing IIS'
}

# Microsoft Web Platform Installer makes the installation of Wordpress and
# all of its requisites easier and leaner
function Install-WPI {

    Install-VCREDIST

    Write-JujuLog 'Installing WPI'

    $wpiPath = Download-File $WPIURL

    Start-Process $wpiPath /q -Wait

    Add-ToUserPath (Join-Path ${env:ProgramFiles} 'Microsoft\Web Platform Installer')

    Write-JujuLog 'WPI installation complete'

}

# Make a backup of the current configs
# (wp-config.php for Wordpress and wordpress.conf for Juju)
function Backup-Configs {
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Timestamp=$(Get-Date -Format yyyyMMdd-HHmmss)
    )

    Write-JujuLog 'Starting configs backup'

    $backupPath = Join-Path $BACKUPDIR $Timestamp
    if(!(Test-Path $backupPath)){
        New-Item -ItemType Directory -Path $backupPath
    }
    $config = Get-WordpressConfig
    $wpConfigFile = (Get-ChildItem -Path $WWWROOT -Filter wp-config.php -Recurse -ErrorAction SilentlyContinue -Force).FullName
    try {
      	Copy-Item -Force $wpConfigFile $backupPath
    } catch {

    }
    Write-JujuLog 'Copying main config to backup'
  	Copy-Item -Force (Join-Path $env:SystemDrive "wordpress.conf") $backupPath

    Write-JujuLog "Configs backed up in $backupPath"

    return $backupPath
}

# Make a backup of the currently used database
# Note: the backup file also contains the DROP TABLE instructions for the
# WordPress tables to remove any deprecated data that already exists in the
# database.
# USE WITH CAUTION!
function Start-DatabaseBackup {
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Timestamp=$(Get-Date -Format yyyyMMdd-HHmmss)
    )

    Write-JujuLog 'Starting database backup'

    $backupPath = Join-Path $BACKUPDIR $Timestamp
    if (!(Test-Path $backupPath)){
        New-Item -ItemType Directory -Path $backupPath
    }

    $backupFile = Join-Path $backupPath 'database.sql'

    wp-cli db export $backupFile --path=$(Join-Path $WWWROOT "\$($config['SitePath'])") | Out-Host

    Write-JujuLog "Database backup file created: $backupFile"

    return $backupFile
}

# Check if the username and password exist and create them if they don't
function Start-CheckAndCreateDbCredentials{

    $config = Get-WordpressConfig
    Write-JujuLog 'Checking and - if needed - creating MySQL username/database'
    Write-JujuLog 'Checking username'
    $mysqlUserCheck = (mysql -h"$($config['DbServer'])" -u"$($config['DbAdminUsername'])" -p"$($config['DbAdminPassword'])" -e "SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = '$($config['DbUsername'])')")
    Write-JujuLog 'Checking database'
    $mysqlDatabaseCheck = (mysql -h"$($config['DbServer'])" -u"$($config['DbAdminUsername'])" -p"$($config['DbAdminPassword'])" --skip-column-names -e "SHOW DATABASES LIKE '$($config['DbName'])'").Length
    if (($mysqlUserCheck -ne $null) -And ($mysqlUserCheck[-1] -eq 0)){
        Write-JujuLog 'Creating user'
        mysql -h"$($config['DbServer'])" -u"$($config['DbAdminUsername'])" -p"$($config['DbAdminPassword'])" -e "CREATE USER '$($config['DbUsername'])'@'$($config['DbServer'])' IDENTIFIED BY '$($config['DbPassword'])';"
    }
    if($mysqlDatabaseCheck -eq 0){
        Write-JujuLog 'Creating database and granting privileges'
        mysql -h"$($config['DbServer'])" -u"$($config['DbAdminUsername'])" -p"$($config['DbAdminPassword'])" -e "CREATE DATABASE $($config['DbName']); GRANT ALL PRIVILEGES ON $($config['DbName']).* TO '$($config['DbUsername'])'@'$($config['DbServer'])'; FLUSH PRIVILEGES;"
    }
    Write-JujuLog 'Finished checking and - if needed - creating MySQL username/database'
}

# Restores the database when the database config has been changed
function Start-DatabaseRestore {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SQLfile
    )

    $config = Get-WordpressConfig

    Write-JujuLog "Starting database restore to $($config['DbName'])"

    wp-cli db create --path=$(Join-Path $WWWROOT "\$($config['SitePath'])") --debug
    wp-cli db import $SQLfile --path=$(Join-Path $WWWROOT "\$($config['SitePath'])") --debug

    Write-JujuLog "Database restored from $SQLfile"
}

# Needed for PHP runtime to work
function Install-VCREDIST {

    Write-JujuLog 'Installing VCREDIST'

    $vcredistPath = Download-File $VCREDISTURL

    Start-Process $vcredistPath /q -Wait

    Write-JujuLog 'VCREDIST installation complete'

}

# Using WPI to install Wordpress and its prerequisites
function Install-Wordpress {

    Write-JujuLog 'Installing Wordpress'
    $configFile = Join-Path $env:SystemDrive 'wordpress.conf'
    $config = Get-WordpressConfig

    WebPICMD-x64 /Install /Products:MySQL_5_5 /AcceptEULA /MySQLPassword:$($config['DbAdminPassword'])

    WebPICMD-x64 /Install /Application:WordPress@$($configFile) /AcceptEULA

    Start-ExternalCommand {
        icacls.exe "$WWWROOT" /t /q /grant "IUSR:(OI)(CI)F"
    }

    Start-ExternalCommand {
        icacls.exe "$WWWROOT" /t /q /grant "jujud:(OI)(CI)F"
    }

    Add-ToUserPath (Join-Path ${env:ProgramFiles(x86)} 'PHP\v5.5')

    Add-ToUserPath (Join-Path ${env:ProgramFiles} 'MySQL\MySQL Server 5.5\bin')

    Set-Content (Join-Path $env:SystemDrive 'mysql.root.passwd') -value $config['DbAdminPassword']

    Write-JujuLog 'Wordpress installation complete'

}

# Install WPCli for interacting with the wordpress installation
function Install-WPCli {

    Write-JujuLog 'Installing WPCli'

    $wpcliPath = Download-File $WPCLIURL
    $wpcliRoot = Join-Path $env:SystemDrive 'wpcli'

    if (!(Test-Path $wpcliRoot)){
        New-Item -ItemType Directory -Path $wpcliRoot
    }

    try {
        Move-Item $wpcliPath "$wpcliRoot\"
    } catch {

    }

    $wpcliBat = Join-Path $wpcliRoot "wp-cli.bat"
    $content = @(
        "@echo off",
        "SET SCRIPT_HOME=%~dp0",
        'php "%SCRIPT_HOME%wp-cli.phar" %*'
    )
    Set-Content $wpcliBat $content

    Add-ToUserPath $wpcliRoot

    Write-JujuLog 'WPCli installation complete'

}

# Configure wordpress useing the current wordpress.conf config file
function Configure-Wordpress {
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Timestamp=$(Get-Date -Format yyyyMMdd-HHmmss)
    )
    $config = Get-WordpressConfig

    Write-JujuLog "(Re)Configuring Wordpress using $($config['DbName'])"

    $backupPath = Join-Path $BACKUPDIR $Timestamp
    if (!(Test-Path $backupPath)){
        New-Item -ItemType Directory -Path $backupPath
    }

    Write-JujuLog "Backing up and deleting $(Join-Path $WWWROOT "\$($config['SitePath'])\wp-config.php")"
    try {
        Copy-Item -Force (Join-Path $WWWROOT "\$($config['SitePath'])\wp-config.php") $backupPath
    } catch {

    }
    try {
        Remove-Item -Force (Join-Path $WWWROOT "\$($config['SitePath'])\wp-config.php")
    } catch {

    }

    wp-cli core config --path=$(Join-Path $WWWROOT "\$($config['SitePath'])") --dbname=$($config['DbName']) --dbhost=$($config['DbServer']) --dbuser=$($config['DbUsername']) --dbpass=$($config['DbPassword']) --debug | Out-Host

    wp-cli db create --path=$(Join-Path $WWWROOT "\$($config['SitePath'])") --debug | Out-Host

    wp-cli core install --path=$(Join-Path $WWWROOT "\$($config['SitePath'])") --url="http://$(Get-JujuUnit -Attribute 'private-address')/$($config['SitePath'])" --title=$($config['SiteName']) --admin_user='Administrator' --admin_password=$($config['AdminUserPassword']) --admin_email=$($config['AdminUserEmail']) --debug | Out-Host

}

# Move WordPress to a new path deleting the old path
# Makes filesystem changes in IIS's web root folder
function Move-WordpressPath {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Source="",
        [string]$Destination,
        [Parameter(Mandatory=$False)]
        [string]$Timestamp=$(Get-Date -Format yyyyMMdd-HHmmss)
    )

    $tempPath = Join-Path $env:TEMP "juju-backups\$($Timestamp)\www"
    $src = Join-Path $WWWROOT $Source
    $dest = Join-Path $WWWROOT $Destination
    New-Item -ItemType Directory $tempPath
    Copy-Item -Recurse -Force "$($src)*" "$($tempPath)\"
    Start-ExecuteWithRetry {
        Remove-Item -Recurse -Force "$WWWROOT\*"
    }
    if (!(Test-Path $dest)) {
        New-Item -ItemType Directory $dest
    }
    Copy-Item -Recurse -Force "$($tempPath)\*" "$($dest)"
    Remove-Item -Recurse -Force $tempPath
}

# Function to download a file in a temporary folder
# Retries if the download failed for some reason
# Returns the absolute path on disk where the file was downloaded
function Download-File {
    Param(
        [Parameter(Mandatory=$True)]
        [System.Uri]$Uri
    )

    Write-JujuLog "Downloading file $Uri"

    $OutFile = $Uri.PathAndQuery.Substring($Uri.PathAndQuery.LastIndexOf("/") + 1)

    $OutPath = Join-Path $env:TEMP $OutFile

    Start-ExecuteWithRetry {
        (New-Object System.Net.WebClient).DownloadFile($Uri, $OutPath)
    }

    Write-JujuLog 'File downloaded'

    return $OutPath
}

# The main function that is triggered when the charm is deployed for the first time
function Run-InstallHook {
    Param()

    Write-JujuLog 'Running install hook.'

    Start-InitCharm

    Write-JujuLog 'Install hook finished'

}

function Run-StartHook {
    Param()

    Write-JujuLog 'Running start hook.'

    Write-JujuLog 'Finished start hook.'
}

# The function that is triggered when the charm's configuration has been changed
# It makes changes based on the context of the changes:
# 1. Database changes - when database-name and/or database-user-name changes
# 2. WordPress changes - when the title, admin password and/or email changes
# 3. WordPress path changes - when the site-path has been changed
function Run-ConfigChangedHook {
    Param()

    Write-JujuLog 'Running config changed hook.'

    $config = Get-WordpressConfig
    $pathChanged = $false
    $configChanged = $false
    $dbChanged = $false
    $timestamp = (Get-Date -Format yyyyMMdd-HHmmss)
    Set-Paths

    if ($config['SitePath'] -ne (Get-JujuCharmConfig -Scope 'site-path')) {
        $pathChanged = $true
    }

    if (($config['SiteName'] -ne (Get-JujuCharmConfig -Scope 'site-name')) -Or ($config['AdminUserPassword'] -ne (Get-JujuCharmConfig -Scope 'admin-password')) -Or ($config['AdminUserEmail'] -ne (Get-JujuCharmConfig -Scope 'admin-mail'))) {
        $configChanged = $true
    }

    if (($config['DbName'] -ne (Get-JujuCharmConfig -Scope 'database-name')) -Or ($config['DbUsername'] -ne (Get-JujuCharmConfig -Scope 'database-user-name'))) {
        if (($config['DbServer'] -ne 'localhost')){
            Request-MySQLRelationCredentials
        }
        $dbChanged = $true
    }

    #Write-JujuLog "Changes => Path -> $pathChanged, Config -> $configChanged, Database -> $dbChanged"
    if (($pathChanged)){
        Move-WordpressPath "$($config['SitePath'])\" "$(Get-JujuCharmConfig -Scope 'site-path')\" -Timestamp $timestamp
        $config['SitePath'] = (Get-JujuCharmConfig -Scope 'site-path')
        wp-cli option update siteurl "http://$(Get-JujuUnit -Attribute 'private-address')/$($config['SitePath'])" --debug --path=$(Join-Path $WWWROOT "\$($config['SitePath'])")
        wp-cli option update home "http://$(Get-JujuUnit -Attribute 'private-address')/$($config['SitePath'])" --debug --path=$(Join-Path $WWWROOT "\$($config['SitePath'])")
    }

    if (($configChanged)){
        $config['SiteName'] = (Get-JujuCharmConfig -Scope 'site-name')
        $config['AdminUserPassword'] = (Get-JujuCharmConfig -Scope 'admin-password')
        $config['AdminUserEmail'] = (Get-JujuCharmConfig -Scope 'admin-mail')
        wp-cli option update blogname $($config['SiteName']) --debug --path=$(Join-Path $WWWROOT "\$($config['SitePath'])")
        wp-cli option update admin_email $($config['AdminUserEmail']) --debug --path=$(Join-Path $WWWROOT "\$($config['SitePath'])")
        wp-cli user update 1 --user_pass=$($config['AdminUserPassword']) --user_email=$($config['AdminUserEmail']) --debug --path=$(Join-Path $WWWROOT "\$($config['SitePath'])")
    }

    Backup-Configs $timestamp
    if (($dbChanged)) {
        $dbBackupFile = Start-DatabaseBackup $timestamp
        $config['DbName'] = (Get-JujuCharmConfig -Scope 'database-name')
        $config['DbUsername'] = (Get-JujuCharmConfig -Scope 'database-user-name')
    }

    Write-ConfigFile $config
    if(($dbChanged)){
        Start-CheckAndCreateDbCredentials
        Configure-Wordpress $timestamp
        Start-DatabaseRestore $dbBackupFile
    }

    Write-JujuLog 'Finished config changed hook.'
}

# Not yet implemented
function Run-UpgradeHook {
    Param()

    Write-JujuLog 'Running upgrade hook.'

    Write-JujuLog 'Finished upgrade hook.'
}

# Not yet implemented
function Run-StopHook {
    Param()

    Write-JujuLog 'Running stop hook.'

    Write-JujuLog 'Finished stop hook.'
}

function Request-MySQLRelationCredentials {
    $settings = @{
        'username' = Get-JujuCharmConfig -Scope 'database-user-name';
        'database' = Get-JujuCharmConfig -Scope 'database-name';
        'hostname' = Get-JujuUnit -Attribute 'private-address'
    }

    $rids = Get-JujuRelationIds 'mysql-db'
    foreach ($r in $rids) {
        try {
            Set-JujuRelation -Settings $settings -RelationId $r
            Write-JujuLog "Set up relation with ID $r"
        } catch {
            Write-JujuError "Failed to set MySQL relation settings."
        }
    }
}

# Function triggered when a MySQL relation is created
function Run-MySqlRelationJoinedHook {
    Param()

    Write-JujuLog 'Running MySQL joined hook.'

    Request-MySQLRelationCredentials

    Write-JujuLog 'Finished MySQL joined hook.'
}

# Function triggered when A MySQL relation changes
function Run-MySqlRelationChangedHook {
    Param()

    Set-Paths
    Write-JujuLog 'Running MySQL changed hook.'

    $requiredCtx = @{
        "db_host" = $null;
        "password" = $null;
    }
    $ctxt = Get-JujuRelationContext -Relation "mysql-db" -RequiredContext $requiredCtx

    if ($ctxt.Count){

        Write-JujuLog "Got new context MySQL credentials"

        $timestamp = Get-Date -Format yyyyMMdd-HHmmss
        $config = Get-WordpressConfig

        Backup-Configs $timestamp
        $dbBackupFile = Start-DatabaseBackup $timestamp
        $config['DbServer'] = $ctxt['db_host']
        $config['DbPassword'] = $ctxt['password']

        Write-ConfigFile $config
        Start-CheckAndCreateDbCredentials
        Configure-Wordpress $timestamp
        Start-DatabaseRestore $dbBackupFile
    }

    Write-JujuLog "Finished MySQL changed hook."
}

# Function triggered when deleting a MySQL relation
# Note: reads the MySQL setting from the initial config that was generated when
# the charm was first deployed
function Run-MySqlRelationDepartedHook {
    Param()

    Set-Paths
    Write-JujuLog 'Running MySQL departed hook.'

    $timestamp = Get-Date -Format yyyyMMdd-HHmmss
    $config = Get-WordpressConfig
    $initialConfig = Get-WordpressInitialConfig

    Backup-Configs $timestamp
    $dbBackupFile = Start-DatabaseBackup $timestamp
    $config['DbServer'] = $initialConfig['DbServer']
    $config['DbPassword'] = $initialConfig['DbPassword']
    $config['DbName'] = $initialConfig['DbName']
    $config['DbUsername'] = $initialConfig['DbUsername']

    Write-ConfigFile $config
    Configure-Wordpress $timestamp
    Start-DatabaseRestore $dbBackupFile

    Write-JujuLog 'Finished MySQL departed hook.'
}

# Not yet implemented
function Run-MySqlRelationBrokenHook {
    Param()

    # This happens after relation is departed

    Write-JujuLog 'Running MySQL broken hook.'

    Write-JujuLog 'Finished MySQL broken hook.'
}

Export-ModuleMember -Function Run-InstallHook
Export-ModuleMember -Function Run-StartHook
Export-ModuleMember -Function Run-ConfigChangedHook
Export-ModuleMember -Function Run-UpgradeHook
Export-ModuleMember -Function Run-StopHook
Export-ModuleMember -Function Run-MySqlRelationJoinedHook
Export-ModuleMember -Function Run-MySqlRelationChangedHook
Export-ModuleMember -Function Run-MySqlRelationDepartedHook
Export-ModuleMember -Function Run-MySqlRelationBrokenHook
