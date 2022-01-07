#region Check_SNMP_Value_If_Exists
<#
.SYNOPSIS
Checks if the value provided by the snmp deamon is a valid value

.DESCRIPTION
Checks if the value provided by the snmp deamon is a valid value

.PARAMETER SNMPValue
The Output of an SNMP request

.EXAMPLE
Check_SNMP_Value_If_Exists -SNMPValue $AllSNMPDATA.Key

.NOTES

#>
function Check_SNMP_Value_If_Exists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        $SNMPValue
    )

    if (
        $SNMPValue -notlike "*NoSuchInstance*" -and `
        $SNMPValue -notlike "*NoSuchObject*" -and `
        $SNMPValue -ne "" -and `
        $null -ne $SNMPValue)
    { 
        return $true
    }
    else { 
        return $false
    }
}
Export-ModuleMember -Function Check_SNMP_Value_If_Exists 
#endregion

#region Convert_Version_To_Accumulated
<#
    .Description
    Compares to versions insertet as an string array

    .example
    $FoundVersionArray = "21.2.16.590".Split(".")
    $MinVerionArray = "11.5.22.980".Split(".")  
    Convert_Version_To_Accumulated -VersionArray $FoundVersionArray -lt Convert_Version_To_Accumulated -VersionArray $MinVerionArray
#>
function Convert_Version_To_Accumulated {
    [CmdletBinding()]
    param (
        # VersionArray
        [Parameter(Mandatory = $true)]
        $VersionArray
    )

    [int64]$Version = ([int64]$VersionArray[3] * 1 + [int64]$VersionArray[2] * 10000 + [int64]$VersionArray[1] * 100000000 + [int64]$VersionArray[0] * 1000000000000)

    return [int64]$Version
}
Export-ModuleMember -Function Convert_Version_To_Accumulated
#endregion

#region Convert_Date_To_German
<#
    .Description
    Converts to german time format
#>
function Convert_Date_To_German {
    [CmdletBinding()]
    param (
        [System.DateTime]
        $DateObj
    )    
    return (Get-Date $Dateobj -Format "dd.MM.yyyy HH:mm:ss")
}
Export-ModuleMember -Function Convert_Date_To_German
#endregion

#region Test_FileLock
<#
.Description
Check if a file is in use
#>
function Test_FileLock {
    param (
        [parameter(Mandatory=$true)][string]$Path
    )

    $oFile = New-Object System.IO.FileInfo $Path
    if ((Test-Path -Path $Path) -eq $false) {
        return $false
    }
    try {
        $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        if ($oStream) {
            $oStream.Close()
        }
        $false
    }
    catch {
        # file is locked by a process.
        return $true
    }
}
Export-ModuleMember -Function Test_FileLock 
#endregion

#region Write_Separator 
<#
.Description
writes separator
#>
function Write_Separator {
    Write-Host ""
    Write-Host "----------------------------------------------------------"
}
Export-ModuleMember -Function Write_Separator 
#endregion

#region Check_SNMP_Module_Installed
<#
.SYNOPSIS
Checks if the SNMP Module is installed

.DESCRIPTION
Checks if the SNMP Module is installed

.EXAMPLE
Check_SNMP_Module_Installed

.NOTES
No Parameters
#>
function Check_SNMP_Module_Installed {
    if ([environment]::OSVersion.Version.Major -gt 8) {
        if ($null -eq (Get-Module -ListAvailable -Name Snmp)) {
            Write-Host "PowerShell Module SNMP is not installed!"
            Error_Exit
        }
    }
    else {
        $PSModulePath1 = "C:\Program Files\WindowsPowerShell\Modules"
        $PSModulePath2 = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
    
        if (Test-Path -path "$PSModulePath1\SNMP\*\SNMP.psm1") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Scope Process
                Import-Module "$PSModulePath1\SNMP\1.0.0.1\SNMP.psm1"
                Add-Type -Path "$PSModulePath1\SNMP\1.0.0.1\SharpSnmpLib.dll"
            }
            catch { 
                Write-Host "(Error - SNMP-Module): $($PSItem.Exception.Message)"
                Error_Exit
            }
        }
        elseif (Test-Path -path "$PSModulePath2\SNMP\*\SNMP.psm1") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Scope Process
                Import-Module "$PSModulePath2\SNMP\1.0.0.1\SNMP.psm1"
                Add-Type -Path "$PSModulePath2\SNMP\1.0.0.1\SharpSnmpLib.dll"
            }
            catch { 
                Write-Host "(Error - SNMP-Module): $($PSItem.Exception.Message)"
                Error_Exit
            }
        }
        else { 
            Write-Host "PowerShell Module SNMP is not installed!"
            Error_Exit
        }
    }
}
Export-ModuleMember -Function Check_SNMP_Module_Installed
#endregion

#region Error_Exit
<#
    .Description
    Increases the Count in $ErrorCount and does an Exit
#>
function Error_Exit {
    $Script:ErrorCount++
    Exit 1001
}
Export-ModuleMember -Function Error_Exit
#endregion

#region Get-N_Able_RMM_Data
<#
.DESCRIPTION
Pulls N-Able RMM API Data 

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881
                                    
.PARAMETER Service
Service you want do use, for example: list_clients

.EXAMPLE
Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_clients"

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/data_extraction_api.htm
#>
function Get-N_Able_RMM_Data {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $Service
    )

    try {
        $Endpoint = "https://$($Hostname)/api/?apikey=$($ApiKey)&service=$($Service)"
        [xml]$N_Able_RMM_Data = (Invoke-RestMethod -Uri $Endpoint -Method Post).InnerXml    
        return $N_Able_RMM_Data    
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Data
#endregion

#region Get-N_Able_RMM_Clients
<#
.DESCRIPTION
Pulls N-Able RMM Clients 

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.EXAMPLE
Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_clients"

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/listing_clients_.htm
#>
function Get-N_Able_RMM_Clients {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey
    )

    try {
        $N_Able_RMM_Data = Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_clients"
        return ($N_Able_RMM_Data.SelectNodes("//client"))
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Clients
#endregion

#region Get-N_Able_RMM_Checks
<#
.DESCRIPTION
Pulls N-Able RMM Device Checks

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.PARAMETER DeviceID
DeviceID of an Device, for example: 1519987

.EXAMPLE
Get-N_Able_RMM_Checks -Hostname $Hostname -ApiKey $ApiKey -DeviceID $DeviceID

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/listing_checks_.htm
#>
function Get-N_Able_RMM_Checks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,
        
        [Parameter(Mandatory)]
        [string]
        $DeviceID
    )
    try {
        $Checks = (Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_checks&deviceid=$($DeviceID)").result.items.check
        return $Checks
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Checks
#endregion

#region Get-N_Able_RMM_Client_Devices
<#
.DESCRIPTION
Pulls N-Able RMM Client Devices 

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.PARAMETER ClientID
ClientID of an Client, for example: 134615

.PARAMETER DeviceType
DeviceType of the Device, can only be 'server', 'workstation', 'mobile_device'

.EXAMPLE
Get-N_Able_RMM_Client_Devices -Hostname $Hostname -ApiKey $ApiKey -ClientID $ClientID -DeviceType server

.EXAMPLE
Get-N_Able_RMM_Client_Devices -Hostname $Hostname -ApiKey $ApiKey -ClientID $ClientID -DeviceType workstation

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/listing_devices_at_client_.htm
#>
function Get-N_Able_RMM_Client_Devices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $ClientID,

        [Parameter(Mandatory)]
        [ValidateSet("server","workstation","mobile_device")]
        [string]
        $DeviceType
    )

    try {
        if ($DeviceType -ceq "Server" -or $DeviceType -ceq "Workstation") {
            throw "Parameter 'DeviceType' is case sensitiv"
        }
        $N_Able_RMM_Data = Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_devices_at_client&clientid=$($ClientID)&devicetype=$($DeviceType)"
        if ("" -ne $N_Able_RMM_Data.SelectNodes("//workstation")) {
            return ($N_Able_RMM_Data.SelectNodes("//workstation"))
        }
        elseif ("" -ne $N_Able_RMM_Data.SelectNodes("//server")) {
            return ($N_Able_RMM_Data.SelectNodes("//server"))
        }
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Client_Devices
#endregion

#region Get-N_Able_RMM_Templates
<#
.DESCRIPTION
Pulls N-Able RMM Templates

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.PARAMETER DeviceType
DeviceType of the Device, can only be 'server', 'workstation'

.EXAMPLE
Get-N_Able_RMM_Templates -Hostname $Hostname -ApiKey $ApiKey -DeviceType server

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/listing_checks_.htm
#>
function Get-N_Able_RMM_Templates{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,
        
        [Parameter(Mandatory)]
        [ValidateSet("server","workstation")]
        [string]
        $DeviceType
    )
    try {
        if ($DeviceType -ceq "Server" -or $DeviceType -ceq "Workstation") {
            throw "Parameter 'DeviceType' is case sensitiv"
        }
        else {
            $Templates = (Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_templates&devicetype=$($DeviceType)").result.items.installation_template
            return $Templates | Select-Object templateid,@{label="name"; expression={$PSItem.name.'#cdata-section'}}
        }
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Templates
#endregion

#region Get-N_Able_RMM_Device_Monitoring_Details
<#
.DESCRIPTION
Lists all monitoring information for the device (server or workstation) identified by the deviceid.

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.PARAMETER DeviceID
DeviceID of an Device, for example: 1519987

.EXAMPLE
Get-N_Able_RMM_Device_Monitoring_Details -Hostname $Hostname -ApiKey $ApiKey -DeviceID $DeviceID

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/listing_device_monitoring_deta.htm
#>
function Get-N_Able_RMM_Device_Monitoring_Details {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $DeviceID
    )

    try {
        $N_Able_RMM_Data = Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_device_monitoring_details&deviceid=$($DeviceID)"
        if ("" -ne $N_Able_RMM_Data.SelectNodes("//workstation")) {
            return ($N_Able_RMM_Data.SelectNodes("//workstation"))
        }
        elseif ("" -ne $N_Able_RMM_Data.SelectNodes("//server")) {
            return ($N_Able_RMM_Data.SelectNodes("//server"))
        }
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Device_Monitoring_Details
#endregion

#region Get-N_Able_RMM_Device_Patches
<#
.DESCRIPTION
Pulls N-Able RMM Device Patch Status

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.PARAMETER DeviceID
DeviceID of an Device, for example: 1519987

.EXAMPLE
Get-N_Able_RMM_Device_Patches -Hostname $Hostname -ApiKey $ApiKey -DeviceID $DeviceID

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/list_all_patches_for_device.htm
#>
function Get-N_Able_RMM_Device_Patches {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $DeviceID
    )
    try {
        $N_Able_RMM_Data = Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "patch_list_all&deviceid=$($DeviceID)"
        return ($N_Able_RMM_Data.SelectNodes("//patch"))
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Device_Patches
#endregion

#region Get-N_Able_RMM_Device_AssetDetails
<#
.DESCRIPTION
Pulls N-Able RMM Device Asset Details, like installed hardware or software

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.PARAMETER DeviceID
DeviceID of an Device, for example: 1519987

.PARAMETER AssetType
AssetType of an Device, for example: software or hardware

.EXAMPLE
Get-N_Able_RMM_Device_AssetDetails -Hostname $Hostname -ApiKey $ApiKey -DeviceID $DeviceID -AssetType software

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/listing_device_asset_details.htm
#>
function Get-N_Able_RMM_Device_AssetDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $DeviceID,

        [Parameter(Mandatory)]
        [ValidateSet("hardware","software")]
        [string]
        $AssetType
    )
    try {
        $N_Able_RMM_Data = Get-N_Able_RMM_Data -Hostname $Hostname -ApiKey $ApiKey -Service "list_device_asset_details&deviceid=$($DeviceID)"

        switch ($AssetType) {
            "hardware" { return ($N_Able_RMM_Data.result.hardware.item) }
            "software" { return ($N_Able_RMM_Data.result.software.item) }
            Default { throw "asset type not defined" }
        }        
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Device_AssetDetails
#endregion

#region Get-N_Able_RMM_Devices_With_Software
<#
.DESCRIPTION
Pulls N-Able RMM with the specified Software 

.PARAMETER Hostname
Hostname of the Dashboard, for example: wwwgermany1.systemmonitor.eu.com

.PARAMETER ApiKey
APIKey of the Dashboard, for example: d48a36b88c8ffhthtfdhjtzj5d653881

.PARAMETER SearchPattern
Type a string which should be found at the installed software, for example: veeam

.PARAMETER DeviceType
DeviceType of the Device, can only be 'server', 'workstation'

.EXAMPLE
Get-N_Able_RMM_Devices_With_Software -Hostname $Hostname -ApiKey $ApiKey -SearchPattern 'Veeam' -DeviceType server

.NOTES
https://documentation.n-able.com/remote-management/userguide/Content/data_extraction_api.htm
#>
function Get-N_Able_RMM_Devices_With_Software {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $SearchPattern,

        [Parameter(Mandatory)]
        [ValidateSet("workstation","server")]
        [string]
        $DeviceType
    )

    try {
        $All_Data = @{}
        $All_Clients = Get-N_Able_RMM_Clients -Hostname $Hostname -ApiKey $ApiKey

        foreach ($Client in $All_Clients) {
            [System.Collections.Arraylist]$DevicesFound = @()

            Write-Verbose -Message "Getting Client Devices"
            $DevicesToCheck = Get-N_Able_RMM_Client_Devices -Hostname $Hostname -ApiKey $ApiKey -ClientID $Client.clientid -DeviceType $DeviceType
                    
            foreach($Device in $DevicesToCheck) {
                $TempVar = (Get-N_Able_RMM_Device_AssetDetails -Hostname $Hostname -ApiKey $ApiKey -DeviceID $Device.ID -AssetType software | Where-Object -FilterScript { $PSItem.name.'#cdata-section' -like "*$($SearchPattern)*" }).name.'#cdata-section'
                if ($TempVar) {
                    $DevicesFound.Add("$($Device.Name.'#cdata-section')") | Out-Null
                }
            }

            if ($null -ne $DevicesFound -and $DevicesFound -ne "") {
                Write-Verbose -Message "Adding '$($Client.name.'#cdata-section')' to All_Data Object"
                $All_Data.Add($($Client.name.'#cdata-section'),$DevicesFound)
            }
        }
        
        return $All_Data
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}
Export-ModuleMember -Function Get-N_Able_RMM_Devices_With_Software
#endregion