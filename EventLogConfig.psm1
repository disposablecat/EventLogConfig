function Set-EventLogAccessReadOnly{
<#
.SYNOPSIS
    Sets permissions on a local/remote computer(s) to allow a domain user to read event logs locally/remotely.
.DESCRIPTION
    Sets permissions on a local/remote computer(s) to allow a domain user to read event logs. Will give access to the Security log as well.
.PARAMETER ComputerName
    Specify a computer to connect to. If left out localhost will be used.
.PARAMETER ObjectName
    Specify a user/group that will be granted access. Will populate local domain by default.
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
    Set-EventLogAccessReadOnly -ComputerName Server1 -UserName jdoe
    Grants jdoe read-only access to the event logs on Server1
.EXAMPLE
    Set-EventLogAccessReadOnly -ComputerName Server1, Server2, Server3 -UserName jdoe
    Grants jdoe read-only access to the event logs on Server1, Server2, and Server3
.EXAMPLE
    Set-EventLogAccessReadOnly -UserName jdoe
    Grants jdoe read-only access to the event logs on the local host
#>
    [CmdletBinding()]
    [OutputType([string])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$ObjectName
    )

    Begin
    {
        $DomainObject = $ObjectName
        $LocalGroup = "Event Log Readers"
        $Domain = $env:USERDOMAIN
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule ("$Domain\$DomainObject","ReadKey","ObjectInherit,ContainerInherit","None","Allow")
        $Key = "SYSTEM\CurrentControlSet\Services\EventLog\Security"
    }
    Process
    {
        ForEach ($Computer in $ComputerName)
        {
            Try
            {
                    Test-Connection -ComputerName $Computer -Count 1 -ErrorAction Stop | Out-Null
                    $de = [ADSI]"WinNT://$Computer/$LocalGroup,group"
                    $de.Add("WinNT://$Domain/$DomainObject")
                    $RegHive = [Microsoft.Win32.RegistryHive]::LocalMachine
                    $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $Computer)
                    #Set Permissions to base event log key
                    $SecurityLogRegKey = $regKey.OpenSubKey($key,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
                    $acl = $SecurityLogRegKey.GetAccessControl()
                    $acl.SetAccessRule($Rule)
                    $SecurityLogRegKey.SetAccessControl($acl)
            }
            Catch [System.Net.NetworkInformation.PingException]
            {
                Write-Verbose "Exception Caught: Cannot ping $Computer."
            }
            Catch
            {
                #Catch any exception.
                Write-Verbose “Exception Caught: $($_.Exception.Message)”
            }
        }

    }
}