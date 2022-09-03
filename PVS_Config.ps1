<#

   	**********************************************************************************************************
	Powershell script to configure Citrix Provisioning Services

	Operating system			: Windows Server 2019 GUI
	Commandline parameters		: CreatevDiskStore,PVSWindowsFeatureReq,DisableTCPoffload.Afconfig
	Author(s)				    : S.N. Baars
	Version					    : 0.0.4
	Date					    : 03-09-2022
	Tags					    : Citrix PVS

	ScriptEngine				: Powershell

	Version  Date        Author  Changelog
	----------------------------------------------------------------------------------------------------------
	0.1    13-03-2016  SNB      First version
    0.2    26-2-2020   RB       Line 163 aangepast, EventloggingEnabled hoeft geen true erachter.
    0.3    20-08-2020  SNB      Netwerkkaart instellingen toegevoegd.
    0.4    27-08-2020  SNB      Configureren van de AnswerFiles.

	**********************************************************************************************************
#>

<#--------------------------------------------
            Set parameters
--------------------------------------------#>
Param(
  [Parameter(ParameterSetName='CreatevDiskStore')]
  [switch]$CreatevDiskStore,
  [Parameter(ParameterSetName='PVSWindowsFeatureReq')]
  [switch]$PVSWindowsFeatureReq,
  [Parameter(ParameterSetName='DisableTCPoffload')]
  [switch]$DisableTCPoffload,
  [Parameter(ParameterSetName='Afconfig')]
  [switch]$Afconfig,
  [Parameter(ParameterSetName='InstallPVSSnapin')]
  [switch]$InstallPVSSnapin,
  [Parameter(ParameterSetName='RemoveCFsDep2')]
  [switch]$NICConfig,
  [Parameter(ParameterSetName='NICConfig')]
  [switch]$DFSrConfig,
  [Parameter(ParameterSetName='DFSrConfig')]
  [switch]$PVSMember,
  [Parameter(ParameterSetName='PVSMember')]
  [switch]$AnswerCleanInstall,
  [Parameter(ParameterSetName='AnswerCleanInstall')]
  [switch]$AnswerUpgrade,
  [Parameter(ParameterSetName='AnswerUpgrade')]
  [switch]$RemoveCFsDep2,
  [string]$vDiskStore,
  [string]$ConfigFile,
  [string]$Log,
  [string]$DeployTemp,
  [string]$SNB_PSModule,
  [string]$SvcAccount,
  [string]$SvcPassword
)

<#--------------------------------------------
            Set variables
--------------------------------------------#>
# for importing XML file
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
[XML]$xmldocument = Get-Content -Path $ConfigFile
$DomainLocal = $xmldocument.Domains.Domain | Where-Object {$_.name -eq "$domain"}
$ADDomain = (Get-ADDomain).NetBIOSName

# PVS
$VARs = $DomainLocal.PVS 
$version = $VARs.version
$NetworkService = "NT AUTHORITY\NETWORK SERVICE"
$PVSConsoleDir = "C:\Program Files\Citrix\Provisioning Services Console"
$hostname = hostname
$PVSSettings = $VARs.Settings.Setting
$PVSServers = $VARs.Farms.Farm.Sites.Site.PVSServers.PVSServer
$PrimaryPVSServer = $PVSServers.name | Select-Object -First 1
$Beheerserver = (Get-ADComputer -filter "name -like '*QAN*B*'").name | Select-Object -First 1
$PVSNetworkBindings = $VARs.NetworkBindings.NetworkBinding
$Farms = $VARs.Farms.farm
$DfsrStagingPathQuota = $Vars.DFSrConfig.DfsrStagingPathQuota
$DfsrFileNameExclude = $Vars.DFSrConfig.FileNameExclu
$DfsrDirectoryExclude = $Vars.DFSrConfig.DirectoryExclu

# Logging, Always as last in the Variables
$WinDir = Get-ChildItem Env:Windir
$WinDir = $WinDir.Value
$LogFilePath = "$WinDir\Logs\CTXDeployment\"
$Global:LogName = "PVS"+$version+"Config.log"
$LogFile = "$LogFilePath\$LogName"

<#-------------------------------------------
        Load SNB Function Module
-------------------------------------------#>
Unblock-File -Path $SNB_PSModule -Confirm:$False
$global:LogName = $Log
Import-Module $SNB_PSModule

# -------------------------------------------------------------------------------------------
# Prerequirements PVS
# -------------------------------------------------------------------------------------------
#region createvDiskStore
If ($CreatevDiskStore) {
    DoLog ("Create vDiskStore Directory ------ " + (Get-Date).ToString() + "") 
    if (!(Test-Path $vDiskStore)) 
        {New-Item -ItemType Directory $vDiskStore}

    # set the rights on the vDiskStore
    DoLog ("Set the NTFSrights on the vDiskStore ------ " + (Get-Date).ToString() + "") 
    $acl = Get-Acl $vDiskStore
    $rule = new-object System.Security.AccessControl.FileSystemAccessRule($NetworkService, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    set-acl $vDiskStore $acl
    DoLog ("the NTFSrights are set on the vDiskStore ------ " + (Get-Date).ToString() + "") 
}
#endregion createvDiskStore

#region DisableTCPoffload
If ($DisableTCPoffload) {
    If ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" -Name "DisableTaskOffload" -ErrorAction SilentlyContinue) -eq $null) {
        Dolog (" Creating DisableTaskOffload dword. ------ " + (Get-Date).ToString() + "")  
            New-ItemProperty -Path “HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters” -Name “DisableTaskOffload” -PropertyType DWord -Value “1”
        Dolog (" DisableTaskOffload dword created. ------ " + (Get-Date).ToString() + "") 
        }

        ElseIf ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" -Name "DisableTaskOffload").DisableTaskOffload -ine "1") {
            Dolog (" Creating DisableTaskOffload dword. ------ " + (Get-Date).ToString() + "")  
                Set-ItemProperty -Path “HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters” -Name “DisableTaskOffload” -Value 1
            Dolog (" DisableTaskOffload dword created. ------ " + (Get-Date).ToString() + "") 
        }
        Else {
            DoLogWarning (" DisableTaskOffload dword already found, doing nothing. ------ " + (Get-Date).ToString() + "")
        }

    If ((!((Get-NetAdapterAdvancedProperty -Name PVS-NIC -DisplayName "Large Send Offload V2 (IPv4)").DisplayValue -eq "Disabled"))) {
        Dolog (" Disabeling the TCPoffload on the PVS-NIC ------ " + (Get-Date).ToString() + "") 
            Set-NetAdapterAdvancedProperty -Name PVS-NIC -DisplayName "Large Send Offload V2 (IPv4)" -DisplayValue "Disabled" -NoRestart
        Dolog (" TCPoffload is disabled on the PVS-NIC ------ " + (Get-Date).ToString() + "") 
        }
    Else {
        DoLogWarning (" TCPoffload is already disabled on the PVS-NIC ------ " + (Get-Date).ToString() + "") 
        }

    If ((!((Get-NetAdapterAdvancedProperty -Name PVS-NIC -DisplayName "Large Send Offload V2 (IPv6)").DisplayValue -eq "Disabled"))) {
        Dolog (" Disabeling the TCPoffload on the PVS-NIC ------ " + (Get-Date).ToString() + "") 
            Set-NetAdapterAdvancedProperty -Name PVS-NIC -DisplayName "Large Send Offload V2 (IPv6)" -DisplayValue "Disabled" -NoRestart
        Dolog (" TCPoffload is disabled on the PVS-NIC ------ " + (Get-Date).ToString() + "") 
        }
    Else {
        DoLogWarning (" TCPoffload is already disabled on the PVS-NIC ------ " + (Get-Date).ToString() + "") 
        }
}
#endregion DisableTCPoffload

#region InstallPVSSnapin
If ($InstallPVSSnapin) {
    Dolog (" Start installing PVS-PSSnapin " + (Get-Date).ToString() + "")
        Invoke-Command -ScriptBlock {C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe "C:\Program Files\Citrix\Provisioning Services Console\Citrix.PVS.SnapIn.dll"}
        Invoke-Command -ScriptBlock {C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe "C:\Program Files\Citrix\Provisioning Services Console\Citrix.PVS.SnapIn.dll"}
    Dolog (" End installing PVS-PSSnapin " + (Get-Date).ToString() + "")
}
#endregion InstallPVSSnapin

#region Afconfig
If ($Afconfig) {
Dolog (" Start the configuration of PVSServer " + (Get-Date).ToString() + "")
    Dolog (" Import PVS Powershell Module " + (Get-Date).ToString() + "")
        Import-Module "$PVSConsoleDir\Citrix.PVS.SnapIn.dll"

    Dolog (" Create connection to the local PVSServer " + (Get-Date).ToString() + "")
        Set-PvsConnection -Server $hostname -Port 54321

    #region SetPVSSettings
    Foreach ($PVSSetting in $PVSSettings) {
        $SettingName = $PVSSetting.Name
        $SettingValue = $PVSSetting.Value
        If((Get-PvsServer -ServerName $Hostname).$SettingName -eq "$SettingValue") {
            DoLogWarning (" $SettingName setting already set on $SettingValue ------ " + (Get-Date).ToString() + "")
        }
        Else {
            If ($SettingName -eq "EventLoggingEnabled") {
            DoLog (" $SettingName setting to $SettingValue ------ " + (Get-Date).ToString() + "")
                iex "Set-PVSServer -ServerName $Hostname "-"+$SettingName"
            DoLog (" $SettingName Set to $SettingValue ------ " + (Get-Date).ToString() + "")
            }
            Else {
            DoLog (" $SettingName setting to $SettingValue ------ " + (Get-Date).ToString() + "")
                iex "Set-PvsServer -ServerName $Hostname -$SettingName $SettingValue"
            DoLog (" $SettingName Set to $SettingValue ------ " + (Get-Date).ToString() + "")
            }
        }
    }
    #endregion SetPVSSettings

    #region BNPXEAutoDelayStart
    $regBNPXE = Get-Item HKLM:\System\CurrentControlSet\Services\BNPXE
    If ($regBNPXE.GetValue("DelayedAutostart") -eq $null) {
        Dolog (" Creating DelayAutostart dword. ------ " + (Get-Date).ToString() + "")  
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\BNPXE" -Name "DelayedAutostart" -Value 1 -Type DWORD
        Dolog (" DelayAutostart dword created. ------ " + (Get-Date).ToString() + "") 
    }
    ElseIf ((Get-ItemProperty HKLM:\System\CurrentControlSet\Services\BNPXE).DelayedAutostart -eq "0") {
        Dolog (" Creating DelayAutostart dword. ------ " + (Get-Date).ToString() + "")  
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\BNPXE" -Name "DelayedAutostart" -Value 1 -Type DWORD
        Dolog (" DelayAutostart dword created. ------ " + (Get-Date).ToString() + "") 
    }
    Else {
        DoLogWarning (" DelayAutostart dword already found, doing nothing. ------ " + (Get-Date).ToString() + "")
    }
    #endregion BNPXEAutoDelayStart

    #region SkipRIMSForPrivate
    $regStreamProcess = Get-Item HKLM:\SOFTWARE\Citrix\ProvisioningServices\StreamProcess
    If ($regStreamProcess.GetValue("SkipRIMSForPrivate") -eq $null) {
        Dolog (" Setting SkipRIMSForPrivate dword. ------ " + (Get-Date).ToString() + "")  
            New-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\ProvisioningServices\StreamProcess" -Name "SkipRIMSForPrivate" -Value 1 -Type DWORD
        Dolog (" SkipRIMSForPrivate dword is set. ------ " + (Get-Date).ToString() + "") 
    }
    ElseIf ((Get-ItemProperty HKLM:\SOFTWARE\Citrix\ProvisioningServices\StreamProcess).SkipRIMSForPrivate -eq "0") {
        Dolog (" Setting SkipRIMSForPrivate dword. ------ " + (Get-Date).ToString() + "")  
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\ProvisioningServices\StreamProcess" -Name "SkipRIMSForPrivate" -Value 1 -Type DWORD
        Dolog (" SkipRIMSForPrivate dword is set. ------ " + (Get-Date).ToString() + "") 
    }
    Else {
        DoLogWarning (" SkipRIMSForPrivate dword already found, doing nothing. ------ " + (Get-Date).ToString() + "")
    }
    #endregion SkipRIMSForPrivate

    Dolog (" Restarting PVSStream Services ------ " + (Get-Date).ToString() + "")
        Restart-Service -Name StreamService -Force -Verbose
    Dolog (" Finish restarting the PVSStream Services ------ " + (Get-Date).ToString() + "")
}
#endregion Afconfig

#region RemoveCFsDep2
If ($RemoveCFsDep2) {
    If (Test-Path -Path HKLM:\SYSTEM\ControlSetSet\Services\CFsDep2) {
        Dolog (" Remove Old CFsDep2 ControlSetSet Keys ------ " + (Get-Date).ToString() + "")  
            Remove-Item -Path "HKLM:\SYSTEM\ControlSetSet\Services\CFsDep2" -Force -Recurse -Confirm:$False
        Dolog (" Removed Old CFsDep2 ControlSetSet Keys ------ " + (Get-Date).ToString() + "") 
    }
    Else {
        DoLogWarning (" HKLM:\SYSTEM\ControlSetSet\Services\CFsDep2 already removed, doing nothing. ------ " + (Get-Date).ToString() + "")
    }

    If (Test-Path -Path HKLM:\SYSTEM\ControlSet001\Services\CFsDep2) {
        Dolog (" Remove Old CFsDep2 ControlSet001 Keys ------ " + (Get-Date).ToString() + "")  
            Remove-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\CFsDep2" -Force -Recurse -Confirm:$False
        Dolog (" Removed Old CFsDep2 ControlSet001 Keys ------ " + (Get-Date).ToString() + "") 
    }
    Else {
        DoLogWarning (" HKLM:\SYSTEM\ControlSet001\Services\CFsDep2 already removed, doing nothing. ------ " + (Get-Date).ToString() + "")
    }

    If (Test-Path -Path HKLM:\SYSTEM\ControlSet002\Services\CFsDep2) {
        Dolog (" Remove Old CFsDep2 ControlSet002 Keys ------ " + (Get-Date).ToString() + "")  
            Remove-Item -Path "HKLM:\SYSTEM\ControlSet002\Services\CFsDep2" -Force -Recurse -Confirm:$False
        Dolog (" Removed Old CFsDep2 ControlSet002 Keys ------ " + (Get-Date).ToString() + "") 
    }
    Else {
        DoLogWarning (" HKLM:\SYSTEM\ControlSet002\Services\CFsDep2 already removed, doing nothing. ------ " + (Get-Date).ToString() + "")
    }

    If (Test-Path -Path C:\Windows\System32\drivers\CFsDep2.sys) {
        Dolog (" Remove Old CFsDep2.sys File ------ " + (Get-Date).ToString() + "")  
            Remove-Item -Path "C:\Windows\System32\drivers\CFsDep2.sys" -Force -Recurse -Confirm:$False
        Dolog (" Removed Old Old CFsDep2.sys File ------ " + (Get-Date).ToString() + "") 
    }
    Else {
        DoLogWarning (" CFsDep2.sys already removed, doing nothing. ------ " + (Get-Date).ToString() + "")
    }        
}
#endregion RemoveCFsDep2

#region NICConfig
If ($NICConfig) {
    Dolog (" Start NICs configuration  ------ " + (Get-Date).ToString() + "") 
    Foreach ($PVSServer in $PVSServers | Where-Object {$_.Name -eq ("$hostname")}) {
        $PVSServerNICs = $PVSServer.NIC
        Foreach ($PVSServerNIC in $PVSServerNICs) {
            $IfIndex = $PVSServerNIC.ifIndex
            $NICLabel = $PVSServerNIC.name
            $IPAddress = $PVSServerNIC.IP
            $PrefixLength = $PVSServerNIC.PrefixLength
            $CurrentLabel = (Get-NetAdapter -InterfaceIndex $IfIndex).Name
            $CurrentIP = (Get-NetIPAddress -InterfaceIndex $IfIndex -AddressFamily IPv4).IPAddress
            $CurrentPrefixLength = (Get-NetIPAddress -InterfaceIndex $IfIndex -AddressFamily IPv4).PrefixLength
            $Binding = $PVSServerNIC.NetworkBinding
            
                        
            #region Set IP-Address and Label
            Dolog (" Start Setting IP-Address to $NICLabel  ------ " + (Get-Date).ToString() + "")
            If (!($CurrentIP -eq $IPAddress -and $CurrentPrefixLength -eq $PrefixLength)) {
                DoLog ( " IP-Address and PrefixLength of $NICLabel is not correctly set, setting correct IP-Address ------ " + (Get-Date).ToString() + "")
                    #Set-NetIPAddress -InterfaceIndex $IfIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -AddressFamily IPv4
                    Remove-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -Confirm:$false
                    New-NetIPAddress -InterfaceIndex $IfIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -AddressFamily IPv4
                DoLog ( " IP-Address and PrefixLength of $NICLabel is now correctly set. ------ " + (Get-Date).ToString() + "")
                }
            Else {
                DoLogWarning (" IP-Address for $NICLabel already set ------ " + (Get-Date).ToString() + "")
                }
            Dolog (" End Setting IP-Address to $NICLabel  ------ " + (Get-Date).ToString() + "")
            #endregion Set IP-Address
            
            #region Set Label
            Dolog (" Start Setting Label to $NICLabel  ------ " + (Get-Date).ToString() + "")
            If (!($CurrentLabel -eq $NICLabel)) {
                DoLog ( " Label of $NICLabel is not correctly set, setting correct label ------ " + (Get-Date).ToString() + "")
                    Rename-NetAdapter -Name $CurrentLabel -NewName $NICLabel
                DoLog ( " Label of $NICLabel is now correctly set. ------ " + (Get-Date).ToString() + "")
                }
            Else {
                DoLogWarning (" Label for $NICLabel already set ------ " + (Get-Date).ToString() + "")
                }
            Dolog (" End Setting Label to $NICLabel  ------ " + (Get-Date).ToString() + "")
            #endregion Set Label

            #region Disable NetworkBindings
            If ($Binding -eq "True") {
            Dolog (" Start Setting NetworkingBindings $NICLabel  ------ " + (Get-Date).ToString() + "")
            Foreach ($PVSNetworkBinding in $PVSNetworkBindings) {
                $NetworkBindingName = $PVSNetworkBinding.Name
                $NetworkBindingValue = $PVSNetworkBinding.Value
                If ((Get-NetAdapter -InterfaceIndex $IfIndex | Get-NetAdapterBinding -DisplayName $NetworkBindingName).Enabled -match $NetworkBindingValue) {
                    DoLogWarning (" $NetworkBindingName setting already set to $NetworkBindingValue ------ " + (Get-Date).ToString() + "")
                }
                Else {
                    DoLog (" $NetworkBindingName setting to $NetworkBindingValue ------ " + (Get-Date).ToString() + "")
                        Get-NetAdapter -InterfaceIndex $IfIndex | Disable-NetAdapterBinding -DisplayName $NetworkBindingName
                    DoLog (" $NetworkBindingName Set to $NetworkBindingValue ------ " + (Get-Date).ToString() + "")
                    }
                }
            }
            Else {
                DoLogWarning (" $NICLabel NetworkBinding is set to False, nothing needed to change ------ " + (Get-Date).ToString() + "")
                }
            Dolog (" End Setting NetworkingBindings $NICLabel  ------ " + (Get-Date).ToString() + "")
            #endregion Disable NetworkBindings

            #region Disable DNS and WINS Registration
            If ($Binding -eq "True") {
            Dolog (" Start Setting DNS Registeration and UseSuffixWhenRegistering $NICLabel  ------ " + (Get-Date).ToString() + "")
                #region Disable DNS Registeration
                If ((Get-DnsClient -InterfaceIndex $IfIndex).RegisterThisConnectionsAddress -eq $True) {
                    DoLog (" Disable DNS Registeration for $NICLabel ------ " + (Get-Date).ToString() + "")
                        Set-DnsClient -InterfaceIndex $IfIndex -RegisterThisConnectionsAddress $False
                    DoLog (" Disabled DNS Registeration for $NICLabel ------ " + (Get-Date).ToString() + "")                    
                }
                Else {

                    DoLogWarning (" DNS Registeration already Disabled for $NICLabel ------ " + (Get-Date).ToString() + "")
                    }
                #endregion Disable DNS Registeration

                #region Disable SuffixWhenRegistering
                If ((Get-DnsClient -InterfaceIndex $IfIndex).UseSuffixWhenRegistering -eq $True) {
                    DoLog (" Disable DNS UseSuffixWhenRegistering for $NICLabel ------ " + (Get-Date).ToString() + "")
                        Set-DnsClient -InterfaceIndex $IfIndex -UseSuffixWhenRegistering $False
                    DoLog (" Disabled DNS UseSuffixWhenRegistering for $NICLabel ------ " + (Get-Date).ToString() + "")                    
                }
                Else {
                    DoLogWarning (" DNS UseSuffixWhenRegistering already disabled for $NICLabel ------ " + (Get-Date).ToString() + "")
                    }
                #endregion Disable SuffixWhenRegistering

                #region Disable NetBIOS Lookup
                $WMINIC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress -eq "$IPAddress"}
                If (($WMINIC).TcpipNetbiosOptions -ne "2") {
                    DoLog (" Disable WINS lookup for $NICLabel ------ " + (Get-Date).ToString() + "")
                        $WMINIC.settcpipnetbios(2)
                    DoLog (" Disabled WINS Lookup for $NICLabel ------ " + (Get-Date).ToString() + "")                    
                }
                Else {
                    DoLogWarning (" WINS Lookup was already disabled for $NICLabel ------ " + (Get-Date).ToString() + "")
                    }
                #endregion Disable NetBIOS Lookup

                #region Disable LMHosts Lookup
                $WMINIC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress -eq "$IPAddress"}
                $WMINICList = Get-WmiObject -List -Class Win32_NetworkAdapterConfiguration
                If (($WMINIC).WINSEnableLMHostsLookup -eq $True) {
                    DoLog (" Disable LMHosts Lookup for $NICLabel ------ " + (Get-Date).ToString() + "")
                        $WMINICList.enablewins($false,$false)
                    DoLog (" Disabled LMHosts Lookup for $NICLabel ------ " + (Get-Date).ToString() + "")                    
                }
                Else {
                    DoLogWarning (" LMHosts Lookup was already disabled for $NICLabel ------ " + (Get-Date).ToString() + "")
                    }
                #endregion Disable LMHosts Lookup
            }
            Else {
                DoLogWarning (" $NICLabel NetworkBinding is set to False, nothing needed to change ------ " + (Get-Date).ToString() + "")
                }
            Dolog (" End Setting DNS Registeration and UseSuffixWhenRegistering $NICLabel  ------ " + (Get-Date).ToString() + "")
            #endregion Disable DNS and WINS Registration

            #region Set NIC order
            Dolog (" Start Setting NIC order, PVS-NIC First than VDI-NIC ------ " + (Get-Date).ToString() + "")
            If ($NICLabel -eq "PVS-NIC") {
                $VDIIntMetric = (Get-NetIPInterface -AddressFamily IPv4 | Where-object {$_.InterfaceAlias -NE "$NICLabel" -and $_.InterfaceAlias -notmatch "Loopback"}).InterfaceMetric
                $PVSIntMetric = (Get-NetIPInterface -AddressFamily IPv4 -InterfaceAlias $NICLabel).InterfaceMetric
                $NewPVSIntMetric = ($VDIIntMetric)-1

                If ($PVSIntMetric -eq $VDIIntMetric -or $PVSIntMetric -gt $VDIIntMetric) {
                    Dolog (" Starting setting NIC order, PVS-NIC First than VDI-NIC ------ " + (Get-Date).ToString() + "")
                        Set-NetIPInterface -InterfaceAlias PVS-NIC -InterfaceMetric $NewPVSIntMetric
                    Dolog (" PVS-NIC is now First  in the NIC order ------ " + (Get-Date).ToString() + "")
                
                    }
                Else {
                    DologWarning (" $NICLabel is already first in the NIC order ------ " + (Get-Date).ToString() + "")
                }
            }
            Else {
                DologWarning (" $NICLabel is not a PVS Network, no need to change the NIC order ------ " + (Get-Date).ToString() + "")
            }
            Dolog (" End Setting NIC order, PVS-NIC First than VDI-NIC ------ " + (Get-Date).ToString() + "")
            #endregion Set NIC order
        }           
    }
    Dolog (" End NICs configuration  ------ " + (Get-Date).ToString() + "") 
}
#endregion NICConfig

#region DFSrConfig
If ($DFSrConfig) {
    Dolog (" Start DFSr configuration  ------ " + (Get-Date).ToString() + "")
    Foreach ($farm in $Farms) {
        $PVSServer = ($Farm.sites.site.PVSServers.PVSServer | Where-Object {$_.Name -eq $hostname}).name
        $farmname = $farm.name
        $GroupName = "DFSr-Group-$Farmname"

        #region DFSr ReplicationFolder
        Dolog (" Start Add New DFSr ReplictionFolder ------ " + (Get-Date).ToString() + "")           
        If ((Get-DfsReplicatedFolder -GroupName $GroupName).groupname -eq $GroupName) {
            DologWarning ("  DFSr ReplictionFolder already exist ------ " + (Get-Date).ToString() + "")
        
            #DFSr File and directory excludes
            Dolog (" Set DFSr ReplictionFolder FileNameExclude ------ " + (Get-Date).ToString() + "")
            If ([System.String]::Join(", ", (Get-DfsReplicatedFolder -GroupName $GroupName).FileNameToExclude) -eq $DfsrFileNameExclude) {
            DologWarning (" DFSr ReplictionFolder FileNameExclude already set ------ " + (Get-Date).ToString() + "")
            }
            Else { Set-DfsReplicatedFolder -GroupName $GroupName -FileNameToExclude $DfsrFileNameExclude
            }
                Dolog (" Set DFSr ReplictionFolder DirectoryNameExclude ------ " + (Get-Date).ToString() + "")
                If ([System.String]::Join(", ", (Get-DfsReplicatedFolder -GroupName $GroupName).DirectoryNameToExclude) -eq $DfsrDirectoryExclude)
                {DologWarning (" DFSr ReplictionFolder DirectoryNameExclude already set ------ " + (Get-Date).ToString() + "")
                }
                Else {
                Set-DfsReplicatedFolder -GroupName $GroupName -DirectoryNameToExclude $DfsrDirectoryExclude
                }
        }
        Else {Dolog ("  Add New DFSr ReplictionFolder ------ " + (Get-Date).ToString() + "")
        New-DfsReplicatedFolder -GroupName $GroupName -FolderName $VdiskStore -FileNameToExclude $DfsrFileNameExclude -DirectoryNameToExclude $DfsrDirectoryExclude
        }
        Dolog ("  End Setting DFSr ReplictionFolder ------ " + (Get-Date).ToString() + "")
        #endregion DFSr ReplicationFolder

        #region DFSr Member
        Dolog ("  Start Add $hostname as DFSr Member------ " + (Get-Date).ToString() + "")
        If ((Get-DfsrMember -GroupName $GroupName -ComputerName $hostname).ComputerName -eq $hostname) {
            DologWarning (" $hostname is already Member ------ " + (Get-Date).ToString() + "")
        }
        else {
            Dolog ("  Add DFSr Member $hostname ------ " + (Get-Date).ToString() + "")
            Add-DfsrMember -GroupName $GroupName -ComputerName $hostname
        }
        Dolog ("  End Add DFSr Member ------ " + (Get-Date).ToString() + "")
        #endregion DFSr Member

        #region DFSr Member Contentpath
        Dolog ("  Start Setting DFSr Member Contentpath on $hostname ------ " + (Get-Date).ToString() + "")
        If ((Get-DfsrMembership -GroupName $GroupName -ComputerName $hostname).ContentPath -eq $vDiskStore) {
            DologWarning ("  $hostname Member Contentpath already set ------ " + (Get-Date).ToString() + "")
        }
        else {
            Dolog ("  Set $Hostname Member Contentpath ------ " + (Get-Date).ToString() + "")
            Set-DfsrMembership -GroupName $GroupName -FolderName $VdiskStore -ComputerName $hostname -ContentPath $vDiskStore -Force
        }
        Dolog ("  End Setting DFSr Member Contentpath ------ " + (Get-Date).ToString() + "")
        #endregion DFSr Member Contentpath

        #region DFSr Member StagingPathQuotaInMB
        Dolog ("  Start Setting DFSr Member $hostname StagingPathQuotaInMB ------ " + (Get-Date).ToString() + "")
        If ((Get-DfsrMembership -GroupName $GroupName -ComputerName $hostname).StagingPathQuotaInMB -eq $DfsrStagingPathQuota) {
            DologWarning ("  $hostname Member StagingPathQuotaInMB already set ------ " + (Get-Date).ToString() + "")
        }
        else {
            Dolog ("  Set $Hostname Member StagingPathQuotaInMB ------ " + (Get-Date).ToString() + "")
            Set-DfsrMembership -GroupName $GroupName -FolderName $VdiskStore -ComputerName $hostname -StagingPathQuotaInMB $DfsrStagingPathQuota -Force
            Dolog ("  End Setting DFSr Member StagingPathQuotaInMB ------ " + (Get-Date).ToString() + "")
        }
        #endregion DFSr Member StagingPathQuotaInMB

        #region DFSr Primary Member
        Dolog ("  Start Setting DFSr Primary Member ------ " + (Get-Date).ToString() + "")
        If ((Get-DfsrMembership -GroupName $GroupName -ComputerName $PrimaryPVSServer).PrimaryMember -eq $True) {
            DologWarning ("  $PrimaryPVSServer already Primary Member ------ " + (Get-Date).ToString() + "")
        }
        else {
            Dolog ("  Set $PrimaryPVSServer as primary Member ------ " + (Get-Date).ToString() + "")
            Set-DfsrMembership -GroupName $GroupName -FolderName $VdiskStore -PrimaryMember $true -ComputerName $PrimaryPVSServer -ContentPath $vDiskStore -Force
        }
        Dolog ("  End Setting DFSr Primary Member ------ " + (Get-Date).ToString() + "")
        #endregion DFSr Primary Member

        #region DFSr Connnection
        Dolog ("  Start Add DFSr connection ------ " + (Get-Date).ToString() + "")
        If ($PrimaryPVSServer -eq $hostname) {
            DologWarning (" DFSr Connecting could not be added, because the source $PrimaryPVSServer and Destination $hostname were the same ------ " + (Get-Date).ToString() + "")
        }
        elseIf ((Get-DfsrConnection -GroupName $GroupName -DestinationComputerName $hostname).DestinationComputerName -eq $hostname) {
             DologWarning (" $hostname connection already exist ------ " + (Get-Date).ToString() + "")
        }
        else {
             Dolog (" Add $hostname to DFSr connection ------ " + (Get-Date).ToString() + "")
             Add-DfsrConnection -GroupName $GroupName -SourceComputerName $PrimaryPVSServer -DestinationComputerName $hostname
             Dolog ("  End Add DFSr connection ------ " + (Get-Date).ToString() + "")
        }
    
             Dolog (" End DFSr configuration  ------ " + (Get-Date).ToString() + "")
        }
        #endregion DFSr Connnection
}
#endregion DFSrConfig 

 #region PVS Group Member
If ($PVSMember) {
 Dolog (" Start PVS Group Member configuration  ------ " + (Get-Date).ToString() + "")
    Foreach ($farm in $Farms) {
        If($PVSServer = ($Farm.sites.site.PVSServers.PVSServer | Where-Object {$_.Name -eq $hostname}).name) 
        {
        $farmname = $farm.name
        $GroupName = "PVS-$Farmname"
            Dolog ("  Start add PVS Group Member------ " + (Get-Date).ToString() + "")
            If ((Get-ADGroupMember -Identity $GroupName | Where-Object {$_.Name -eq $hostname}).name -eq $hostname) {
            Dologwarning ("  $hostname already member of $GroupName ------ " + (Get-Date).ToString() + "")
            }
            Else {
            Dolog ("  Add $hostname to $GroupName group ------ " + (Get-Date).ToString() + "")
            $ScriptBlock = {
            $secureString = convertto-securestring $Using:SvcPassword -asplaintext -force
            Connect-QADService -ConnectionAccount $Using:SvcAccount -ConnectionPassword $secureString -proxy
            $DN = (Get-QADGroup $Using:GroupName).DN
            Add-QADGroupMember -Identity $DN -Member $Using:hostname
            }
            Invoke-Command -ComputerName $beheerserver -ScriptBlock $ScriptBlock
            Dolog (" End Add $hostname to $GroupName group ------ " + (Get-Date).ToString() + "")
            }
        }
        Else {Dolog (" End PVS Group Member configuration  ------ " + (Get-Date).ToString() + "")
        }
    }
Dolog (" End PVS Group Member configuration ------ " + (Get-Date).ToString() + "")
}
#endregion PVS Group Member
