<#
   	**********************************************************************************************************
	Powershell script to configure Virtual Apps and Desktops

	Operating system			: Windows Server 2019 Core/GUI 
	Author(s)				    : S.N. Baars
	Version					    : 0.0.3
	Date					    : 03-09-2022
	Tags					    : Citrix Virtual Apps and Desktop

	ScriptEngine				: Powershell

	Version  Date        Author  Changelog
	----------------------------------------------------------------------------------------------------------
	0.0.1    13-01-2015  SNB      First version
	0.0.2	 16-02-2016  SNB      Added InstallXD76PowerShell, for installing all the XenDesktop PowerShell SnapIn's
    0.0.3    17-02-2016  SNB      De parameter ConfigXD71x toegevoegd waarmee de XDSite mee af wordt geconfigureerd.
    0.0.4    06-06-2017  Avdk     Parameters aangepast
	**********************************************************************************************************
#>

<#--------------------------------------------
            Set parameters
--------------------------------------------#>
Param(
  [String]$ConfigFile,
  [String]$DeployTemp,
  [String]$SNB_PSModule,
  [String]$log,
  [switch]$Config,
  [switch]$InstallPowerShell,
  [switch]$SSLXML,
  [switch]$HyperDLLPatch
  )

#region Variables

$DeployTempUNC = $DeployTemp -replace ":","$"

$Domain = (Get-WmiObject Win32_ComputerSystem).Domain
[xml]$xmlDocument = Get-Content -Path $ConfigFile
$DomainLocal = $xmldocument.Domains.Domain | Where-Object {$_.name -eq "$domain"}
$VARs = $DomainLocal.XDConfig
$ADDomain = (Get-ADDomain).DNSRoot

# Xendesktop Settings
$XDVersion = $VARs.XDVersion
$SiteAdmins = $VARs.SiteAdmins.SiteAdmin
$XDServer = Hostname
$ASPnetConfig = "\\$XDServer\$DeployTempUNC\Windows\System32\mmc.exe.config"
$ASPnetConfig64 = "\\$XDServer\$DeployTempUNC\Windows\SysWOW64\mmc.exe.config"

$XDCert = $XDServer + "_" + $ADDomain.Replace('.','_') + ".pfx" 
$CertStore = "Cert:\LocalMachine\My"
$CertUrl = $XDServer + "." + $domain
$CertEncryptPassword = $Vars.CertencryptPassword

 <#-------------------------------------------
        Load SNB Function Module
-------------------------------------------#>
Unblock-File -Path $SNB_PSModule -Confirm:$False
$global:LogName = $Log
Import-Module $SNB_PSModule -Force
#endregion LoadModules

#region SSL-XML
if ($SSLXML) {
    DoLog ("--- Enable SSL XML --- " + (Get-Date).ToString() + " ---")
    DoLog ("--- Get AppID fpr Citrix Broker Service --- " + (Get-Date).ToString() + " ---")
        If (!(Get-PSDrive -name HKCR -ErrorAction SilentlyContinue)) {
            DoLog ("--- Creating PSDrive for HKCR  --- " + (Get-Date).ToString() + " ---")
                New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
            DoLog ("--- PSDrive for HKCR created --- " + (Get-Date).ToString() + " ---")
        }
        Else {
            DoLogWarning ("--- PSDrive HKCR exists, doing nothing --- " + (Get-Date).ToString() + " ---")
        }
    DoLog ("--- Putting GUID from Citrix Broker Service in variable --- " + (Get-Date).ToString() + " ---")
        $ProductKey = (get-childitem -path HKCR:\Installer\Products\ -recurse | Get-ItemProperty | Where-Object {$_.ProductName -like "Citrix Broker Service"}).PSChildName
        $GUID8 = $ProductKey.Insert(8,"-")
        $GUID13 = $GUID8.Insert(13,"-")
        $GUID18 = $GUID13.Insert(18,"-")
        $GUID = $GUID18.Insert(23,"-")
    DoLog ("--- GUID from Citrix Broker Service in variable filt --- " + (Get-Date).ToString() + " ---")
        $SSLBind = netsh http show sslcert | findstr "{$GUID}"
    If (!($SSLBind -match $GUID)) {
        If (Test-Path -Path $DeployTemp\$XDCert) {
        DoLog ("--- Import Certificate --- " + (Get-Date).ToString() + " ---")
            $CertDecryptPassword = Decrypt -CertencryptPassword $CertEncryptPassword
            $SecureString = ConvertTo-SecureString $CertDeCryptPassword -AsPlainText -Force
            ImportPfxCert -CertFile $DeployTemp\$XDCert -CertStore $CertStore -CertSubject $CertUrl -CertPassword $SecureString
        DoLog ("--- Import Certificate --- " + (Get-Date).ToString() + " ---")
            DoLog ("--- Putting Thumb from Certificate in variable --- " + (Get-Date).ToString() + " ---")
                $cert = Get-ChildItem -Path $CertStore -DnsName $CertUrl
                $CertThumb = $cert.Thumbprint.ToString()
            DoLog ("--- Thumb from Certificate in variable filt --- " + (Get-Date).ToString() + " ---")
   
            DoLog ("--- Bind Certificate to the Citrix BrokerService --- " + (Get-Date).ToString() + " ---")
                Invoke-Command -ScriptBlock {netsh http add sslcert ipport=0.0.0.0:443 certhash=$CertThumb appid="{$GUID}"}
            DoLog ("--- Binding the Certificate to the Citrix BrokerService is done  --- " + (Get-Date).ToString() + " ---")
        }
        Else {
            DoLogError ("--- Certificate file not found, skipping function.  --- " + (Get-Date).ToString() + " ---")
            }
        }
    Else {
        DoLogWarning ("--- Certificate already bind to the Citrix Broker Service, doing nothing.  --- " + (Get-Date).ToString() + " ---")
    }
}
#endregion SSL-XML


