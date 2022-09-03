<#
	**********************************************************************************************************
	Operating system			: Windows Server 2019 Core/GUI
	Commandline parameters		: None
	Requirements				: Citrix Director 7.x
								  
	Author(s)					: S.N. Baars
                                : 
	Version						: 0.0.1
	Date						: 07-09-2015
	Tags						: Director, VDI, XenDesktop

	ScriptEngine				: Powershell

	Version  Date        Author    Changelog
	----------------------------------------------------------------------------------------------------------
	0.1    04-06-2014  RB        Initial
    0.2    7-8-2019    RB        UI.TaskManager.EnableApplications with false toegevoegd
 
	**********************************************************************************************************
#>

Param(
  [String]$ConfigFile,
  [String]$Deploytemp,
  [String]$SNB_PSModule,
  [String]$log,
  [switch]$Config,
  [switch]$Certificate
  )

#region Variables
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
[XML]$xmldocument = Get-Content -Path $ConfigFile
$DomainLocal = $xmldocument.Domains.Domain | Where-Object {$_.name -eq "$domain"}
$VARs = $DomainLocal.DirectorConfig
$ADDomain = (Get-ADDomain).NetBIOSName

$DeployTempUNC = $DeployTemp -replace ":","$" 

$ComputerName = $env:computername
$WebFolder = "\\$ComputerName\c$\inetpub\wwwroot"
$DefaultFile = "$WebFolder\default.htm"
$XenDesktop_DDCs = $Vars.XenDesktopDDCs
$DDVersion = $Vars.Directorversion
$DefaultWebsite = $Vars.DefaultWebsite
$ASPnetConfig = "\\$ComputerName\C$\Windows\Microsoft.NET\Framework\v4.0.30319\Aspnet.config"
$ASPnetConfig64 = "\\$ComputerName\\C$\Windows\Microsoft.NET\Framework64\v4.0.30319\Aspnet.config"
$DesktopDirectorUrl = $VARs.DesktopDirectorUrl
$version = $VARs.Directorversion

# Certificates
$Certs = $VARs.Certificaten.Certificaat

# Configure logging
$WinDir = Get-ChildItem Env:Windir
$WinDir = $WinDir.Value
$Global:LogName = "01_Director"+$DDVersion+"_config.log"
#endregion Variables

 <#-------------------------------------------
        Load SNB Function Module
-------------------------------------------#>
Unblock-File -Path $SNB_PSModule -Confirm:$False
$global:LogName = $Log
Import-Module $SNB_PSModule

#region Certificate
If ($Certificate) {
#Import and Bind certificate to IIS
    ForEach ($Cert in $Certs) {
        If ($Cert.BindIIS -eq "True") {
            $PassCertDeCrypt = Decrypt -CertencryptPassword $Cert.CertencryptPassword
            $SecureStringCert = ConvertTo-SecureString $PassCertDeCrypt -AsPlainText -Force
            $CertPath = $Cert.CertPath
            $CertStore = $Cert.CertStore
            $CertSubject = $Cert.CertSubject
            ImportPfxCert -CertFile $DeployTemp\$CertPath -CertStore $CertStore -CertSubject $CertSubject -CertPassword $SecureStringCert
            BindCertIIS -CertUrl $DesktopDirectorUrl -CertStore $CertStore
            }
        Else {
            DoLogWarning ("--- $Cert.BindIIS not found, doing nothing --- " + (Get-Date).ToString() + " ---")
        }
    }
}
#endregion Certificate



# Create OSOptimize Function
Function OSOptimize {
    DoLog ("--- Citrix Director 7.x OS Optimizer started --- " + (Get-Date).ToString() + " ---")
    # Edit the ASPnet.config file
    [xml]$c=Get-Content $ASPnetConfig
    $n=$c.configuration.runtime.generatePublisherEvidence
    if($n -eq $null){$n=$c.CreateElement('generatePublisherEvidence')
    $c.configuration.runtime.AppendChild($n)}
    $n.SetAttribute('enabled',[string]$false)
    $c.Save($ASPnetConfig)
    DoLog ("Added generatePublisherEvidence to Aspnet.config " + (Get-Date).ToString() + "")

    # Edit the ASPnet.config x64 file 
    [xml]$c64=Get-Content $ASPnetConfig64
    $n64=$c64.configuration.runtime.generatePublisherEvidence
    if($n64 -eq $null){$n64=$c64.CreateElement('generatePublisherEvidence')
    $c64.configuration.runtime.AppendChild($n64)}
    $n64.SetAttribute('enabled',[string]$false)
    $c64.Save($ASPnetConfig64)
    DoLog ("Added generatePublisherEvidence to Aspnet.config x64 " + (Get-Date).ToString() + "")

    # Disable Netbios over TCP/IP
    $adapters=(gwmi win32_networkadapterconfiguration )
    Foreach ($adapter in $adapters){
         Write-host $adapter
        $adapter.settcpipnetbios(2)}
    DoLog ("Disabled Netbios over TCP/IP")

    # Disable check publisher's certificate revocation (to speed up console start-up)
    Set-ItemProperty -path "REGISTRY::\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -name State -value 146944
    DoLog ("Disabled check publisher's certificate revocation " + (Get-Date).ToString() + "")

    # Create redirection default.htm (default webpage).
    If ($Defaultwebsite -eq "True") {
    Write-Output "<script type=""text/javascript"">" | Out-File -filepath "$DefaultFile" 
    Write-Output "<!--" | Out-File -filepath "$DefaultFile" -Append -NoClobber
    Write-Output "window.location=""/Director"";" | Out-File -filepath "$DefaultFile" -Append -NoClobber
    Write-Output "// -->" | Out-File -filepath "$DefaultFile" -Append -NoClobber
    Write-Output "</script>" | Out-File -filepath "$DefaultFile" -Append -NoClobber
    Write-Host -ForegroundColor Green "Created DefaultFile"
    }
    Else {DoLog ("No default webpage configured" + (Get-Date).ToString() + "")}
    DoLog ("--- Citrix Director 7.x OS Optimizer ended --- " + (Get-Date).ToString() + " ---")
}

# Create LoadpowershellSnapin WebAdministration
	Function LoadPowershellSnapins{
		if ( (Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue) -eq $null )
		{
        Import-Module WebAdministration
		}
}

<#--------------------------------------------------------------
            Afconfig Desktopdirector 7.x
---------------------------------------------------------------#>

If ($Config){
    DoLog ("--- Afconfig Desktopdirector 7.x Started --- " + (Get-Date).ToString() + " ---")
    
    # Deploy the OSOptimizer
    OSOptimize
    DoLog ("Configured OSOptimize " + (Get-Date).ToString() + "")
    
    #Backup orginal files.
    Copy-Item -Path "$WebFolder\Director\web.config" -Destination "$WebFolder\Director\web.config_old"
    DoLog ("Backup orginal files " + (Get-Date).ToString() + "")

    # Configure the XenDesktop and XenApp Controllers
    & $WebFolder\Director\tools\DirectorConfig.exe /site Director /ddc $XenDesktop_DDCs
    DoLog ("Configured the XenDesktop and XenApp Controllers " + (Get-Date).ToString() + "")

    # Configure Remote-Assistance for the DesktopDirector
    & $WebFolder\Director\tools\DirectorConfig.exe /enablera
    DoLog ("Configured Remote Assistance for the DesktopDirector " + (Get-Date).ToString() + "")

    # Turn off SSL Check for Director Site
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\Director" -filter "appSettings/add[@key='UI.EnableSslCheck']" -Name value -Value "false"
    DoLog ("Turned off SSL Check for Director Site " + (Get-Date).ToString() + "")

    # WebSite Session Timeout (60 minutes)
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\Director" -Filter "system.web/sessionState" -Name timeout -Value "01:00:00"
    DoLog ("Set the WebSite Session Timeout (60 minutes) " + (Get-Date).ToString() + "")

    # Pre-populate domain textbox and make it readonly (obv jouw search & replace acties)
    (Get-Content "C:\inetpub\wwwroot\Director\LogOn.aspx") |
        Foreach-Object {$_ -replace "<asp:TextBox ID=""Domain"" runat=""server"" CssClass=""text-box""", "<asp:TextBox ID=""Domain"" runat=""server"" Text=""$domain"" ReadOnly=""true"" CssClass=""text-box"""} | 
    Set-Content "$WebFolder\Director\LogOn.aspx"
    DoLog ("Pre-populated Domain textbox on Director Logon form " + (Get-Date).ToString() + "")

    # Replace Add ActiveDirectory.Domains (user),(server) with actual domain names
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\Director" -Filter "/appSettings/add[@key='Connector.ActiveDirectory.Domains']" -Name value -Value "$domain"
    DoLog ("Replaced the Add ActiveDirectory.Domains (user),(server) with actual domain names " + (Get-Date).ToString() + "")

    # add a new value called ActiveDirectory.ForestSearch. Set it to False. (see http://support.citrix.com/article/CTX133013)
    Add-WebConfigurationProperty -Filter "/appSettings" -PSPath "IIS:\Sites\Default Web Site\Director" -atIndex 0 -Name "Collection" -Value @{key='Connector.ActiveDirectory.ForestSearch';value='false'}
    DoLog ("added the new value called ActiveDirectory.ForestSearch. Set it to False. (see http://support.citrix.com/article/CTX133013) " + (Get-Date).ToString() + "")
    
    # Replace UI.TaskManager.EnableApplications with false
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\Director" -Filter "/appSettings/add[@key='UI.TaskManager.EnableApplications']" -Name value -Value "false"
    DoLog ("Replaced the UI.TaskManager.EnableApplications with false " + (Get-Date).ToString() + "")
    }

DoLog ("--- Afconfig Desktopdirector Ended --- " + (Get-Date).ToString() + " ---")