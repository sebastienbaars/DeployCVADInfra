<#
********************************************************************************************
Powershell script to install and activate a Windows RDS License Server and Citrix Licensing 11.14 for Windows 2012 R2

	Operating system			: Server 2012R2 and Servers 2016
	Commandline parameters		: AllLicensing, RDSLicensing and CTXLicensing
	Requirements				: Start PS with administrator credentials.
					  
	Authors						: P. Reijgersberg - Dutch Ministry of Defense
                                : S.N. Baars - Dutchy MoD
	Version						: 0.0.7
	Date						: 26-05-2017
	Tags						: RDSLicensing, Microsoft, Citrix Licensing 11.14.0.1
	ScriptEngine				: Powershell Copyright 2009

	Version  Date        Author  Changelog
	----------------------------------------------------------------------------------------
	0.0.1    10-03-2016  PR     First version
    0.0.2    29-04-2016  SNB    structuur aan het script gebracht.
    0.0.3    07-06-2016  SNB    Het aanzetten van CheckIns and CheckOuts in de Citrix.opt
    0.0.4    15-06-2016  SNB    InstallWindowsFeature "NET-Framework-Core" toegevoegd omdat deze benodigd is voor de CTXLicensing.
    0.0.5    12-07-2016  SNB    Extra checks ingebouwd en de Function InstallCTXLicensing verbeterd.
    0.0.6    14-10-2016  SNB    Script wijzigen voor CTX Licensing Server 11.14 + Kleine Bugfixes
    0.0.7    26-05-2017  SNB    Script aanpassen aan de SBC methode.
********************************************************************************************
#>
<#--------------------------------------------
            Set parameters
--------------------------------------------#>
Param(
  [String]$ConfigFile,
  [String]$SBC_PSModule,
  [String]$DeployTemp,
  [switch]$RDSLicensing,
  [switch]$CTXLicensing
)

<#--------------------------------------------
            Import SBC_PSModule
--------------------------------------------#>
Import-Module $SBC_PSModule

<#--------------------------------------------
            Set variables
--------------------------------------------#>
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
[XML]$xmldocument = Get-Content -Path $ConfigFile
$DomainLocal = $xmldocument.Domains.Domain | Where-Object {$_.name -eq "$domain"}
$VARs = $DomainLocal.LSConfig
$ADDomain = (Get-ADDomain).NetBIOSName

$CTXLicenseMyFilesPathProp = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\FLEXlm License Manager\CitrixLicensing' -Name License).License
$CTXLicenseMyFilesPath = $CTXLicenseMyFilesPathProp.Substring(0,$CTXLicenseMyFilesPathProp.Length-1)
$CTXLicenseLSPathProp = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Citrix\LicenseServer\Install' -Name LS_Install_Dir).LS_Install_Dir
$CTXLicenseLSPath = $CTXLicenseLSPathProp.Substring(0,$CTXLicenseLSPathProp.Length-1)
$CTXLicensingServerXML = $CTXLicenseLSPath + "\Conf\Server.xml"
$CTXLicenseCitrixOpt = "$CTXLicenseMyFilesPath\CITRIX.Opt"

$Admins = $ADDomain + "\"  + $Vars.Settings.Admins
$maxReceiveThreads = $VARs.Settings.maxReceiveThreads
$maxProcessThreads = $VARs.Settings.maxProcessThreads
$port = $VARs.Settings.port
$redirectHTTP = $VARs.Settings.redirectHTTP
$securePort = $VARs.Settings.securePort

# Configure logging
$WinDir = Get-ChildItem Env:Windir
$WinDir = $WinDir.Value
$LogFilePath = "$WinDir\Logs\CTXDeployment\"
$LogName = "RDS_CTX_Licensing_Config.log"
$LogFile = "$LogFilePath\$LogName"
if (!(Test-Path $LogFilePath)) {New-Item -Type Directory $LogFilePath}



<#--------------------------------------------
            Create Aliases
--------------------------------------------#>
# Create Out-Clipboard alias
new-alias  Out-Clipboard $env:SystemRoot\system32\clip.exe

<#--------------------------------------------
            Create Aliases
--------------------------------------------#>
# Create Activate RDS Licensing Function
    Function ActivateRDSLicensing {
        DoLog (" ------ Start ActivateRDSLicensing ------ " + (Get-Date).ToString() + "")
        PowershellSnapins "RemoteDesktopServices"
        Set-Location RDS:\LicenseServer
        If ((Get-Item .\ActivationStatus).CurrentValue -eq "1") {
            DoLogWarning (" RDSLicensingServer is already Activated, skipping activation " + (Get-Date).ToString() + "")
            }
        Else{
        DoLog (" Start manual activation of the RDSLicenseServer " + (Get-Date).ToString() + "")
            Write-Host "De productID wordt uitgelezen en in de clipboard gezet."
            (Get-Item .\ProductId).CurrentValue | Out-Clipboard | Write-Host "ProductID is in de clipboard gezet."
            (Get-Item .\ProductID).CurrentValue
            Write-Host "Ga naar https://activate.microsoft.com"
            Write-Host "Daarna 2x Next"
            Write-Host "Vul het Product ID, Company en Country in"
            Write-Host "Daarna 2x Next"
            Write-Host "Neem het license server ID over en vul dit aan in het script"
            $ServerID = Read-Host "ServerID"
            Set-Item .\ActivationStatus -Value 1 -ConnectionMethod pw -LSID $ServerID
        DoLog (" Ended manual activation of the RDSLicenseServer " + (Get-Date).ToString() + "")
            }
    }

<#--------------------------------------------------------------
            Install CTX Licensing Server
---------------------------------------------------------------#>
If ($CTXLicensing){
    # Configure CTXLicensing
        ConfigCTXLicensing -CTXLicensingServerXML $CTXLicensingServerXML -Admins $Admins -maxProcessThreads $maxProcessThreads -maxReceiveThreads $maxReceiveThreads -port $port -redirectHTTP $redirectHTTP -SecurePort $securePort -CTXLicenseCitrixOpt $CTXLicenseCitrixOpt
        
        ImportCTXLicense -PatchLocation $DeployTemp -CTXLicenseMyFilesPath $CTXLicenseMyFilesPath
                                
        DoLog ("Herstarting Services " + (Get-Date).ToString() + "")
            Restart-Service -DisplayName "Citrix Licensing"
            Restart-Service -Displayname "Citrix Licensing Support Service" 
            Restart-Service -Displayname "Citrix Licensing WMI"
            Restart-Service -Displayname "Citrix Web Services for Licensing"
        DoLog ("Services are restarted " + (Get-Date).ToString() + "")
}

<#--------------------------------------------------------------
            Install RDS Licensing Server
---------------------------------------------------------------#>
If ($RDSLicensing){
    # Import PowerShell Snapin, the snapin is needed for activating the RDSLicenseServer
        PowershellSnapins "RemoteDesktopServices"

    # Do Write-Host for Activeting the RDSLicening Server.
        ActivateRDSLicensing
}