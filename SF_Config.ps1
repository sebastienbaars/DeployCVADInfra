<#
	**********************************************************************************************************
	Configure Storefront
	Operating system			: Windows Server 2019 GUI
	Commandline parameters		: ConfigFile
	Requirements				: Citrix Storefront and importmodules.ps1 (Snapin)
	Author(s)					: S.N. Baars
	Version						: 0.5
	Date						: 03-09-2022
	Tags						: Storefront, VDI, XenDesktop
	ScriptEngine				: Powershell
	Version  Date        Author    Changelog
	----------------------------------------------------------------------------------------------------------
	0.1    14-10-2016  SNB        Initial
    0.4    11-04-2018  SNB        CallBackURL toegevoegd in de functie en XML bestand
    0.5    10-07-2018  SNB        Toevoegen van de WebCustomizing voor het laten zien op welke SF je aanwezig bent
    0.7    20-03-2019  SNB        DefaultICA in de variables gezet.
    0.8	   24-06-2019  RB         $GatewaySTAUrls aangepast van http:// naar https://
    0.9    09-07-2019  AVDK       Toevoegen van Application Setting tbv CurrentServer
    1.0    29-08-2019  AVDK       CleanUp_StoreFront in 2 delen gesplitst ivm reboot
    1.3    15-04-2020  SNB        Wijzigen van de Gateway's, AggratieGroepen en Receiver Detectie-methode.
    1.4    25-04-2020  SNB        VIP toegevoegd aan de CAG configuratie.
    1.5    04-02-2021  SNB        Foreach toegevoegd aan de AggregationGroups en StopScript gefixt. 
    1.6    12-02-2021  AVDK       Disable IIS Httplogging + Disable Scheduletask Cleanup IIS Logs
    1.7	   18-5-2021   RB         Scheduledtask creation /V1 /RU SYSTEM toegevoegd voor server 2019
    1.8    1-12-2022   SNB        Fix Gateway issues, adding XML-options for Session Control
 
	**********************************************************************************************************
#>
#region Parameters
<#--------------------------------------------
            Set parameters
--------------------------------------------#>
Param(
  [String]$ConfigFile,
  [String]$DeployTemp,
  [String]$SNB_PSModule,
  [String]$log,
  [switch]$Certificate,
  [switch]$AddDNSToHosts,
  [switch]$Config,
  [switch]$JoinSFGroup,
  [switch]$SFConfigure,
  [switch]$SFGroupUpdate,
  [switch]$CleanUp_Storefront_1,
  [switch]$CleanUp_Storefront_2,
  [switch]$AppSetting,
  [switch]$DisableLog
 )
#endregion Parameters 
 
#region Variables

$SFInstallProp = (Get-ItemProperty -Path HKLM:\SOFTWARE\Citrix\DeliveryServicesManagement -Name InstallDir).InstallDir
$SFInstallDir = $SFInstallProp.Substring(0,$SFInstallProp.Length-1)
$SFScriptDir = $SFInstallDir.Substring(0,$SFInstallDir.Length-10) + "Scripts" 

$DeployTempUNC = $DeployTemp -replace ":","$" 

$DefaultWebDir = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\InetStp -name PathWWWRoot
$wwwrootFolder = $DefaultWebDir.PathWWWRoot

$domain = (Get-WmiObject Win32_ComputerSystem).Domain
[XML]$xmldocument = Get-Content -Path $ConfigFile
$DomainLocal = $xmldocument.Domains.Domain | Where-Object {$_.name -eq "$domain"}
$VARs = $DomainLocal.SFConfig
$ADDomain = ((Get-WmiObject Win32_NTDomain).DomainName | Out-String).Trim()

# StoreFront Settings
$SFBaseUrl = $VARs.SFBaseUrl
$SFVersion = $VARs.SFVersion
$SFServer = $VARs.SFServer
$SFClusterPasscodeFile = $VARs.SFClusterPasscodeFile
$Stores = @($VARs.Stores.Store.name)
$JoinScript = "JoinScript.ps1"
$StopScript = "StopScript.ps1"
$DefaultWebSiteStore = $VARs.Stores.Store | Where-Object {$_.DefaultWebsite -eq "True"}
$DefaultWebsite = $DefaultWebSiteStore.name + "Web"
$DefaultICAEntries = $Vars.DefaultICA.ICAEntries.ICAEntry
$StoresChangeDefaultICA = $Vars.Stores.Store | Where-Object {$_.ChangeDefaultICA -eq "True"}

$SFSettings = $VARs.Settings
$SessionTimeoutInterval = $SFSettings.SessionTimeoutInterval
$HTML5Receiver = $SFSettings.HTML5Receiver
$LogoffAction = $SFSettings.LogoffAction


# FarmSettings
$XDFarm1 = $VARs.Farms.Farm | Where-Object {$_.DC -eq "1" -and $_.TYPE -eq "XenDesktop"}
$XDSrv1 = $XDFarm1.Srv
$XDFarm2 = $VARs.Farms.Farm | Where-Object {$_.DC -eq "2" -and $_.TYPE -eq "XenDesktop"}
$XDSrv2 = $XDFarm2.Srv
$XDFarms = $VARs.Farms.Farm | Where-Object {$_.TYPE -eq "XenDesktop"}
$AllFarms = $VArs.Farms.Farm

$XAFarms = $VARs.Farms.Farm | Where-Object {$_.TYPE -eq "XenApp"}
$XASrvs = $XAFarm.Srv + $XAFarm.Zones.Zone.Srv


# Gateway
$STASrvs = ($VARs.Farms.Farm | Where-Object {$_.STA -eq "True"}).Srv
$Gateways = $VARs.AccessGateways.AccessGateway
$GatewayStores = $VARs.Stores.Store | Where-Object {$_.AccessGateway -eq "True"}
$GatewaySTAUrls = ForEach ($STASrv in $STASrvs) {"https://$STASrv"}
$HostsEntries = $VARs.HostEntries.HostEntry.entry

# Certificates
$Certs = $VARs.Certificaten.Certificaat

#AggregationGroups
$AggregationGroups = $VARs.AggregationGroups.AggregationGroup

#FAS
$FASStores = @($VARS.Stores.Store | Where-Object {$_.FAS -eq "True"})

#KeyWords
$KeyWordStores = $VARs.Stores.store | Where-Object {$_.KeyWords.Value -eq "True"}

#region LoadModules
 <#-------------------------------------------
        Load SNB Function Module
-------------------------------------------#>
Unblock-File -Path $SNB_PSModule -Confirm:$False
$global:LogName = $Log
Import-Module $SNB_PSModule -Force
#endregion LoadModules

#region Functions
#region Create AddFarm functionV2
    Function AddFarmtoStore($Farms,$StoreFilter) {
    DoLog ("Start creating Farms to Store " + (Get-Date).ToString() + "")
    ForEach ($Store in $Stores) {
    $StoreServ = Get-STFStoreService | Where-Object {$_.Name -eq ($Store)}
        ForEach ($Farm in $Farms) {
        $FarmName = $Farm.Name
        $FarmType = $Farm.Type
        $FarmSrv = $Farm.Srv
        $XMLPort = $Farm.XMLPort
        $TransportType = $Farm.TransportType
        If (!((Get-STFStoreFarm -StoreService $StoreServ).FarmName -eq $FarmName)) {
            DoLog ("Start adding $FarmName to the $Store "  + (Get-Date).ToString() + "")
                Add-STFStoreFarm -StoreService $StoreServ -FarmName $FarmName -FarmType $FarmType -Servers $FarmSrv -LoadBalance $True -Port $XMLPort -TransportType $TransportType -SSLRelayPort 443
            DoLog ("Added the $FarmName to the $Store "  + (Get-Date).ToString() + "")
            }
            Else {
                DoLogWarning ("$FarmName " + " has already been added to $store " + (Get-Date).ToString() + "")
            }
        }
    }
    DoLog ("End creating Farms to Store " + (Get-Date).ToString() + "")
}
#endregion Create AddFarm function

#region SFConfigure function
    Function SFConfigure {
    DoLog ("--- StoreFront $SFVersion Optimizer started --- " + (Get-Date).ToString() + " ---")
    $WebStores = Get-STFWebReceiverService
    $AuthStores = Get-STFAuthenticationService
    $Stores = Get-STFStoreService

    #region Backup orginal files.
    DoLog (" ------ Start Backup orginal files ------ " + (Get-Date).ToString() + "")
    ForEach ($Webstore in $Webstores) {
    $WebStoreName = $WebStore.FriendlyName
        BackupFile "$wwwrootFolder\Citrix\$WebStoreName\web.config"
		BackupFile "$wwwrootFolder\Citrix\$WebStoreName\custom\script.js"
        BackupFile "$wwwrootFolder\Citrix\$WebStoreName\custom\style.css"
        BackupFile "$wwwrootFolder\Citrix\$WebStoreName\custom\strings.en.js"
        BackupFile "$wwwrootFolder\Citrix\$WebStoreName\custom\strings.nl.js"	
    }

    ForEach ($Store in $Stores) {
    $StoreName = $Store.FriendlyName
        BackupFile "$wwwrootFolder\Citrix\$StoreName\App_Data\default.ica"
        BackupFile "$wwwrootFolder\Citrix\$StoreName\web.config"
    }

    ForEach ($AuthStore in $AuthStores) {
    $AuthStoreName = $authStore.FriendlyName
        BackupFile "$wwwrootFolder\Citrix\$AuthStoreName\web.config"
    }
    DoLog (" ------ End Backup orginal files ------ " + (Get-Date).ToString() + "")
    #endregion Backup orginal files.

    #region Disable User Subscriptions
    DoLog (" ------ Start Disable User Subscriptions ------ " + (Get-Date).ToString() + "")
    ForEach ($Store in $Stores) {
    $StoreLD = Get-STFStoreService -VirtualPath $Store.VirtualPath 
    If (!($StoreLD.Service.LockedDown -eq $True)) {
        DoLog (" ------  Set Disable User Subscriptions on $Store------ " + (Get-Date).ToString() + "")
            Set-STFStoreService -LockedDown $True -StoreService $Store -Confirm:$False
        DoLog (" ------ Setting Disable User Subscriptions on $Store ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------ The  User Subscriptions on $Store was already Disabled ------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Disable User Subscriptions ------ " + (Get-Date).ToString() + "")
    #endregion Disable User Subscriptions    

    #region Disable the PNAgent on all stores
    DoLog (" ------ Start Disable the PNAgent ------ " + (Get-Date).ToString() + "")
    ForEach ($Store in $Stores) {
    $StorePNA = Get-STFStorePNA  -StoreService $Store
    If (!($StorePNA.PnaEnabled -eq $False)) {
        DoLog (" ------  Set Disable PNAgent on $Store ------ " + (Get-Date).ToString() + "")
            Disable-STFStorePna -StoreService $Store -Confirm:$False
        DoLog (" ------  Disabled PNAgent on $Store ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------ The PNAgent on $Store was already Disabled ------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Disable the PNAgent ------ " + (Get-Date).ToString() + "")
    #endregion Disable the PNAgent on all stores       

    #region Deactivate the Classic Theme on the Citrix Receiver for Web
    DoLog (" ------ Start Deactivate the Classic Theme on the Citrix Receiver for Web ------ " + (Get-Date).ToString() + "")
    ForEach ($Webstore in $WebStores) {
    $WebStoreCRE = Get-STFWebReceiverService -VirtualPath $WebStore.VirtualPath 
    If (!($WebStoreCRE.WebReceiver.ClassicReceiverExperience -eq $False)) {
        DoLog (" ------  Set Deactivate the Classic Theme on the Citrix Receiver for Web on $WebStore------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverService -ClassicReceiverExperience $False -WebReceiverService $WebStore
        DoLog (" ------ Setting Deactivate the Classic Theme on the Citrix Receiver for Web on $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------ Deactivate the Classic Theme on the Citrix Receiver for Web on $WebStore was already set ------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Deactivate the Classic Theme on the Citrix Receiver for Web ------ " + (Get-Date).ToString() + "")
    #endregion Deactivate the Classic Theme on the Citrix Receiver for Web

    #region Activate the Unified Receiver Experience as default
    DoLog (" ------ Start Activate the Unified Receiver Experience as default ------ " + (Get-Date).ToString() + "")
    ForEach ($Store in $Stores) {
    $StoreName = $Store.FriendlyName
    $StoreServiceURE = Get-STFStoreService -VirtualPath /Citrix/$StoreName
    $WebStoreURE = Get-STFWebReceiverService -StoreService $StoreServiceURE
        DoLog (" ------  Activate the Unified Receiver Experience as default on $StoreName ------ " + (Get-Date).ToString() + "")
            Set-STFStoreService -UnifiedReceiver $WebStoreURE -StoreService $StoreServiceURE -Confirm:$False
        DoLog (" ------ Activated the Unified Receiver Experience as default on $StoreName ------ " + (Get-Date).ToString() + "")
    }
    DoLog (" ------ End Activate the Unified Receiver Experience as default ------ " + (Get-Date).ToString() + "")
    #endregion Activate the Unified Receiver Experience as default

    #region Set Autolaunch Desktop
    DoLog (" ------ Start Set Autolaunch Desktop ------ " + (Get-Date).ToString() + "")
    ForEach ($WebStore in $WebStores) {
    $StoreUI = Get-STFWebReceiverUserInterface -WebReceiverService $WebStore
    If ($SFSettings.AutoLaunchDesktop -eq "False") {
        [bool]$AutoLaunchDesktop = $False
        }
    If ($SFSettings.AutoLaunchDesktop -eq "True") {
        [bool]$AutoLaunchDesktop = $True
        }
    If ($StoreUI.AutoLaunchDesktop -ne $AutoLaunchDesktop) {
        DoLog (" ------  change  Autolaunch Desktop  on $WebStore ------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverUserInterface -WebReceiverService $WebStore -AutoLaunchDesktop $AutoLaunchDesktop
        DoLog (" ------  changed Autolaunch Desktop on $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------  The Autolaunch Desktop on $WebStore was already changed------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Set Autolaunch Desktop ------ " + (Get-Date).ToString() + "")
    #endregion Set Autolaunch Desktop

    #region Disable "Activate" Option in WebPage
    DoLog (" ------ Start Disable ""Activate"" Option in WebPage ------ " + (Get-Date).ToString() + "")
    ForEach ($WebStore in $WebStores) {
    $WebStoreUI = Get-STFWebReceiverUserInterface -WebReceiverService $WebStore
    If ($WebStoreUI.ReceiverConfiguration.Enabled -eq $True) {
        DoLog (" ------  change Disable ""Activate"" Option in WebPage on $WebStore ------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverUserInterface -WebReceiverService $WebStore -ReceiverConfigurationEnabled $False
        DoLog (" ------  changed Disable ""Activate"" Option in WebPage on $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------  The Disable ""Activate"" Option in WebPage on $WebStore was already changed------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Disable ""Activate"" Option in WebPage ------ " + (Get-Date).ToString() + "")
    #endregion Disable "Activate" Option in WebPage

    #region Change the Storefront layout    
    DoLog (" ------ Start change the Storefront layout with  ------ " + (Get-Date).ToString() + "")  
    ForEach ($Webstore in $Webstores) {
    $WebStoreName = $WebStore.FriendlyName
        DoLog (" ------ Start change the Storefront layout for $WebStore ------ " + (Get-Date).ToString() + "")
            Copy-Item -Path "$Deploytemp\custom\*" -Destination "$wwwrootFolder\Citrix\$WebStoreName\custom\" -Force -Confirm:$False -Recurse
        DoLog (" ------ Changed the Storefront layout for $WebStore ------ " + (Get-Date).ToString() + "")
    }
    DoLog (" ------ End change the Storefront layout  ------ " + (Get-Date).ToString() + "")
    #endregion Change the Storefront layout    

    #region change the plugin assistant
    DoLog (" ------ Start Change the plugin assistant ------ " + (Get-Date).ToString() + "")
    ForEach ($WebStore in $WebStores) {
    $WebStoreName = $WebStore.FriendlyName
    $StorePA = Get-STFWebReceiverPluginAssistant -WebReceiverService $WebStore
    If ($SFSettings.Html5SingleTabLaunch -eq "False") {
        [bool]$Html5SingleTabLaunch = $False
        }
    If ($SFSettings.AutoLaunchDesktop -eq "True") {
        [bool]$Html5SingleTabLaunch = $True
        }
    If (($StorePA.Enabled -ne $False) -or ($StorePA.ProtocolHandler.Enabled -ne $False) -or ($StorePA.Html5.Enabled -ne "$HTML5Receiver") -or ($StorePA.html5.SingleTabLaunch -ne $Html5SingleTabLaunch)) {
        DoLog (" ------  change the plugin assistant on $WebStore ------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverPluginAssistant -WebReceiverService $WebStore -Enabled $False -ProtocolHandlerEnabled $False -Html5SingleTabLaunch $Html5SingleTabLaunch -Html5Enabled $HTML5Receiver
        DoLog (" ------  changed the plugin assistant on $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------  The plugin assistant on $WebStore was already changed------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Disable the plugin assistant ------ " + (Get-Date).ToString() + "")
    #endregion change the plugin assistant   

    #region change the default view to Desktops
    DoLog (" ------ Start change the default view to Desktops ------ " + (Get-Date).ToString() + "")
    ForEach ($WebStore in $WebStores) {
    $StoreUI = Get-STFWebReceiverUserInterface -WebReceiverService $WebStore
    If (!($storeUI.UIViews.DefaultView -eq "Desktops")) {
        DoLog (" ------  change the default view to Desktops on $Webstore ------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverUserInterface -WebReceiverService $Webstore -DefaultView Desktops
        DoLog (" ------  changed the default view to Desktops on $Webstore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------  The default view to Desktops on $Webstore was already changed------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End change the default view to Desktops ------ " + (Get-Date).ToString() + "")
    #endregion change the default view to Desktops            

    #region Set Session Time-out on $SessionTimeoutInterval
    DoLog (" ------ Start Set Session Time-out on $SessionTimeoutInterval ------ " + (Get-Date).ToString() + "")
    ForEach ($Webstore in $WebStores) {
    $WebStoreST = Get-STFWebReceiverService -VirtualPath $WebStore.VirtualPath 
    If (!($WebStoreST.WebReceiver.SessionStateTimeout -eq $SessionTimeoutInterval)) {
        DoLog (" ------  Set Session Time-out on $SessionTimeoutInterval for $WebStore------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverService -WebReceiverService $WebStore -SessionStateTimeout $SessionTimeoutInterval
        DoLog (" ------ Setting Session Time-out on $SessionTimeoutInterval for $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------ SessionTimeoutInterval already set for $WebStore to $SessionTimeoutInterval ------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Set Session Time-out on $SessionTimeoutInterval ------ " + (Get-Date).ToString() + "")
    #endregion Set Session Time-out on $SessionTimeoutInterval       

    #region Set Trusted Domain
    DoLog (" ------ Start Set Trusted Domain ------ " + (Get-Date).ToString() + "")
    ForEach ($AuthStore in $AuthStores) {
    $AuthStoreCO = Get-STFExplicitCommonOptions -AuthenticationService $AuthStore
    If (!($AuthStoreCO.DomainSelection -eq "$ADDomain")) {
        DoLog (" ------  change Trusted Domain on $AuthStore ------ " + (Get-Date).ToString() + "")
            Set-STFExplicitCommonOptions -AuthenticationService $AuthStore -Domains "$ADDomain" -DefaultDomain "$ADDomain" -HideDomainField $True
        DoLog (" ------  changed Trusted Domain on $AuthStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------  The Trusted Domain on $AuthStore was already changed------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Set Trusted Domain ------ " + (Get-Date).ToString() + "")
    #endregion Set Trusted Domain

    #region Set displayName to Domain\Username
    DoLog (" ------ Start Set displayName to Domain\Username ------ " + (Get-Date).ToString() + "")
    ForEach ($AuthStore in $AuthStores) {
    $AuthStoreFN = $AuthStore.FriendlyName
        DoLog (" ------  change Set displayName to Domain\Username on $AuthStore ------ " + (Get-Date).ToString() + "")
            SearchAndReplace $wwwrootFolder\Citrix\$AuthStoreFN\web.config "<add property=""displayName"" />" ""
        DoLog (" ------  changed Set displayName to Domain\Username on $AuthStore ------ " + (Get-Date).ToString() + "")
    }
    DoLog (" ------ End Set displayName to Domain\Username ------ " + (Get-Date).ToString() + "")
    #endregion Set displayName to Domain\Username

    #region Set Change password on Windows Behavior
    DoLog (" ------ Start Set Change password on Windows Behavior ------ " + (Get-Date).ToString() + "")
    ForEach ($AuthStore in $AuthStores) {
    $AuthStoreCO = Get-STFExplicitCommonOptions -AuthenticationService $AuthStore
    If (!($AuthStoreCO.AllowUserPasswordChange -eq "Always")) {
        DoLog (" ------  change Set Change password on Windows Behavior on $AuthStore ------ " + (Get-Date).ToString() + "")
            Set-STFExplicitCommonOptions -AuthenticationService $AuthStore -AllowUserPasswordChange Always -ShowPasswordExpiryWarning Windows
        DoLog (" ------  changed Set Change password on Windows Behavior on $AuthStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------  The Set Change password on Windows Behavior on $Store was already changed------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End Set Change password on Expired ------ " + (Get-Date).ToString() + "")
    #endregion Set Change password on Windows Behavior    

    #region Set WorkSpaceControl Settings
    DoLog (" ------ Start WorkSpaceControl Settings ------ " + (Get-Date).ToString() + "")
    ForEach ($WebStore in $WebStores) {
    $WebStoreWSC = Get-STFWebReceiverService -VirtualPath $WebStore.VirtualPath
    If ($WebStoreWSC.WebReceiver.ClientSettings.UserInterface.WorkspaceControl.LogoffAction -ne "$LogoffAction") {
        DoLog (" ------  change WorkSpaceControl Settings on $WebStore ------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverUserInterface -WorkspaceControlEnabled $True -WorkspaceControlAutoReconnectAtLogon $False -WorkspaceControlLogoffAction $LogoffAction -WorkspaceControlShowReconnectButton $True -WorkspaceControlShowDisconnectButton $True -AppShortcutsAllowSessionReconnect $True -WebReceiverService $WebStore
        DoLog (" ------  changed WorkSpaceControl Settings on $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" ------  The WorkSpaceControl Settings on $WebStore was already changed------ " + (Get-Date).ToString() + "")
        }
    }
    DoLog (" ------ End WorkSpaceControl Settings ------ " + (Get-Date).ToString() + "")
    #endregion Set WorkSpaceControl Settings 

    #region Set Default Webpage
    DoLog (" ------ Start Set Default Webpage ------ " + (Get-Date).ToString() + "")
    Foreach ($WebStore in $WebStores | Where-Object {$_.FriendlyName -eq $DefaultWebSite}) {
    If ($WebStore.DefaultIISSite -eq $False) {
        DoLog (" ------ Set Default Webpage on $WebStore ------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverService -DefaultIISSite -WebReceiverService $WebStore
        DoLog (" ------ Setting Default Webpage on $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else{
            DoLogWarning (" ------ Default Webpage already set on $WebStore ------ " + (Get-Date).ToString() + "")
        }
    DoLog (" ------ End Set Default Webpage ------ " + (Get-Date).ToString() + "")
    }
    #endregion Set Default Webpage

    #region Set Multi-Click
    DoLog (" ------ Start Set Multi-Click ------ " + (Get-Date).ToString() + "")
    Foreach ($WebStore in $WebStores) {
    If (!($Webstore.WebReceiver.ClientSettings.UserInterface.MultiClickTimeout -eq "30")) {
        DoLog (" ------ Set the Multi-Click on $WebStore ------ " + (Get-Date).ToString() + "")
            Set-STFWebReceiverUserInterface -MultiClickTimeout 30 -WebReceiverService $WebStore
        DoLog (" ------ Setting the Multi-Click on $WebStore ------ " + (Get-Date).ToString() + "")
        }
        Else{
            DoLogWarning (" ------ Multi-Click already set on $WebStore ------ " + (Get-Date).ToString() + "")
        }
    DoLog (" ------ End Set Multi-Click ------ " + (Get-Date).ToString() + "")
    }
    #endregion Set Multi-Click
	
	#region Set Default.ica
    DoLog (" ------ Start Set Default.ica ------ " + (Get-Date).ToString() + "")
	ForEach ($Store in $Stores | Where-Object {$_.FriendlyName -eq $StoresChangeDefaultICA.name}) {
    $StoreName = $Store.FriendlyName
        Foreach ($DefaultICAEntry in $DefaultICAEntries) {
            $DefaultICANewLine = $DefaultICAEntry.NewLine
            $DefaultICASearchLine = $DefaultICAEntry.SearchLine
            If ($DefaultICANewLine -eq $Null) {
                DoLogWarning (" No $DefaultICANewLine Found, doing nothing " + (Get-Date).ToString() + "")
            } 
            
            Else {   
                $DefaultIcaContent = Get-Content $wwwrootFolder\Citrix\$StoreName\App_Data\default.ica | Select-String $DefaultICANewLine -Quiet
                If ($DefaultIcaContent -eq $null) {
                   $FileName = "$wwwrootFolder\Citrix\$StoreName\App_Data\default.ica"
                   $Pattern = $DefaultICASearchLine
                   $FileOriginal = Get-Content $FileName
                   [String[]] $FileModified = @() 
                   Foreach ($Line in $FileOriginal)
                   {   
                       $FileModified += $Line
                           if ($Line -match $pattern) 
                           {
                           #Add Lines after the selected pattern 
                           $FileModified += $DefaultICANewLine
                           } 
                   }
                   Set-Content $fileName $FileModified
                   DoLog ("Added the $DefaultICANewLine option in the default.ica for $StoreName " + (Get-Date).ToString() + "")
                }
                Else {
                    DoLogWarning (" the $DefaultICANewLine option in the default.ica of $StoreName was already added " + (Get-Date).ToString() + "")
                }
            }
         }
	}
    DoLog (" ------ End Setting Default.ica ------ " + (Get-Date).ToString() + "")
    #endregion Set Default.ica

		
    DoLog ("--- StoreFront $SFVersion Optimizer ended --- " + (Get-Date).ToString() + " ---")
    }
#endregion SFConfigure function

#region ForceUpdate function
    Function ForceUpdate {
        DoLog (" ------ Start ForceUpdate ------ " + (Get-Date).ToString() + "")
        RemovePSSession $SFServer
        $s = New-PSSession -ComputerName $SFServer
        Invoke-Command -Session $s {Publish-STFServerGroupConfiguration -Confirm:$false}
        DoLog (" ------ End ForceUpdate ------ " + (Get-Date).ToString() + "")
    }
#endregion ForceUpdate function       

#region Create JoinScript function
    Function JoinScript {
        If (!(Test-Path "\\$SFServer\$DeployTempUNC")) {
        DoLog (" DeployTemp not found, creating directory " + (Get-Date).ToString() + "")
            New-Item -ItemType Directory -Path "\\$SFServer\$DeployTempUNC" -Force
        DoLog (" DeployTemp directory created " + (Get-Date).ToString() + "")
            }
        Else {
            DoLogWarning (" DeployTemp directory was found, doing nothing " + (Get-Date).ToString() + "")
            }

        If (Test-Path "\\$SFServer\$DeployTempUNC\$JoinScript") {
        DoLog (" Creating $JoinScript with powershellcode, first remove old file " + (Get-Date).ToString() + "")
            Remove-Item "\\$SFServer\$DeployTempUNC\$JoinScript" -Force
            Add-Content -Value "`$`GetPasscode = Start-STFServerGroupJoin -IsAuthorizingServer -Confirm:`$`False" -Path "\\$SFServer\$DeployTempUNC\$JoinScript" -Force
            Add-Content -Value "`$`GetPasscode.Passcode | Out-file ""$DeployTemp\$SFClusterPasscodeFile"" -Force" -Path "\\$SFServer\$DeployTempUNC\$JoinScript" -Force
        DoLog (" Created $JoinScript with powershellcode, first remove old file " + (Get-Date).ToString() + "")
        }
        ElseIf (!(Test-Path "\\$SFServer\$DeployTempUNC\$JoinScript")) {
        DoLog (" Creating $JoinScript with powershellcode " + (Get-Date).ToString() + "")
            Add-Content -Value "`$`GetPasscode = Start-STFServerGroupJoin -IsAuthorizingServer -Confirm:`$`False" -Path "\\$SFServer\$DeployTempUNC\$JoinScript" -Force
            Add-Content -Value "`$`GetPasscode.Passcode | Out-file ""$DeployTemp\$SFClusterPasscodeFile"" -Force" -Path "\\$SFServer\$DeployTempUNC\$JoinScript" -Force
        DoLog (" Created $JoinScript with powershellcode " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogError (" Something when wrong... " + (Get-Date).ToString() + "")
        }
    }
#endregion Create JoinScript function

#region Create StopJoin function
    Function StopJoin {
        If (!(Test-Path "\\$SFServer\$DeployTempUNC")) {
        DoLog (" DeployTemp not found, creating directory " + (Get-Date).ToString() + "")
            New-Item -ItemType Directory -Path "\\$SFServer\$DeployTempUNC" -Force
        DoLog (" DeployTemp directory created " + (Get-Date).ToString() + "")
            }
        Else {
            DoLogWarning (" DeployTemp directory was found, doing nothing " + (Get-Date).ToString() + "")
            }

        If (Test-Path "\\$SFServer\$DeployTempUNC\$StopScript") {
        DoLog (" Creating $StopScript with powershellcode, first remove old file " + (Get-Date).ToString() + "")
            Remove-Item "\\$SFServer\$DeployTempUNC\$StopScript" -Force
            Add-Content -Value "Stop-STFServerGroupJoin -Confirm:`$`False" -Path "\\$SFServer\$DeployTempUNC\$StopScript" -Force
            Add-Content -Value "Publish-STFServerGroupConfiguration -Confirm:`$`False" -Path "\\$SFServer\$DeployTempUNC\$StopScript" -Force
        DoLog (" Created $JoinScript with powershellcode, first remove old file " + (Get-Date).ToString() + "")
        }
        ElseIf (!(Test-Path "\\$SFServer\$DeployTempUNC\$StopScript")) {
        DoLog (" Creating $StopScript with powershellcode " + (Get-Date).ToString() + "")
            Add-Content -Value "Stop-STFServerGroupJoin -Confirm:`$`False" -Path "\\$SFServer\$DeployTempUNC\$StopScript" -Force
            Add-Content -Value "Publish-STFServerGroupConfiguration -Confirm:`$`False" -Path "\\$SFServer\$DeployTempUNC\$StopScript" -Force
        DoLog (" Created $StopScript with powershellcode " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogError (" Something when wrong... " + (Get-Date).ToString() + "")
        }
    }
#endregion Create JoinScript function

#region Create SleepProcess Function
    Function SleepProgress([hashtable]$SleepHash){ 
     [int]$SleepSeconds = 0
     foreach($Key in $SleepHash.Keys){
         switch($Key){
             "Seconds" {
                 $SleepSeconds = $SleepSeconds + $SleepHash.Get_Item($Key)
             }
             "Minutes" {
                 $SleepSeconds = $SleepSeconds + ($SleepHash.Get_Item($Key) * 60)
             }
             "Hours" {
                 $SleepSeconds = $SleepSeconds + ($SleepHash.Get_Item($Key) * 60 * 60)
             }
         }
     }
     for($Count=0;$Count -lt $SleepSeconds;$Count++){
         $SleepSecondsString = [convert]::ToString($SleepSeconds)
         Write-Progress -Activity "Please wait for $SleepSecondsString seconds" -Status "Sleeping" -PercentComplete ($Count/$SleepSeconds*100)
         Start-Sleep -Seconds 1
     }
     Write-Progress -Activity "Please wait for $SleepSecondsString seconds" -Completed
    }
  #endregion Create SleepProcess Function

#endregion Functions


#-------------------------------------------------------------------------------------------------------------------------------------------------#
#                                                                                                                                                 #
#                                                                                                                                                 #
#                                                                                                                                                 #
#-------------------------------------------------------------------------------------------------------------------------------------------------#

#region AddDNSToHosts
If ($AddDNSToHosts) {
# Add HostEntries to the HostsFile
    forEach ($HostEntry in $HostsEntries) { 
        AddDNStoHostsFile -DNSName $HostEntry
    }
}
#endregion AddDNSToHosts

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
            BindCertIIS -CertUrl $SFBaseUrl -CertStore $CertStore
            }
        Else {
            DoLogWarning ("--- $Cert.BindIIS not found, doing nothing --- " + (Get-Date).ToString() + " ---")
        }
    }
}
#endregion Certificate

#region Config
If ($Config){
        DoLog ("--- Config StoreFront started --- " + (Get-Date).ToString() + " ---")
            #Load Powershell MSWeb Snapins
            ImportModule WebAdministration
            
            #region Configure Storefront Configuration
            #region Configure Storefront BaseURL
            DoLog ("Start Configuring Storefront BaseURL $SFVersion " + (Get-Date).ToString() + "")
                If(!((Get-STFDeployment).HostbaseURL.Host -eq $SFBaseUrl)) {
                    DoLog ("Start creating HostBaseURL $SFBaseUrl " + (Get-Date).ToString() + "")
                        Add-STFDeployment -HostBaseUrl https://$SFBaseUrl -SiteId 1 -Confirm:$False
                    DoLog ("Created HostBaseURL $SFBaseUrl " + (Get-Date).ToString() + "")
                }
                Else {
                    DoLogWarning (" Storefront Deployment with $SFBaseUrl has already been created " + (Get-Date).ToString() + "")
                }
            DoLog ("Ended Configuring Storefront BaseURL $SFVersion " + (Get-Date).ToString() + "")
            #endregion Configure Storefront BaseURL
                
            #region Creating the AuthenticationStervices
            DoLog ("Start creating AuthenticationService " + (Get-Date).ToString() + "")
            ForEach($Store in $Stores) {
            If (!((Get-STFAuthenticationService).FriendlyName -eq ("$Store"+"Auth"))) {
                DoLog ("Start creating $Store" + "Auth " + (Get-Date).ToString() + "")
                    Add-STFAuthenticationService -VirtualPath ("/Citrix/"+$Store+"Auth")
                DoLog ("Created $Store" + "Auth " + (Get-Date).ToString() + "")
                }
            Else {
                DoLogWarning (" $Store" + "Auth has already been created " + (Get-Date).ToString() + "")
                }
            }
            DoLog ("End creating AuthenticationService " + (Get-Date).ToString() + "")
            #endregion Creating the AuthenticationStervices

            #region Creating the StoreServices
            DoLog ("Start creating Stores " + (Get-Date).ToString() + "")
            ForEach ($Store in $Stores) {
            If (!((Get-STFStoreService).FriendlyName -eq $Store)) {
                $AuthStore = Get-STFAuthenticationService | Where-Object {$_.Name -eq ($Store+"Auth")}
                DoLog ("Start creating $Store " + (Get-Date).ToString() + "")
                    Add-STFStoreService  -VirtualPath ("/Citrix/"+$Store) -AuthenticationService $AuthStore -FriendlyName $Store
                DoLog ("Created $Store " + (Get-Date).ToString() + "")
                }
            Else {
                DoLogWarning (" $Store has already been created " + (Get-Date).ToString() + "")
                }
            }
            DoLog ("End creating Stores " + (Get-Date).ToString() + "")
            #endregion Creating the StoreServices
            
            #region Creating the Webstores and adding it to the Stores
            DoLog ("Start creating WebStores " + (Get-Date).ToString() + "")
            ForEach ($Store in $Stores) {
            $StoreServ = Get-STFStoreService | Where-Object {$_.Name -eq ($Store)}
            If (!((Get-STFWebReceiverService).Name -eq ($Store+"Web"))) {
                DoLog ("Start creating the $Store" + "Web "  + (Get-Date).ToString() + "")
                    Add-STFWebReceiverService -VirtualPath ("/Citrix/"+$Store+"Web") -StoreService $StoreServ -FriendlyName ($Store+"Web")
                DoLog ("Created the $Store" + "Web "  + (Get-Date).ToString() + "")
            }
            Else {
                DoLogWarning (" $Store" + "Web has already been created " + (Get-Date).ToString() + "")
                }
            }
            DoLog ("End creating WebStores " + (Get-Date).ToString() + "")
            #endregion Creating the Webstores and adding it to the Stores

            #region Adding the Farms to the Stores
            AddFarmtoStore -Farms $AllFarms
            #endregion Adding the Farms to the Stores

            #region Get Citrix Storefront Config.
            $WebStoreServices = Get-STFWebReceiverService
            $AuthStoreServices = Get-STFAuthenticationService
            $StoreServices = Get-STFStoreService
            #endregion Get Citrix Storefront Config.			
          
            #region Add IntegratedWindows as Authtication to the AuthStore 
            ForEach ($AuthStoreService in $AuthStoreServices) {
            DoLog (" Start Add IntegratedWindows in the Authentication Store " + (Get-Date).ToString() + "")
            $AuthStoreSP = Get-STFAuthenticationServiceProtocol -AuthenticationService $AuthStoreService | Where-Object {$_.Name -eq "IntegratedWindows"}
            $IntegratedWindows = Get-STFAuthenticationProtocolsAvailable | Where-Object { $_ -match "IntegratedWindows" }
            If (!($AuthStoreSP.Enabled -eq $True)) {
                DoLog (" ------  Add IntegratedWindows to the Authentication $AuthStoreService ------ " + (Get-Date).ToString() + "")
                    Enable-STFAuthenticationServiceProtocol -AuthenticationService $AuthStoreService -Name $IntegratedWindows
                DoLog (" ------  Added IntegratedWindows to the Authentication $AuthStoreService ------ " + (Get-Date).ToString() + "")
                }
            Else {
                DoLogWarning (" IntegratedWindows to the Authentication $AuthStoreService was already added " + (Get-Date).ToString() + "")
                }
            }
            DoLog (" ------ End IntegratedWindows in the Authentication Store ------ " + (Get-Date).ToString() + "")
            #endregion Add IntegratedWindows as Authtication to the AuthStore

			#region Set Loopback option
			ForEach ($WebStoreService in $WebStoreServices) {
				DoLog (" Starting Enabling Loopback for faster communication " + (Get-Date).ToString() + "")
    			$WebStoreLoopBack = (Get-STFWebReceiverCommunication -WebReceiverService $WebStoreService).Loopback
                If ($WebStoreLoopBack -eq "Off") {
				    DoLog (" Setting Loopback for faster communication " + (Get-Date).ToString() + "")
                        Set-STFWebReceiverCommunication -WebReceiverService $WebStoreService -Loopback On
                    DoLog (" Loopback for faster communication is set " + (Get-Date).ToString() + "")
                }
                Else {
                    DoLogWarning (" Setting Loopback for faster communication is already set, doing nothing." + (Get-Date).ToString() + "")
                }
                DoLog (" Ended Enabling Loopback for faster communication " + (Get-Date).ToString() + "")
			}
            #endregion Set Loopback option

            #region FAS
			DoLog ("Start FAS Configuration " + (Get-Date).ToString() + "")
			If ($FASStores.FAS -eq "True") {
		    Dolog ("FAS Configuration found " + (Get-Date).ToString() + "")
            Foreach ($FASStore in $FASStores) {
                $FASAuthStoreService = Get-STFAuthenticationService | Where-Object {$_.Name -eq $FASStore.Name+"Auth"}
                $FASStoreService = Get-STFStoreService | Where-Object {$_.Name -eq $FASStore.Name}
				If ((Get-STFCitrixAGBasicOptions $FASAuthStoreService).CredentialValidationMode -eq "Password") {
				    Dolog ("Configure Delegated Authentication for AccessGateway for $FASAuthStoreService " + (Get-Date).ToString() + "")
				        Set-STFCitrixAGBasicOptions -CredentialValidationMode "Auto" -AuthenticationService $FASAuthStoreService
				    Dolog (" Configured Delegated Authentication for AccessGateway $FASAuthStoreService " + (Get-Date).ToString() + "")
                    DoLog (" Enabeling FAS Authentication for $FASStoreService " + (Get-Date).ToString() + "")				    
                        Set-STFClaimsFactoryNames –AuthenticationService $FASAuthStoreService –ClaimsFactoryName "FASClaimsFactory"
                        Set-STFStoreLaunchOptions –StoreService $FASStoreService –VdaLogonDataProvider "FASLogonDataProvider"
                    DoLog (" Enabled FAS Authentication for $FASStoreService " + (Get-Date).ToString() + "")
                    }
                Else {
				    DologWarning ("FAS Configuration already set for $FASStoreService " + (Get-Date).ToString() + "")
				    }		
			    }
            }
            Else {
			    DologWarning ("No FAS Configuration found, skipping function " + (Get-Date).ToString() + "")
                }
            DoLog ("Ended FAS Configuration " + (Get-Date).ToString() + "")
            #endregion FAS

            #region CAG Configuration
            # Adding the Netscaler Gateway Configuration
            # Add NetScaler AccessGateway to the Authentication Store
            DoLog ("Start CAG Configuration " + (Get-Date).ToString() + "")
            ForEach ($GatewayStore in $GatewayStores) {
                $GatewayStoreName = $GatewayStore.Name
                $GatewayStoreNameAuth = $GatewayStoreName+"Auth"
                DoLog (" Start Add CitrixAGBasic in the Authentication Store " + (Get-Date).ToString() + "")
                $AuthStoreSPGW = Get-STFAuthenticationServiceProtocol -AuthenticationService (Get-STFAuthenticationService -VirtualPath /Citrix/$GatewayStoreNameAuth) | Where-Object {$_.Name -eq "CitrixAGBasic"}
                $CitrixAGBasic = Get-STFAuthenticationProtocolsAvailable | Where-Object { $_ -match "CitrixAGBasic" }
                If (!($AuthStoreSPGW.Enabled -eq $True)) {
                    DoLog (" ------  Add CitrixAGBasic to the Authentication $GatewayStoreNameAuth ------ " + (Get-Date).ToString() + "")
                        Enable-STFAuthenticationServiceProtocol -Name $CitrixAGBasic -AuthenticationService (Get-STFAuthenticationService -VirtualPath /Citrix/$GatewayStoreNameAuth)
                    DoLog (" ------  Added CitrixAGBasic to the Authentication $GatewayStoreNameAuth ------ " + (Get-Date).ToString() + "")
                    }
                Else {
                    DoLogWarning (" CitrixAGBasic to the Authentication $GatewayStoreNameAuth was already added " + (Get-Date).ToString() + "")
                    }
                DoLog (" ------ End CitrixAGBasic in the Authentication Store ------ " + (Get-Date).ToString() + "")

                # Add CitrixAGBasic to the WebStore
                DoLog ("Start Add CitrixAGBasic to the WebReceiver $GatewayStoreName " + (Get-Date).ToString() + "")
                $GatewayWebName = $GatewayStoreName+"Web"
                $GatewayWebService = Get-STFWebReceiverService -VirtualPath /Citrix/$GatewayWebName
                    Set-STFWebReceiverAuthenticationMethods -WebReceiverService $GatewayWebService -AuthenticationMethods ExplicitForms,CitrixAGBasic
                DoLog ("Ended Add CitrixAGBasic to the WebReceiver $GatewayStoreName " + (Get-Date).ToString() + "")
                
                # Add NetScaler AccessGateway 
                DoLog ("Start creating AccessGateway to the store " + (Get-Date).ToString() + "")
                Foreach ($Gateway in $Gateways | Where-Object {$_.Storename -eq $GatewayStore.Name}) {
                    $GatewayName = $Gateway.Name
                    $GatewayURL = $Gateway.URL
                    $CallBackURL = $Gateway.CallBackURL
                    $GatewayStoreMapping = $Gateway.StoreName
                    $GatewayVIP = $Gateway.VIP
                    $GWStoreServ = Get-STFStoreService | Where-Object {$_.Name -eq ($GatewayStoreMapping)}
                    $GatewayServName = (Get-STFRoamingGateway -Name $GatewayName).Name
                    $GWStore = (Get-STFStoreRegisteredGateway -StoreService $GWStoreServ).Name
                        If ($GatewayServName -eq $null -and $Gateway.HDXRouting -eq "False") {
                            DoLog ("Start creating the $Gatewayname in StoreFront "  + (Get-Date).ToString() + "")
                                Add-STFRoamingGateway -Name $GatewayName -LogonType Domain -Version Version10_0_69_4 -GatewayUrl $GatewayURL -CallbackUrl $CallBackURL -SecureTicketAuthorityUrls $GatewaySTAUrls -SessionReliability:$True -StasUseLoadBalancing:$True -SubnetIPAddress $GatewayVIP
                            DoLog (" creating the $Gatewayname in StoreFront "  + (Get-Date).ToString() + "")
                            }
                            Else {
                                DoLogWarning (" $GatewayName has already been created in StoreFront  or is for HDXRouting " + (Get-Date).ToString() + "")
                            }
                        If (($GWStore -ne $GatewayName) -and ($Gateway.HDXRouting -eq "False")) {
                            $GatewayServ = Get-STFRoamingGateway -Name $GatewayName
                            If ($Gateway | Where-Object {$_.Default -eq "true"}) {
                                Dolog (" Enable Remote Access on the $GatewayStoreName and add $GatewayName to the Store as default " + (Get-Date).ToString() + "")
                                    Register-STFStoreGateway -Gateway $GatewayServ -StoreService $GWStoreServ -DefaultGateway
                                Dolog (" Enabled Remote Access on the $GatewayStoreName and add $GatewayName to the Store as default " + (Get-Date).ToString() + "")
                            }
                            Else {
                                Dolog (" Enable Remote Access on the $GatewayStoreName and add $GatewayName to the Store " + (Get-Date).ToString() + "")
                                    Register-STFStoreGateway -Gateway $GatewayServ -StoreService $GWStoreServ
                                Dolog (" Enabled Remote Access on the $GatewayStoreName and add $GatewayName to the Store " + (Get-Date).ToString() + "")
                            }
                        }
                        Else {
                            DoLogWarning (" $GatewayName has already been configured for Remote Access on $GatewayStoreName or is for HDXRouting " + (Get-Date).ToString() + "")
                        }
                        DoLog (" Start add $GatewayName to the Optimal HDX Routing Gateway to $GatewayStoreName " + (Get-Date).ToString() + "")
                        If ($Gateway.HDXRouting -eq "True") {
                            $GatewayHDXRoutServ = Get-STFStoreRegisteredOptimalLaunchGateway -StoreService $GWStoreServ
                            $GatewayAGFarm = $Gateway.AGFarm
                            If ($GatewayServName -eq $null) {
                                DoLog ("Start creating the $Gatewayname in StoreFront "  + (Get-Date).ToString() + "")
                                    Add-STFRoamingGateway -Name $GatewayName -LogonType UsedForHDXOnly -GatewayUrl $GatewayURL -SecureTicketAuthorityUrls $GatewaySTAUrls -SessionReliability:$True -StasUseLoadBalancing:$True
                                DoLog (" creating the $Gatewayname in StoreFront "  + (Get-Date).ToString() + "")
                            }
                            Else {
                                DoLogWarning (" $GatewayName has already been created in StoreFront " + (Get-Date).ToString() + "")
                            }                               
                            If (!($GatewayHDXRoutServ.Name -eq $GatewayName)) {
                                $GatewayServHDX = Get-STFRoamingGateway -Name $GatewayName
                                DoLog (" Start adding $GatewayName to the Optimal HDX Routing Gateway to $GatewayStoreName " + (Get-Date).ToString() + "")
                                    Register-STFStoreOptimalLaunchGateway -Gateway $GatewayServHDX -FarmName $GatewayAGFarm -StoreService $GWStoreServ -Verbose
                                DoLog (" The $GatewayName to the Optimal HDX Routing Gateway to $GatewayStoreName is added " + (Get-Date).ToString() + "")
                            }
                            Else {
                                DoLogWarning (" $GatewayName has already been configured for Optimal HDX Routing Gateway on $GatewayStoreName " + (Get-Date).ToString() + "")
                            }
                        }
                        Else {
                         DoLogWarning (" $GatewayName wil not be used for Optimal HDX Routing Gateway " + (Get-Date).ToString() + "")
                        } 
                    DoLog (" Ended adding $GatewayName to the Optimal HDX Routing Gateway to $GatewayStoreName " + (Get-Date).ToString() + "")
                }     
            }
            # Add NetScaler AccessGateway to the Authentication Store
            DoLog ("End CAG Configuration " + (Get-Date).ToString() + "")
            #endregion CAG Configuration

            #region Beacon Configuration
            DoLog (" Start configure Beacons " + (Get-Date).ToString() + "")
            If (!($Gateways -eq $null)) {
                DoLog (" Gateways found, configuring Beacons " + (Get-Date).ToString() + "")
                Set-STFRoamingBeacon -Internal https://$SFBaseUrl -External (($Gateways | Where-Object {$_.HDXRouting -eq "False"}).URL | Sort -Unique)
                DoLog (" Beacons are configured. " + (Get-Date).ToString() + "")
                }
            Else {
                DoLogWarning (" No Gateways configured, so no Beacons will be configured " + (Get-Date).ToString() + "")
            }
            DoLog (" End configure Beacons " + (Get-Date).ToString() + "")
            #endregion Beacon Configuration

            #region Create the AggregationGroups
            DoLog (" Configure AggregationGroups " + (Get-Date).ToString() + "")
            If ($VARs.Stores.Store.AggregationGroup -eq "True") {
                $AGStores = $VARs.Stores.store | Where-Object {$_.AggregationGroup -eq "True"}
                ForEach ($AGStore in $AGStores) {
                    $AGStoreName = $AGStore.name
                    $AGStoreService = Get-STFStoreService -VirtualPath /Citrix/$AGStorename
                        ForEach ($AggregationGroup in $AggregationGroups | where-object {$_.StoreName -eq $AGStoreName} ) {
                            $AggregationGroupName = $AggregationGroup.name
                            $UserFarmMappingNames = $AggregationGroup.UserFarmMappingName
                            ForEach ($UserFarmMappingName in $UserFarmMappingNames) {
                            $UserFarmMappingFriendlyName = $UserFarmMappingName.name
                                If (!((Get-STFUserFarmMapping -StoreService $AGStoreService).Name -eq $UserFarmMappingName.name)) {
                                    $PrimaryFarms = @($UserFarmMappingName.AggregatedDeliveryControllers.Controllers)
                                    $LoadBalanceMode = $UserFarmMappingName.LoadBalanceMode
                                    [boolean]$AreIdentical = [System.Convert]::ToBoolean($AggregationGroup.AreIdentical)
                                    $EquivalentFarmSet = New-STFEquivalentFarmset -Name $AggregationGroupName `
                                                                                  -AggregationGroupName $AggregationGroupName `
                                                                                  -LoadBalanceMode $LoadBalanceMode `
                                                                                  -PrimaryFarms $PrimaryFarms `
                                                                                  -FarmsAreIdentical $AreIdentical

                                        $ADGroupNames = $UserFarmMappingName.ADGroupsName.ADGroupName
                                        $GroupMembers = ForEach ($ADGroupName in $ADGroupNames) {
                                                        $ADGroup = "$ADDomain\$ADGroupName"
                                                        $ADGroupSID = (Get-ADGroup $ADGroupName).SID.Value
                                                        New-STFUserFarmMappingGroup -GroupName $ADGroup -AccountSid $ADGroupSid
                                        }
                                        DoLog (" Configure $UserFarmMappingFriendlyName AggregationGroups for $AGStoreName " + (Get-Date).ToString() + "")
                                            Add-STFUserFarmMapping -StoreService $AGStoreService -Name $UserFarmMappingFriendlyName -GroupMembers @($GroupMembers) -EquivalentFarmSet @($EquivalentFarmSet)
                                        DoLog (" Configured $UserFarmMappingFriendlyName AggregationGroups for $AGStoreName " + (Get-Date).ToString() + "")

                                    }
                                Else {
                                    DoLogWarning (" $UserFarmMappingFriendlyName has already been added to $AggregationGroupName " + (Get-Date).ToString() + "")
                                }
                            }
                        }
                    }
			}
            Else {
                DoLogWarning (" No $AGStore is configured for the use of AggregationGroups " + (Get-Date).ToString() + "")
                }
            #endregion Create the AggregationGroups

            #region Configure KeyWords on Stores
            DoLog (" Start Configure KeyWords " + (Get-Date).ToString() + "")
            If ($KeyWordStores.KeyWords.Value -eq "True") {
            ForEach ($KeyWordStore in $KeyWordStores) {
                    $KeyWordStoreName = $KeyWordStore.name
                    $KeyWordStoreService = Get-STFStoreService -VirtualPath /Citrix/$KeyWordStoreName
                    $KeyWordStoreExclude = $KeyWordStore.KeyWords.exclude
                    $KeyWordStoreInclude = $KeyWordStore.KeyWords.include
                    If ($KeyWordStoreExclude -ne $IsNullOrEmpty) {
                        $KeyWordSetExclude = (Get-STFStoreEnumerationOptions -StoreService $KeyWordStoreService).FilterByKeywordsExclude
                        If (($KeyWordSetExclude -ne $IsNullOrEmpty) -or ($KeyWordSetExclude -ne $KeyWordStoreExclude)) {
                        DoLog (" Configure KeyWords Exclude for $KeyWordStoreName " + (Get-Date).ToString() + "")
                            Set-STFStoreEnumerationOptions -FilterByKeywordsExclude $KeyWordStoreExclude -StoreService $KeyWordStoreService
                        DoLog (" Configured KeyWords Exclude for $KeyWordStoreName " + (Get-Date).ToString() + "")
                        }
                    Else {
                            DoLog (" No KeyWords Exclude for $KeyWordStoreName found, doing nothing " + (Get-Date).ToString() + "")
                        }
                    }
                    If ($KeyWordStoreInclude -ne $IsNullOrEmpty) {
                        $KeyWordSetInclude = (Get-STFStoreEnumerationOptions -StoreService $KeyWordStoreService).FilterByKeywordsInclude
                        If (($KeyWordSetInclude -ne $IsNullOrEmpty) -or ($KeyWordSetInclude -ne $KeyWordStoreInclude)) {
                        DoLog (" Configure KeyWords Exclude for $KeyWordStoreName " + (Get-Date).ToString() + "")
                            Set-STFStoreEnumerationOptions -FilterByKeywordsInclude $KeyWordStoreInclude -StoreService $KeyWordStoreService
                        DoLog (" Configured KeyWords Exclude for $KeyWordStoreName " + (Get-Date).ToString() + "")
                        }
                    Else {
                            DoLog (" No KeyWords Include for $KeyWordStoreName found, doing nothing " + (Get-Date).ToString() + "")
                        }
                    }
                }
                DoLog (" No KeyWords found set, doing nothing " + (Get-Date).ToString() + "")
            }


            DoLog (" End Configure KeyWords " + (Get-Date).ToString() + "")
            #endregion Configure KeyWords on Stores

            
            
            
            
            
            
            
            
            
            #endregion Configure Storefront Configuration
			
            SFConfigure


        DoLog ("Storefront $SFVersion Configured  " + (Get-Date).ToString() + "")
}
#endregion Config            

#region JoinSFGroup
<#--------------------------------------------------------------
            JoinSFGroup
<#-------------------------------------------------------------#>
    If ($JoinSFGroup){
         DoLog ("--- Join StoreFront Server to ServerGroup started --- " + (Get-Date).ToString() + " ---")
            #region Join Server to ServerGroup
            DoLog ("Start Join Server to Servergroup " + (Get-Date).ToString() + "")
            
            #Create JoinScript.ps1
            JoinScript
            StopJoin

            #Create Scheduled Job for creating the Passcode
            DoLog (" Start Create Scheduled Job for the Passcode" + (Get-Date).ToString() + "")
				schtasks /Create /F /TN TEMP_CreateSFPasscode /NP /SC DAILY /S $SFServer /RL HIGHEST /TR "powershell.exe -File $DeployTemp\$JoinScript" /V1 /RU SYSTEM
			DoLog (" End Create Scheduled Job for the Passcode" + (Get-Date).ToString() + "")
			
			DoLog (" Start Create Scheduled Job for the StopJoin" + (Get-Date).ToString() + "")
				schtasks /Create /F /TN TEMP_StopJoin /NP /SC DAILY /S $SFServer /RL HIGHEST /TR "powershell.exe -File $DeployTemp\$StopScript" /V1 /RU SYSTEM
            DoLog (" End Create Scheduled Job for the StopJoin" + (Get-Date).ToString() + "")
			
            DoLog (" Start Scheduled Job for passcode " + (Get-Date).ToString() + "")
				schtasks /Run /TN TEMP_CreateSFPasscode /S $SFServer
            DoLog (" Started the Scheduled Job for passcode " + (Get-Date).ToString() + "")
			
            DoLog ("Wait a periode of time " + (Get-Date).ToString() + "")
            SleepProgress @{"Seconds" = 30}

            DoLog ("End Create Scheduled Job for the Passcode " + (Get-Date).ToString() + "")

               DoLog ("Start joing the server to the servergroup " + (Get-Date).ToString() + "")
               If (Test-Path "\\$SFServer\$DeployTempUNC\$SFClusterPasscodeFile"){
                   $SFPasscode,$remainingLines = Get-Content "\\$SFServer\$DeployTempUNC\$SFClusterPasscodeFile"
                   DoLog ("PassCode : $SFPasscode " + (Get-Date).ToString() + "")
                   Start-STFServerGroupJoin -AuthorizerHostName $SFServer -Passcode $SFPasscode -Confirm:$false
                        # Wait for the joining server to join
                        DoLog ("Waiting for the joining server, cancel using CTRL+C " + (Get-Date).ToString() + "")
                        Wait-STFServerGroupJoin -Confirm:$false
                       
                   #stop the ClusterJoinService
                   DoLog (" Start Scheduled Job for StopJoin " + (Get-Date).ToString() + "")
                   schtasks /Run /TN TEMP_StopJoin /S $SFServer
                   DoLog (" Junction done " + (Get-Date).ToString() + "")
               }
               Else {
                   DoLogError (" No PassCode file in destination" + (Get-Date).ToString() + "")
               }
               DoLog (" End joing the server to the servergroup " + (Get-Date).ToString() + "")

               DoLog ("Wait a periode of time " + (Get-Date).ToString() + "")
               SleepProgress @{"Seconds" = 30}

               DoLog (" Start removing Scheduled Job for the Passcode " + (Get-Date).ToString() + "")
               Schtasks /Delete /TN TEMP_CreateSFPasscode /S $SFServer /F
               Schtasks /Delete /TN TEMP_StopJoin /S $SFServer /F
               DoLog (" End removing Scheduled Job for the Passcode " + (Get-Date).ToString() + "")
               DoLog (" End Join Server to Servergroup " + (Get-Date).ToString() + "")


            #endregion Join Server to ServerGroup

            # Force the Propagete Changes
            SleepProgress @{"Seconds" = 60}
            ForceUpdate

        DoLog ("--- Join StoreFront Server to ServerGroup Ended --- " + (Get-Date).ToString() + " ---")
    }
#endregion JoinSFGroup

#region SFGroupUpdate
<#--------------------------------------------------------------
            SFGroupUpdate
<#-------------------------------------------------------------#>
    If ($SFGroupUpdate){
         DoLog ("--- Force update StoreFrontGroup started --- " + (Get-Date).ToString() + " ---")

            # Force the Propagete Changes
            SleepProgress @{"Seconds" = 60}
            ForceUpdate

        DoLog ("--- Force update StoreFrontGroup Ended --- " + (Get-Date).ToString() + " ---")
    }
#endregion SFGroupUpdate

#region CleanUp_Storefront
<#--------------------------------------------------------------
            CleanUp_Storefront_part1
<#-------------------------------------------------------------#>
    If ($CleanUp_Storefront_1){
         DoLog ("--- Cleanup old Storefront configuration started --- " + (Get-Date).ToString() + " ---")

            # Force removing the old Storefront Configuration
            DoLog ("--- Launch Clearup_1 for cleaning up the old configuration of Storefront part 1--- " + (Get-Date).ToString() + " ---")
                & $SFScriptDir\ClearUp_1.ps1
            DoLog ("--- Launched Clearup_1 for cleaning up the old configuration of Storefront part 1--- " + (Get-Date).ToString() + " ---")

        DoLog ("--- Cleanup old Storefront configuration Ended --- " + (Get-Date).ToString() + " ---")
    }
<#--------------------------------------------------------------
            CleanUp_Storefront_part2
<#-------------------------------------------------------------#>
    If ($CleanUp_Storefront_2){
         DoLog ("--- Cleanup old Storefront configuration started --- " + (Get-Date).ToString() + " ---")

            # Force removing the old Storefront Configuration
            DoLog ("--- Add the PSSnapin of Citrix Framework.Commands --- " + (Get-Date).ToString() + " ---")
                Add-PSSnapin Citrix.DeliveryServices.Framework.Commands
            DoLog ("--- Added the PSSnapin of Citrix Framework.Commands --- " + (Get-Date).ToString() + " ---")
            
            DoLog ("--- Remove old StoreFront configuration part 2--- " + (Get-Date).ToString() + " ---")
                Uninstall-DSFeatureClass -All -Confirm:$false
            DoLog ("--- Removed old StoreFront configuration part 2 --- " + (Get-Date).ToString() + " ---")

        DoLog ("--- Cleanup old Storefront configuration Ended --- " + (Get-Date).ToString() + " ---")
    }
#endregion CleanUp_Storefront

#region Application Setting
<#--------------------------------------------------------------
            Application Settings
<#-------------------------------------------------------------#>
If ($AppSetting){
    

            Dolog ("Start Application Setting " + (Get-Date).ToString() + "")
            $ServerNumber = $env:computername.Substring($env:computername.Length-1)
            $ServerLocation = switch ($env:computername.Split("W")[0].Substring($env:computername.Split("W")[0].Length-1)) {
                                                         a { "a" } # Ambachtweg
                                                         b { "b" } # Bastiondreef
                                          }
            Dolog ("Hostname: $env:COMPUTERNAME, dus CurrentServer: $ServerLocation$ServerNumber " + (Get-Date).ToString() + "")
            # als de ServerIdentifier in IIS gedefinieerd onder de Citrix Virtual Directory;
            If ( Get-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site\Citrix" -filter "/appSettings" -Name Collection | ? {$_.key -eq "ServerIdentifier" } )
               {
                    Dolog ("ServerIdentifier setting found " + (Get-Date).ToString() + "")
                    #Controleren of de juiste waarde niet is ingevuld, moet dit alsnog worden gedaan
                    If (!(     Get-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site\Citrix" -filter "/appSettings" -Name Collection | ? {$_.key -eq "ServerIdentifier" -and $_.value -eq "$ServerLocation$ServerNumber" } ))
                    {
                        $oldvalue = (Get-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site\Citrix" -filter "/appSettings" -Name Collection | ? {$_.key -eq "ServerIdentifier" }).value
                        Dolog ("ServerIdentifier waarde: $oldvalue niet Juist " + (Get-Date).ToString() + "")
                        #De ServerIdentifier is ongelijk aan de hostnaam....
                        #Hier moet iets mee gedaan worden...
                        
                        Dolog ("ServerIdentifier waarde ingesteld op $ServerLocation$ServerNumber " + (Get-Date).ToString() + "")
                        Set-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site\Citrix" -filter "/appSettings" -Name Collection -Value @{key='ServerIdentifier';value="$ServerLocation$ServerNumber"}
                    }
               } else {
                        Dolog ("ServerIdentifier setting Not found " + (Get-Date).ToString() + "")
                        Dolog ("Start setting ServerIdentifier met waarde $ServerLocation$ServerNumber " + (Get-Date).ToString() + "")
                        #Als de ServerIdentifier niet is gedefinieerd, moet dit alsnog worden gedaan met de juiste waarde….
                        Add-WebConfigurationProperty -Filter "/appSettings" -PSPath "IIS:\Sites\Default Web Site\Citrix" -atIndex 0 -Name "Collection" -Value @{key='ServerIdentifier';value="$ServerLocation$ServerNumber"} 
                      }
               Dolog ("Ended Application Setting " + (Get-Date).ToString() + "")
}
#endregion Application Setting

#region Disable IIS HTTPLogging + Disable Scheduletask Cleanup IIS Logs
<#----------------------------------------------------------------------
            Disable IIS HTTPLogging + Disable ScheduleTask Cleanup IIS Logs 
<#-----------------------------------------------------------------------#>
If ($DisableLog){
            Dolog ("Start Disable IIS HTTPLogging " + (Get-Date).ToString() + "")
            # 
            If ((get-WebConfigurationProperty -PSPath "IIS:\" -filter "system.webServer/httpLogging" -name dontLog).value -eq $True) 
            {
                DologWarning ("Disable IIS HTTPLogging already set " + (Get-Date).ToString() + "")}
            else 
            {
                Dolog ("Start Setting IIS HTTPLogging op Disable " + (Get-Date).ToString() + "")
                Set-WebConfigurationProperty -PSPath "IIS:\" -filter "system.webServer/httpLogging" -name dontLog -value $True
                Dolog ("IIS HTTPLogging Disabled " + (Get-Date).ToString() + "")
            }
            Dolog ("Ended Disable IIS HTTPLogging " + (Get-Date).ToString() + "")
            
            Dolog ("Start Disable scheduleTask Cleanup IIS logs " + (Get-Date).ToString() + "") 
            If (Get-ScheduledTask | Where-Object {$_.TaskName -like "Cleanup IIS logs"})
            {
                If (Get-ScheduledTask | Where-Object {$_.TaskName -like "Cleanup IIS logs" -and $_.State -ne "Disabled"} ) 
                {
                Disable-ScheduledTask -TaskName "Cleanup IIS logs"
                }
                else
                {
                Dologwarning ("schedule Task Cleanup IIS Logs already disabled " + (Get-Date).ToString() + "")
                }
            }
            else 
            {
            Dologwarning ("schedule Task Cleanup IIS Logs not exist " + (Get-Date).ToString() + "")
            }
            Dolog ("Ended Disable scheduleTask Cleanup IIS logs " + (Get-Date).ToString() + "")
}
#endregion Disable IIS HTTPLogging + Disable Scheduletask Cleanup IIS Logs
