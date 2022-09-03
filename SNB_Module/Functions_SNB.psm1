<#--------------------------------------------
            Set variables
--------------------------------------------#>
$WinDir = Get-ChildItem Env:Windir
$WinDir = $WinDir.Value
$LogFilePath = "$WinDir\Logs\CTXDeployment\"
$script:LogName = "dummylog.log"
$LogFile = "$LogFilePath\$global:LogName"
if (!(Test-Path $LogFilePath)) {New-Item -Type Directory $LogFilePath}

<#--------------------------------------------
            Create functions
--------------------------------------------#>
# Create Logging functions
if (!(Test-Path $LogFilePath)) {New-Item -Type Directory $LogFilePath} 
    Function DoLog ($str) {
        $str | %{out-file -filepath $LogFile -inputobject $_ -append; Write-Host -ForegroundColor Green $_}
    }
    Function DoLogWarning ($strWarning) {
        $strWarning | %{out-file -filepath $LogFile -inputobject $_ -append; Write-Warning $_}
    }
    Function DoLogError ($strError) {
        $strError | %{out-file -filepath $LogFile -inputobject $_ -append; Write-Error $_ -ErrorAction Stop}
        throw "Script stopped, because of unexpected error."
}

# Create Downloadsource function
Function DownloadSource($Source,$Destination) {
    DoLog (" ------ Start copy source from DSL ------ " + (Get-Date).ToString() + "")
    if (!(Test-Path "$Source")) {
        DoLogError (" ------ $Source doesn't exist, exiting script ------ " + (Get-Date).ToString() + "")
        }
        Else {
            CMD /C "Start /wait Robocopy $Source $Destination /E"
        }
    DoLog (" ------ End copy source from DSL ------ " + (Get-Date).ToString() + "")
}

# Create Add-PsSnapin function with Error handeling
Function AddPSSnapIn($AddPSSnapIn){
        DoLog (" ------ Start AddPSSnapIn $AddPSSnapIn ------ " + (Get-Date).ToString() + "")
        if (Get-PSSnapin -Registered $AddPSSnapIn) {
            DoLog (" ------ Loading AddPSSnapIn $AddPSSnapIn ------ " + (Get-Date).ToString() + "")
                Add-PSSnapin $AddPSSnapIn
            DoLog (" ------ Loaded AddPSSnapIn $AddPSSnapIn ------ " + (Get-Date).ToString() + "")
        }
        Else{
            DoLogError (" ------  $AddPSSnapIn not found, exiting script ------" + (Get-Date).ToString() + "")
        }
        DoLog (" ------ End AddPSSnapIn $AddPSSnapIn ------ " + (Get-Date).ToString() + "")
}

# Create Import-Module function with Error Handeling
Function ImportModule($ImportModule){
        DoLog (" ------ Start ImportModule $ImportModule ------ " + (Get-Date).ToString() + "")
        if (Get-Module -ListAvailable $ImportModule) {
            DoLog (" ------ Loading ImportModule $ImportModule ------ " + (Get-Date).ToString() + "")
            Import-Module $ImportModule
            DoLog (" ------ Loaded ImportModule $ImportModule ------ " + (Get-Date).ToString() + "")
        }
        Else{
            DoLogError (" ------  $ImportModule not found, exiting script ------" + (Get-Date).ToString() + "")
        }
        DoLog (" ------ End ImportModule $ImportModule ------ " + (Get-Date).ToString() + "")
}

# Create Import-Module from File function with Error Handeling
Function ImportModuleFromFile($ImportModuleFromFile){
        DoLog (" ------ Start ImportModuleFromFile $ImportModuleFromFile ------ " + (Get-Date).ToString() + "")
        if (Test-Path $ImportModuleFromFile) {
            DoLog (" ------ Loading ImportModuleFromFile $ImportModuleFromFile ------ " + (Get-Date).ToString() + "")
            Import-Module $ImportModuleFromFile
            DoLog (" ------ Loaded ImportModuleFromFile $ImportModuleFromFile ------ " + (Get-Date).ToString() + "")
        }
        Else{
            DoLogError (" ------  $ImportModuleFromFile not found, exiting script ------" + (Get-Date).ToString() + "")
        }
        DoLog (" ------ End ImportModuleFromFile $ImportModuleFromFile ------ " + (Get-Date).ToString() + "")
}

# Create Hotfixes function
Function Hotfixes($PatchLocation) {
        DoLog (" Hotfixes Install Started " + (Get-Date).ToString() + "")
            If (Test-Path $PatchLocation) {
            $PatchFiles = Get-ChildItem -Path $PatchLocation -Recurse -Filter *.msi
                If ($PatchFiles -eq $Null) {
                    DoLogWarning ( " No MSI files found in the $PatchLocation " + (Get-Date).ToString() + "" ) 
                }
                Else {
                    ForEach ($PatchFile in $PatchFiles) {
                    DoLog ( " Start Installing MSI hotfix $PatchFile " + (Get-Date).ToString() + "" )
                    $PatchFileFullName = $PatchFile.Fullname
                    Start-Process -FilePath msiexec -ArgumentList "/i ""$PatchFileFullName"" /passive /norestart /log ""$LogFilePath\$PatchFile.log""" -Wait
                    DoLog ( " End Installing MSI hotfix $PatchFile " + (Get-Date).ToString() + "" )
                    }
                }
            }
            Else {
                DoLogError (" $PatchLocation not found, exiting script. " + (Get-Date).ToString() + "")
            	}


            If (Test-Path $PatchLocation) {
            $PatchFiles = (Get-ChildItem -Path $PatchLocation -Recurse -Filter *.msu).Name
                If ($PatchFiles -eq $Null) {
                    DoLogWarning ( " No MSU files found in the $PatchLocation " + (Get-Date).ToString() + "" ) 
                }
                Else {
                    ForEach ($PatchFile in $PatchFiles) {
                    $PatchFileFullName = $PatchFile.Fullname
                    DoLog ( " Start Installing MSU hotfix $PatchFile " + (Get-Date).ToString() + "" )
                    Start-Process "wusa" -ArgumentList "/quiet ""$PatchFileFullName"" /norestart /log:""$LogFilePath\$PatchFile.log""" -Wait
                    DoLog ( " End Installing MSU hotfix $PatchFile " + (Get-Date).ToString() + "" )
                    }
                }
            }
            Else {
                DoLogError (" $PatchLocation not found, exiting script. " + (Get-Date).ToString() + "")
            	}


            If (Test-Path $PatchLocation) {
            $PatchFiles = (Get-ChildItem -Path $PatchLocation -Recurse -Filter *.msp).Name
                If ($PatchFiles -eq $Null) {
                    DoLogWarning ( " No MSP files found in the $PatchLocation " + (Get-Date).ToString() + "" ) 
                }
                Else {
                    ForEach ($PatchFile in $PatchFiles) {
                    DoLog ( " Start Installing MSP hotfix $PatchFile " + (Get-Date).ToString() + "" )
                    $PatchFileFullName = $PatchFile.Fullname
                    Start-Process "msiexec" -ArgumentList "/update ""$PatchFileFullName"" /passive /norestart /log ""$LogFilePath\$PatchFile.log""" -Wait
                    DoLog ( " Start Installing MSP hotfix $PatchFile " + (Get-Date).ToString() + "" )
                    }
                }
            }
            Else {
                DoLogError (" $PatchLocation not found, exiting script. " + (Get-Date).ToString() + "")
            	}
            DoLog ("Hotfixes Install Ended " + (Get-Date).ToString() + "")
}




# Create PSSnapInInstall function
Function PSSnapInInstall($PatchLocation,$Filter) {
        DoLog (" PSSnapIn Install Started " + (Get-Date).ToString() + "")
            If (Test-Path $PatchLocation) {
            $PatchFiles = Get-ChildItem -Path $PatchLocation -Recurse -Filter $Filter
                If ($PatchFiles -eq $Null) {
                    DoLogWarning ( " No MSI files found in the $PatchLocation " + (Get-Date).ToString() + "" ) 
                }
                Else {
                    ForEach ($PatchFile in $PatchFiles) {
                    DoLog ( " Start Installing MSI hotfix $PatchFile " + (Get-Date).ToString() + "" )
                    $PatchFileFullName = $PatchFile.Fullname
                    Start-Process -FilePath msiexec -ArgumentList "/i ""$PatchFileFullName"" /passive /norestart /log ""$LogFilePath\$PatchFile.log""" -Wait
                    DoLog ( " End Installing MSI PSSnapIn $PatchFile " + (Get-Date).ToString() + "" )
                    }
                }
            }
            Else {
                DoLogError (" $PatchLocation not found, exiting script. " + (Get-Date).ToString() + "")
            }
        DoLog (" PSSnapIn Install Ended " + (Get-Date).ToString() + "")
}

# Create Directory
Function CreateDir($FolderName) {
    DoLog ("Create $FolderName Directory")
    If (!(Test-Path $FolderName)) {
        New-Item -ItemType Directory $FolderName
        }
    Else {
        DoLogWarning (" $FolderName found, doing nothing. " + (Get-Date).ToString() + "")
        }
}

# Create Install WindowsFeature Function
Function InstallWindowsFeature($WindowsFeature){
        DoLog (" ------ Start Install $WindowsFeature ------ " + (Get-Date).ToString() + "")
        ImportModule "ServerManager"

        If ((Get-WindowsFeature -Name $WindowsFeature).InstallState -eq "Installed") {
            DoLogWarning (" ------ $WindowsFeature already Installed ------ " + (Get-Date).ToString() + "")
        }
        ElseIf ((Get-WindowsFeature -Name $WindowsFeature).Name -eq $null) {
            DoLogError (" ------ $WindowsFeature not found, exiting script ------ " + (Get-Date).ToString() + "")
        }
        Else {
            Install-WindowsFeature -Name $WindowsFeature
            DoLog (" ------ Installing $WindowsFeature ------ " + (Get-Date).ToString() + "")
        }
        DoLog (" ------ End Install $WindowsFeature ------ " + (Get-Date).ToString() + "")
    }

# Create BackupFile function
    Function BackupFile ($OriginalFile) {
        $BackupFile = $OriginalFile + "_old"
        If (!(Test-Path $OriginalFile))
        {
        DoLogError ("$OriginalFile doesn't exist, exit script " + (Get-Date).ToString() + "")
            }
        ElseIf (!(Test-Path $BackupFile))
        {
        Copy-Item -Path "$OriginalFile" -Destination "$BackupFile"
        DoLog ("Copied $OriginalFile to $BackupFile " + (Get-Date).ToString() + "")
        }
        Else
        {
         DoLogWarning ("$BackupFile already exists, Do Nothing. " + (Get-Date).ToString() + "")
        }
    }

# Create RenameFile function
    Function RenameFile ($OriginalFile) {
        $RenameFile = $OriginalFile + "_old"
        If (!(Test-Path $OriginalFile)) {
        DoLogWarning ("$OriginalFile doesn't exist, file is already renamed " + (Get-Date).ToString() + "")
        }
        ElseIf (!(Test-Path $RenameFile)) {
        Rename-Item -Path "$OriginalFile" -NewName "$RenameFile"
        DoLog ("Renamed $OriginalFile to $RenameFile " + (Get-Date).ToString() + "")
        }
        Else {
         DoLogWarning ("$RenameFile already exists, Do Nothing. " + (Get-Date).ToString() + "")
        }
    }

# Create RenameFile function
    Function CopyFile ($OriginalFile,$NewFile) {
        If (!(Test-Path $OriginalFile)) {
            DoLogError (" $OriginalFile doesn't exist, exiting script " + (Get-Date).ToString() + "")
        }
        ElseIf (!(Test-Path $NewFile)) {
            Copy-Item -Path "$OriginalFile" -Destination "$NewFile"
        DoLog (" Copied $OriginalFile to $NewFile " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" $NewFile already exists, Do Nothing. " + (Get-Date).ToString() + "")
        }
    }


# Create SearchAndReplace function
Function SearchAndReplace ($FileSearch,$SearchObject,$ReplaceObject){
        $FileContent = Get-Content "$FileSearch"
        If ($FileContent -match $SearchObject) {
            (Get-Content "$FileSearch") |
            Foreach-Object {$_ -replace "$SearchObject", "$ReplaceObject"} | 
            Set-Content "$FileSearch"
            DoLog ("Replaced $SearchObject with $ReplaceObject in File $FileSearch " + (Get-Date).ToString() + "")
        }
        ElseIf ($FileContent -match $ReplaceObject) {
            DoLogWarning ("$SearchObject was already replaced with $ReplaceObject in File $FileSearch " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogError ("$SearchObject and $ReplaceObject not found in $FileSearch exiting script " + (Get-Date).ToString() + "")
        }
    }
    
# Create Decrypt function
    Function Decrypt([string]$CertencryptPassword) {
          $securepassword = ConvertTo-SecureString $CertencryptPassword -Key (1..16) 
          $marshal = [System.Runtime.InteropServices.Marshal]
          $ptr = $marshal::SecureStringToBSTR( $securepassword )
          $str = $marshal::PtrToStringBSTR( $ptr )
          $marshal::ZeroFreeBSTR( $ptr )
          return $str
    }
	
# Create BindCert function
    Function BindCertIIS($CertUrl,$CertStore) {
        DoLog (" ------ Start Binding Certificate ------ " + (Get-Date).ToString() + "")
        ImportModule IISAdministration
        #Bind your certificate to IIS HTTPS listener
        $Cert = Get-ChildItem -Path $CertStore -DnsName $CertUrl
        $CertThumb = $Cert.Thumbprint.ToString()
        $IISSiteBinding = Get-IISSiteBinding -Name "Default Web Site" -Protocol HTTPS
        $IISSiteBindingCertficateHash = $IISSiteBinding.Attributes.Value
        If ($IISSiteBinding -eq $null) {
            New-IISSiteBinding -Name "Default Web Site" -Protocol HTTPS -CertificateThumbPrint $CertThumb -CertStoreLocation $CertStore -BindingInformation "*:443:"
            DoLog (" https is set on the Default Web Site " + (Get-Date).ToString() + "")
            }
            Else {
                DoLogWarning (" https was already set on the Default Web Site " + (Get-Date).ToString() + "")
            }
        If (!($IISSiteBindingCertficateHash -eq $CertThumb)) {
            get-item $CertStore\$CertThumb | new-item 0.0.0.0!443
            DoLog (" Set binding for the cert on default website https " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" binding for the cert on default website https is already set " + (Get-Date).ToString() + "")
        }
        Pop-Location
        DoLog (" ------ End Binding Certificate ------ " + (Get-Date).ToString() + "")
    }

#region Create function ImportCert
    Function ImportCert ($CertFile,$CertStore,$CertSubject) {
    DoLog (" ------ Start Importing Certificate ------ " + (Get-Date).ToString() + "")
    $Cert = Get-ChildItem $CertStore 
    If (!($cert.Subject -match "$CertSubject")) {
        DoLog (" ------ Importing $CertFile in $CertStore ------ " + (Get-Date).ToString() + "")
        Import-Certificate -FilePath $CertFile -CertStoreLocation $CertStore
        DoLog (" ------ Imported $CertFile in $CertStore ------ " + (Get-Date).ToString() + "")
        }
    Else {
        DoLogWarning (" ------ $CertFile is already imported in the $CertStore ------ " + (Get-Date).ToString() + "")
    }
    DoLog (" ------ End Importing Certificate ------ " + (Get-Date).ToString() + "")
}
#endregion

#region Create function ImportPfxCert
    Function ImportPfxCert ($CertFile,$CertStore,$CertSubject,$CertPassword) {
    DoLog (" ------ Start Importing PfxCertificate ------ " + (Get-Date).ToString() + "")
    $Cert = Get-ChildItem $CertStore 
    If (!($cert.Subject -match "$CertSubject")) {
        DoLog (" ------ Importing $CertFile in $CertStore ------ " + (Get-Date).ToString() + "")
        Import-PfxCertificate -FilePath $CertFile -CertStoreLocation $CertStore -Password $CertPassword
        DoLog (" ------ Imported $CertFile in $CertStore ------ " + (Get-Date).ToString() + "")
        }
    Else {
        DoLogWarning (" ------ $CertFile is already imported in the $CertStore ------ " + (Get-Date).ToString() + "")
    }
    DoLog (" ------ End Importing Certificate ------ " + (Get-Date).ToString() + "")
}
#endregion

# Create RemovePSSession function
    Function RemovePSSession ($SFServer){
        DoLog (" ------ Start RemovePSSession ------ " + (Get-Date).ToString() + "")
        if ((Get-PSSession).ComputerName -eq $SFServer){
            Remove-PSSession -ComputerName $SFServer
            DoLog (" The PSSession from the $SFServer is removed " + (Get-Date).ToString() + "")
        }
        Else {
            DoLogWarning (" No PSSession from the $SFServer found " + (Get-Date).ToString() + "")
        }
        DoLog (" ------ End RemovePSSession ------ " + (Get-Date).ToString() + "")
    }