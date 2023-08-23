param ([Switch]$EnableSensitiveInfoSearch = $false)
# add the "EnableSensitiveInfoSearch" flag to search for sensitive data

$Version = "1.38" # used for logging purposes
###########################################################
<# TODO: 
- Bug fixes:
-- Debug antivirus check (got "registry access is not allowed" exception on Windows 10 without admin elevation)
-- Check for bugs in the SMB1 check - fixed need to check
-- Fix SAM enum CSV output
-- Fix PSv2 CSV output - seems that only "based on reg value" is presented, which isn't accurate
-- Change the "running" to "Running" in log file, change "log_COMPNAME" to "Log_COMPNAME", prevent the transcription messages from being written to screen
-- Debug the FirewallProducts check
-- Debug the RDP check on multiple OS versions - There is a problem in this check (writes RDP disabled when in fact it is open)
- Update PSv2 checks - speak with Nir/Liran, use this: https://robwillis.info/2020/01/disabling-powershell-v2-with-group-policy/, https://github.com/robwillisinfo/Disable-PSv2/blob/master/Disable-PSv2.ps1
- Add check into NetSessionEnum to see whether running on a DC
- Determine if computer is protected against IPv6 based DNS spoofing (mitm6) - IPv6 disabled (Get-NetAdapterBinding -ComponentID ms_tcpip6) or inbound ICMPv6 / outbound DHCPv6 blocked by FW - https://vuls.cert.org/confluence/display/Wiki/2022/02/24/Kerberos+relaying+with+krbrelayx+and+mitm6
- Add AMSI test (find something that is not EICAR based) - https://www.blackhillsinfosec.com/is-this-thing-on
- Update PSv2 checks - speak with Nir/Liran, use this: https://robwillis.info/2020/01/disabling-powershell-v2-with-group-policy/, https://github.com/robwillisinfo/Disable-PSv2/blob/master/Disable-PSv2.ps1
- Ensure that the internet connectivity check (curl over HTTP/S) proxy aware
- Determine more stuff that are found only in the Security-Policy/GPResult files:
-- Determine LDAP Signing and Channel Binding (https://4sysops.com/archives/secure-domain-controllers-with-ldap-channel-binding-and-ldap-signing)
-- Determine if local users can connect over the network ("Deny access to this computer from the network")
-- Determine LDAP Signing and Channel Binding (https://4sysops.com/archives/secure-domain-controllers-with-ldap-channel-binding-and-ldap-signing)
-- Determine if the local administrators group is configured as a restricted group with fixed members (based on Security-Policy inf file)
-- Determine if Domain Admins cannot login to lower tier computers (Security-Policy inf file: Deny log on locally/remote/service/batch)
- Test on Windows 2008
- Consider adding AD permissions checks from here: https://github.com/haim-n/ADDomainDaclAnalysis
- Add check for mDNS? https://f20.be/blog/mdns
- Check AV/Defender configuration also on non-Windows 10/11, but on Windows Server
- Consider removing the recommendation of running as local admin; ensure that most functionality is preserved without it
- When the script is running by an admin but without UAC, pop an UAC confirmation (https://gallery.technet.microsoft.com/scriptcenter/1b5df952-9e10-470f-ad7c-dc2bdc2ac946)
- Check Macro and DDE (OLE) settings (in progress)
- Look for additional checks from windows_hardening.cmd script / Seatbelt
- Enhance internet connectivity checks (use proxy configuration) - need to check proxy settings on multiple types of deployments 
- Check for Lock with screen saver after time-out? (\Control Panel\Personalization\) and "Interactive logon: Machine inactivity limit"? Relevant mostly for desktops
- Check for Device Control? (GPO or dedicated software)
- Add more hardening checks from here: https://adsecurity.org/?p=3299
- Add more hardening checks from here: https://docs.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10
- Add more hardening checks from here: https://twitter.com/dwizzzleMSFT/status/1511368944380100608
- Add more ideas from Microsoft's Attack Surface Analyzer: https://github.com/Microsoft/AttackSurfaceAnalyzer
- Add more settings from hardening docs
- Run the script from remote location to a list of servers - psexec, remote ps, etc.

##########################################################
@Haim Nachmias @Nital Ruzin
##########################################################>

### functions


#<-------------------------  Internal Functions ------------------------->
#function to write to screen
function writeToScreen {
    param (
        $str,$ForegroundColor
    )
    if($null -eq $ForegroundColor){
        $ForegroundColor = Yellow
    }
    Write-Host $str -ForegroundColor $ForegroundColor
}

#function that writes to file gets 3 params (path = folder , file = file name , str string to write in the file)
function writeToFile {
    param (
        $path, $file, $str
    )
    if (!(Test-Path "$path\$file"))
    {
        New-Item -path $path -name $file -type "file" -value $str | Out-Null
        writeToFile -path $path -file $file -str ""
    }
    else
    {
        Add-Content -path "$path\$file" -value $str
    } 
}
#function that writes the log file
function writeToLog {
    param (
        [string]$str
    )
    $stamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $logMessage = "$stamp $str"
    writeToFile -path $folderRootLocation -file (getNameForFile -name "log" -extension ".txt") -str $logMessage
}

#Generate file name based on convention
function getNameForFile{
    param(
        $name,
        $extension
    )
    if($null -eq $extension){
        $extension = ".txt"
    }
    return ($name + "_" + $hostname+$extension)
}

#get registry value
function getRegValue {
    #regName can be empty (pass Null)
    #HKLM is a boolean value True for HKLM(Local machine) False for HKCU (Current User) 
    param (
        $HKLM,
        $regPath,
        $regName
    )
    if(($null -eq $HKLM -and $HKLM -isnot [boolean]) -or $null -eq $regPath){
        writeToLog -str "getRegValue: Invalid use of function - HKLM or regPath"
    }
    if($HKLM){
        if($null -eq $regName){
            return Get-ItemProperty -Path "HKLM:$regPath" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKLM:$regPath" -Name $regName -ErrorAction SilentlyContinue
        }
    }
    else{
        if($null -eq $regName){
            return Get-ItemProperty -Path "HKCU:$regPath" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKCU:$regPath" -Name $regName -ErrorAction SilentlyContinue
        }
    }
    
}

#add result to array - To be exported to CSV 
function addToCSV {
    #isACheck is not mandatory default is true
    param (
        $category,
        $checkName,
        $checkID,
        $status,
        $risk,
        $finding,
        $comment,
        $relatedFile

    )
    $script:checksArray += New-Object -TypeName PSObject -Property @{    
        Category = $category
        CheckName = $checkName
        CheckID = $checkID
        Status = $status
        Risk = $risk
        Finding = $finding
        Comments = $comment
        'Related file' = $relatedFile
      }
}

function addControlsToCSV {
    addToCSV -category "Machine Hardening - Patching" -checkID  "control_OSupdate" -checkName "OS Update" -finding "Ensure OS is up to date" -risk $csvR4 -relatedFile "hotfixes" -comment "shows recent updates" -status $csvUn
    addToCSV -category "Machine Hardening - Audit" -checkID  "control_AuditPol" -checkName "Audit policy" -finding "Ensure audit policy is sufficient (need admin permission to run)" -risk $csvR3 -relatedFile "Audit-Policy" -status $csvUn
    addToCSV -category "Machine Hardening - Users" -checkID  "control_LocalUsers" -checkName "Local users" -finding "Ensure local users are all disabled or have their password rotated" -risk $csvR4 -relatedFile "Local-Users, Security-Policy.inf" -comment "Local users and cannot connect over the network: Deny access to this computer from the network " -status $csvUn
    addToCSV -category "Machine Hardening - Authentication" -checkID  "control_CredDel" -checkName "Credential delegation" -finding "Ensure Credential delegation is not configured or disabled (need admin permission to run)" -risk $csvR3 -relatedFile "GPResult" -comment "Administrative Templates > System > Credentials Delegation > Allow delegating default credentials + with NTLM" -status $csvUn
    addToCSV -category "Machine Hardening - Users" -checkID  "control_LocalAdminRes" -checkName "Local administrators in Restricted groups" -finding "Ensure local administrators group is configured as a restricted group with fixed members (need admin permission to run)" -risk $csvR2 -relatedFile "Security-Policy.inf" -comment "Restricted Groups" -status $csvUn
    addToCSV -category "Machine Hardening - Security" -checkID  "control_UAC" -checkName "UAC enforcement " -finding "Ensure UAC is enabled (need admin permission to run)" -risk $csvR3 -relatedFile "Security-Policy.inf" -comment "User Account Control settings" -status $csvUn
    addToCSV -category "Machine Hardening - Security" -checkID  "control_LocalAV" -checkName "Local Antivirus" -finding "Ensure Antivirus is running and updated, advanced Windows Defender features are utilized" -risk $csvR5 -relatedFile "AntiVirus file" -status $csvUn
    addToCSV -category "Machine Hardening - Users" -checkID  "control_DomainAdminsAcc" -checkName "Domain admin access" -finding "Ensure Domain Admins cannot login to lower tier computers (need admin permission to run)" -risk $csvR4 -relatedFile "Security-Policy.inf" -comment "Deny log on locally/remote/service/batch" -status $csvUn
    addToCSV -category "Machine Hardening - Operation system" -checkID  "control_SvcAcc" -checkName "Service Accounts" -finding "Ensure service Accounts cannot login interactively (need admin permission to run)" -risk $csvR4 -relatedFile "Security-Policy inf" -comment "Deny log on locally/remote" -status $csvUn
    addToCSV -category "Machine Hardening - Authentication" -checkID  "control_LocalAndDomainPassPol" -checkName "Local and domain password policies" -finding "Ensure local and domain password policies are sufficient " -risk $csvR3 -relatedFile "AccountPolicy" -status $csvUn
    addToCSV -category "Machine Hardening - Operation system" -checkID  "control_SharePerm" -checkName "Overly permissive shares" -finding "No overly permissive shares exists " -risk $csvR3 -relatedFile "Shares" -status $csvUn
    addToCSV -category "Machine Hardening - Users" -checkID  "control_NumOfUsersAndGroups" -checkName "Reasonable number or users/groups" -finding "Reasonable number or users/groups have local admin permissions " -risk $csvR3 -relatedFile "Local-Users" -status $csvUn
    addToCSV -category "Machine Hardening - Users" -checkID  "control_UserRights" -checkName "User Rights Assignment" -finding "User Rights Assignment privileges don't allow privilege escalation by non-admins (need admin permission to run)" -risk $csvR4 -relatedFile "Security-Policy.inf" -comment "User Rights Assignment" -status $csvUn
    addToCSV -category "Machine Hardening - Operation system" -checkID  "control_SvcPer" -checkName "Service with overly permissive privileges" -finding "Ensure services are not running with overly permissive privileges" -risk $csvR3 -relatedFile "Services" -status $csvUn
    addToCSV -category "Machine Hardening - Operation system" -checkID  "control_MalProcSrvSoft" -checkName "Irrelevant/malicious processes/services/software" -finding "Ensure no irrelevant/malicious processes/services/software exists" -risk $csvR4 -relatedFile "Services, Process-list, Software, Netstat" -status $csvUn
    addToCSV -category "Machine Hardening - Audit" -checkID  "control_EventLog" -checkName "Event Log" -finding "Ensure logs are exported to SIEM" -risk $csvR2 -relatedFile "Audit-Policy" -status $csvUn
    addToCSV -category "Machine Hardening - Network Access" -checkID  "control_HostFW" -checkName "Host firewall" -finding "Host firewall rules are configured to block/filter inbound (Host Isolation)" -risk $csvR4 -relatedFile "Windows-Firewall, Windows-Firewall-Rules" -status $csvUn
    addToCSV -category "Machine Hardening - Operation system" -checkID  "control_Macros" -checkName "Macros are restricted" -finding "Ensure office macros are restricted" -risk $csvR4 -relatedFile "GPResult, currently WIP" -status $csvUn
}


#<-------------------------  Data Collection Functions ------------------------->
# get current user privileges
function dataWhoAmI {
    param (
        $name 
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToScreen -str "Running whoami..." -ForegroundColor Yellow
    writeToLog -str "running DataWhoAmI function"
    writeToFile -file $outputFile -path $folderLocation -str "`Output of `"whoami /all`" command:`r`n"
    # when running whoami /all and not connected to the domain, claims information cannot be fetched and an error occurs. Temporarily silencing errors to avoid this.
    #$PrevErrorActionPreference = $ErrorActionPreference
    #$ErrorActionPreference = "SilentlyContinue"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2 -and (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        $tmp = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
    }
    else{
        $tmp = $true 
    }
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (!$tmp))
        {
            writeToFile -file $outputFile -path $folderLocation -str (whoami /user /groups /priv)
        }
    else
        {
            writeToFile -file $outputFile -path $folderLocation -str (whoami /all)
        }
    #$ErrorActionPreference = $PrevErrorActionPreference
    writeToFile -file $outputFile -path $folderLocation -str "`r`n========================================================================================================" 
    writeToFile -file $outputFile -path $folderLocation -str "`r`nSome rights allow for local privilege escalation to SYSTEM and shouldn't be granted to non-admin users:"
    writeToFile -file $outputFile -path $folderLocation -str "`r`nSeImpersonatePrivilege `r`nSeAssignPrimaryPrivilege `r`nSeTcbPrivilege `r`nSeBackupPrivilege `r`nSeRestorePrivilege `r`nSeCreateTokenPrivilege `r`nSeLoadDriverPrivilege `r`nSeTakeOwnershipPrivilege `r`nSeDebugPrivilege " 
    writeToFile -file $outputFile -path $folderLocation -str "`r`nSee the following guide for more info:`r`nhttps://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"
}

# get IP settings
function dataIpSettings {
    param (
        $name 
    )
    
    writeToScreen -str "Running ipconfig..." -ForegroundColor Yellow
    writeToLog -str "running DataIpSettings function"
    if($psVer -ge 4){
        $outputFile = getNameForFile -name $name -extension ".csv"
        Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Export-CSV -path "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToFile -file $outputFile -path $folderLocation -str "`Output of `"ipconfig /all`" command:`r`n" 
    writeToFile -file $outputFile -path $folderLocation -str (ipconfig /all) 
    
    
}

# get network connections (run-as admin is required for -b associated application switch)
function getNetCon {
    param (
        $name
    )
    writeToLog -str "running getNetCon function"
    writeToScreen -str "Running netstat..." -ForegroundColor Yellow
    if($psVer -ge 4){
        $outputFile = getNameForFile -name $name -extension ".csv"
        Get-NetTCPConnection | Select-Object local*,remote*,state,AppliedSetting,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -path "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    else{
        $outputFile = getNameForFile -name $name -extension ".txt"
        writeToFile -file $outputFile -path $folderLocation -str "============= netstat -nao ============="
        writeToFile -file $outputFile -path $folderLocation -str (netstat -nao)
        writeToFile -file $outputFile -path $folderLocation -str "============= netstat -naob (includes process name, elevated admin permission is required ============="
        writeToFile -file $outputFile -path $folderLocation -str (netstat -naob)
    }
# "============= netstat -ao  =============" | Out-File $outputFileName  -Append
# netstat -ao | Out-File $outputFileName -Append  # shows server names, but takes a lot of time and not very important
}

#get gpo
function dataGPO {
    param (
        $name
    )
    function testArray{
        param ($gpoName, $gpoList)
        foreach ($name in $gpoList){
            if($name -eq $gpoName){
                return $true
            }
        }
        return $false
    }
    $MAX_GPO_SIZE = 5
    writeToLog -str "running dataGPO function"
    # check if the computer is in a domain
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        # check if we have connectivity to the domain, or if is a DC
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            $gpoPath = $folderLocation+"\"+(getNameForFile -name $name -extension ".html")
            writeToScreen -str "Running GPResult to get GPOs..." -ForegroundColor Yellow
            gpresult /f /h $gpoPath
            # /h doesn't exists on Windows 2003, so we run without /h into txt file
            if (!(Test-Path $gpoPath)) {
                writeToLog -str "Function dataGPO: gpresult failed to export to HTML exporting in txt format"
                $gpoPath = $folderLocation+"\"+(getNameForFile -name $name -extension ".txt")
                gpresult $gpoPath
            }
            else{
                writeToLog -str "Function dataGPO: gpresult exported successfully "
            }
            #getting full GPOs folders from sysvol
            writeToLog -str "Function dataGPO: gpresult exporting xml file"
            $file = getNameForFile -name $name -extension ".xml"
            $folderName = "Applied GPOs"
            $gpoXMLPath =  $folderLocation+"\"+ $file
            $appliedGPOs = @()
            gpresult /f /x $gpoXMLPath
            [xml]$xmlEl = Get-Content $gpoXMLPath
            mkdir -Name $folderName -Path $folderLocation | Out-Null
            $GPOsFolder = $folderLocation + "\" + $folderName 
            if(Test-Path -Path $GPOsFolder -PathType Container){
                $computerGPOs = ($xmlEl.Rsop.ComputerResults.GPO)
                $usersGPOs = ($xmlEl.Rsop.UserResults.GPO)
                if($null -eq $computerGPOs){
                    if($runningAsAdmin)
                    {writeToLog -str "Function dataGPO: exporting full GPOs did not found any computer GPOs"}
                    else{
                        writeToLog -str "Function dataGPO: exporting full GPOs did not found any computer GPOs (not running as admin)"
                    }
                }
                writeToLog -str "Function dataGPO: exporting applied GPOs"
                foreach ($gpo in $computerGPOs){
                    if($gpo.Name -notlike "{*"){
                        if($gpo.Name -ne "Local Group Policy" -and $gpo.Enabled -eq "true" -and $gpo.IsValid -eq "true"){
                            $gpoGuid = $gpo.Path.Identifier.'#text'
                            $fullGPOPath = ("\\$domainName\SYSVOL\$domainName\Policies\$gpoGuid\")
                            if(!(testArray -gpoList $appliedGPOs -gpoName $gpoGuid))
                            {
                                $appliedGPOs += $gpoGuid
                                if(((Get-ChildItem  $fullGPOPath -Recurse| Measure-Object -Property Length -s).sum / 1Mb) -le $MAX_GPO_SIZE){
                                    Copy-item -path $fullGPOPath -Destination ("$GPOsFolder\"+$gpo.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($gpo.Enabled -eq "true" -and $gpo.IsValid -eq "true"){
                        $fullGPOPath = ("\\$domainName\SYSVOL\$domainName\Policies\"+$gpo.Name+"\")
                        if(!(testArray -gpoList $appliedGPOs -gpoName $gpo.Name))
                        {
                            $appliedGPOs += $gpo.Name
                            if(((Get-ChildItem  $fullGPOPath -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $MAX_GPO_SIZE){
                                Copy-item -path $fullGPOPath -Destination ("$GPOsFolder\"+$gpo.Name) -Recurse -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                foreach ($gpo in $usersGPOs){
                    if($gpo.Name -notlike "{*"){
                        if($gpo.Name -ne "Local Group Policy"){
                            $gpoGuid = $gpo.Path.Identifier.'#text'
                            $fullGPOPath = ("\\$domainName\SYSVOL\$domainName\Policies\$gpoGuid\")
                            if(!(testArray -gpoList $appliedGPOs -gpoName $gpoGuid))
                            {
                                $appliedGPOs += $gpoGuid
                                if(((Get-ChildItem  $fullGPOPath -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $MAX_GPO_SIZE){
                                    Copy-item -path $fullGPOPath -Destination ("$GPOsFolder\"+$gpo.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($gpo.Enabled -eq "true" -and $gpo.IsValid -eq "true"){
                        $fullGPOPath = ("\\$domainName\SYSVOL\$domainName\Policies\"+$gpo.Name+"\")
                        if(!(testArray -gpoList $appliedGPOs -gpoName $gpo.Name))
                        {
                            $appliedGPOs += $gpo.Name
                            if(((Get-ChildItem  $fullGPOPath -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $MAX_GPO_SIZE){
                                Copy-item -path $fullGPOPath -Destination ("$GPOsFolder\"+$gpo.Name) -Recurse -ErrorAction SilentlyContinue 
                            }
                        }
                    }
                }
            }
            else{
                writeToLog -str "Function dataGPO: exporting full GPOs failed because function failed to create folder"
            }   
        }
        else
        {
            # TODO: remove live connectivity test
            writeToScreen -str "Unable to get GPO configuration... the computer is not connected to the domain" -ForegroundColor Red
            writeToLog -str "Function dataGPO: Unable to get GPO configuration... the computer is not connected to the domain "
        }
    }
}

# get security policy settings (secpol.msc), run as admin is required
function dataSecurityPolicy {
    param (
        $name
    )
    writeToLog -str "running dataSecurityPolicy function"
    # to open the *.inf output file, open MMC, add snap-in "Security Templates", right click and choose new path, choose the *.inf file path, and open it
    $sPPath = $folderLocation+"\"+(getNameForFile -name $name -extension ".inf")
    if ($runningAsAdmin)
    {
        writeToScreen -str "Getting security policy settings..." -ForegroundColor Yellow
        secedit /export /CFG $sPPath | Out-Null
        if(!(Test-Path $sPPath)){
            writeToLog -str "Function dataSecurityPolicy: failed to export security policy unknown reason"
        }
    }
    else
    {
        writeToScreen -str "Unable to get security policy settings... elevated admin permissions are required" -ForegroundColor Red
        writeToLog -str "Function dataSecurityPolicy: Unable to get security policy settings... elevated admin permissions are required"
    }
}

# Get windows features
function dataWinFeatures {
    param (
        $name
    )
    writeToLog -str "running dataWinFeatures function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    if ($winVersion.Major -ge 6)
    {    
        # first check if we can fetch Windows features in any way - Windows workstation without RunAsAdmin cannot fetch features (also Win2008 but it's rare...)
        if ((!$runningAsAdmin) -and ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1))
        {
            writeToLog -str "Function dataWinFeatures: Unable to get Windows features... elevated admin permissions are required"
            writeToScreen -str "Unable to get Windows features... elevated admin permissions are required" -ForegroundColor Red
        }
        else
        {
            writeToLog -str "Function dataWinFeatures: Getting Windows features..."
            writeToScreen -str "Getting Windows features..." -ForegroundColor Yellow
        }

        writeToFile -file $outputFile -path $folderLocation -str "There are several ways of getting the Windows features. Some require elevation. See the following for details: https://hahndorf.eu/blog/WindowsFeatureViaCmd"
        # get features with Get-WindowsFeature. Requires Windows SERVER 2008R2 or above
        if ($psVer -ge 4 -and (($winVersion.Major -ge 7) -or ($winVersion.Minor -ge 1))) # version should be 7+ or 6.1+
        {
            if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3))
            {
                $outputFile = getNameForFile -name $name -extension ".csv"
                Get-WindowsFeature |  Export-CSV -path ($folderLocation+"\"+$outputFile) -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }
        else{
            writeToLog -str "Function dataWinFeatures: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
        }
        $outputFile = getNameForFile -name $name -extension ".txt"
        # get features with Get-WindowsOptionalFeature. Requires Windows 8/2012 or above and run-as-admin
        if ($psVer -ge 4 -and (($winVersion.Major -ge 7) -or ($winVersion.Minor -ge 2))) # version should be 7+ or 6.2+
        {
            writeToFile -file $outputFile -path $folderLocation -str "============= Output of: Get-WindowsOptionalFeature -Online ============="
            if ($runningAsAdmin)
                {
                    $outputFile = getNameForFile -name $name -extension "-optional.csv"
                    Get-WindowsOptionalFeature -Online | Sort-Object FeatureName |  Export-CSV -path "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue
                }
            else
                {writeToFile -file $outputFile -path $folderLocation -str "Unable to run Get-WindowsOptionalFeature without running as admin. Consider running again with elevated admin permissions."}
        }
        else {
            writeToLog -str "Function dataWinFeatures: unable to run Get-WindowsOptionalFeature - require windows server 8/2008R2 and above and powershell version 4"
        }
        $outputFile = getNameForFile -name $name -extension ".txt"
        # get features with dism. Requires run-as-admin - redundant?
        writeToFile -file $outputFile -path $folderLocation -str "============= Output of: dism /online /get-features /format:table | ft =============" 
        if ($runningAsAdmin)
        {
            writeToFile -file $outputFile -path $folderLocation -str (dism /online /get-features /format:table)
        }
        else
            {writeToFile -file $outputFile -path $folderLocation -str "Unable to run dism without running as admin. Consider running again with elevated admin permissions." 
        }
    } 
}

# get windows features (Windows vista/2008 or above is required) 
# get installed hotfixes (/format:htable doesn't always work)
function dataInstalledHotfixes {
    param (
        $name
    )
    writeToLog -str "running dataInstalledHotfixes function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToScreen -str "Getting installed hotfixes..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str ("The OS version is: " + [System.Environment]::OSVersion + ". See if this version is supported according to the following pages:")
    writeToFile -file $outputFile -path $folderLocation -str "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" 
    writeToFile -file $outputFile -path $folderLocation -str "https://en.wikipedia.org/wiki/Windows_10_version_history" 
    writeToFile -file $outputFile -path $folderLocation -str "https://support.microsoft.com/he-il/help/13853/windows-lifecycle-fact-sheet" 
    writeToFile -file $outputFile -path $folderLocation -str "Output of `"Get-HotFix`" PowerShell command, sorted by installation date:`r`n" 
    writeToFile -file $outputFile -path $folderLocation -str (Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Out-String )
    $outputFile = getNameForFile -name $name -extension ".csv"
    Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object "__SERVER","InstalledOn","HotFixID","InstalledBy","Description","Caption","FixComments","InstallDate","Name","Status" | export-csv -path "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue

    <# wmic qfe list full /format:$htable > $hostname\hotfixes_$hostname.html
    if ((Get-Content $hostname\hotfixes_$hostname.html) -eq $null)
    {
        writeToScreen -str "Checking for installed hotfixes again... htable format didn't work" -ForegroundColor Yellow
        Remove-Item $hostname\hotfixes_$hostname.html
        wmic qfe list > $hostname\hotfixes_$hostname.txt
    } #>
    
}

# get processes (new powershell version and run-as admin are required for IncludeUserName)
function dataRunningProcess {
    param (
        $name
    )
    writeToLog -str "running dataRunningProcess function"
    $outputFile = getNameForFile -name $name -extension ".csv"
    writeToScreen -str "Getting processes..." -ForegroundColor Yellow
    # writeToFile -file $outputFile -path $folderLocation -str  "Output of `"Get-Process`" PowerShell command:`r`n"
    try {
        Get-Process -IncludeUserName | Select-Object "ProcessName", "id", "company", "ProductVersion", "username", "cpu", "WorkingSet"  | export-csv -path "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue

    }
    # run without IncludeUserName if the script doesn't have elevated permissions or for old powershell versions
    catch { 
        Get-Process | Select-Object "ProcessName", "id", "company", "ProductVersion", "cpu", "WorkingSet"  | export-csv -path "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue
    }
        
} 

# get services
function dataServices {   
    param (
        $name
    )
    writeToLog -str "running dataServices function"
    $outputFile = getNameForFile -name $name -extension ".csv"
    writeToScreen -str "Getting services..." -ForegroundColor Yellow
    #writeToFile -file $outputFile -path $folderLocation -str "Output of `"Get-WmiObject win32_service`" PowerShell command:`r`n"
    #writeToFile -file $outputFile -path $folderLocation -str (Get-WmiObject win32_service  | Sort-Object displayname | Format-Table -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-String)
    Get-WmiObject win32_service  | Sort-Object displayname | Select-Object "DisplayName", "Name", "State", "StartMode", "StartName" | export-csv -path  "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue
}

# get installed software
function dataInstalledSoftware{
    param(
        $name
    )
    writeToLog -str "running dataInstalledSoftware function"
    $outputFile = getNameForFile -name $name -extension ".csv"
    writeToScreen -str "Getting installed software..." -ForegroundColor Yellow
    #writeToFile -file $outputFile -path $folderLocation -str (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Out-String -Width 180 | Out-String)
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | export-csv -path "$folderLocation\$outputFile" -NoTypeInformation -ErrorAction SilentlyContinue
}

# get shared folders (Share permissions are missing for older PowerShell versions)
function dataSharedFolders{
    param(
        $name
    )
    writeToLog -str "running dataSharedFolders function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToScreen -str "Getting shared folders..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= Shared Folders ============="
    $shares = Get-WmiObject -Class Win32_Share
    writeToFile -file $outputFile -path $folderLocation -str ($shares | Out-String )
    # get shared folders + share permissions + NTFS permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
    foreach ($share in $shares)
    {
        $sharePath = $share.Path
        $shareName = $share.Name
        writeToFile -file $outputFile -path $folderLocation -str "============= Share Name: $shareName | Share Path: $sharePath =============" 
        writeToFile -file $outputFile -path $folderLocation -str "Share Permissions:"
        # Get share permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
        try
        {
            import-module smbshare -ErrorAction SilentlyContinue
            writeToFile -file $outputFile -path $folderLocation -str ($share | Get-SmbShareAccess | Out-String -Width 180)
        }
        catch
        {
            $shareSecSettings = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'"
            if ($null -eq $shareSecSettings)
                {
                # Unfortunately, some of the shares security settings are missing from the WMI. Complicated stuff. Google "Count of shares != Count of share security"
                writeToLog -str "Function dataSharedFolders:Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting."
                writeToFile -file $outputFile -path $folderLocation -str "Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting.`r`n" }
            else
            {
                $DACLs = (Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'" -ErrorAction SilentlyContinue).GetSecurityDescriptor().Descriptor.DACL
                foreach ($DACL in $DACLs)
                {
                    if ($DACL.Trustee.Domain) {$Trustee = $DACL.Trustee.Domain + "\" + $DACL.Trustee.Name}
                    else {$Trustee = $DACL.Trustee.Name}
                    $AccessType = [Security.AccessControl.AceType]$DACL.AceType
                    $FileSystemRights = $DACL.AccessMask -as [Security.AccessControl.FileSystemRights]
                    writeToFile -file $outputFile -path $folderLocation -str "Trustee: $Trustee | Type: $AccessType | Permission: $FileSystemRights"
                }
            }    
        }
        writeToFile -file $outputFile -path $folderLocation -str "NTFS Permissions:" 
        try {
            writeToFile -file $outputFile -path $folderLocation -str  ((Get-Acl $sharePath).Access | Format-Table | Out-String)
        }
        catch {writeToFile -file $outputFile -path $folderLocation -str "No NTFS permissions were found."}
    }
}

# get local+domain account policy
function dataAccountPolicy {
    param (
        $name
    )
    writeToLog -str "running dataAccountPolicy function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToScreen -str "Getting local and domain account policy..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= Local Account Policy ============="
    writeToFile -file $outputFile -path $folderLocation -str "Output of `"NET ACCOUNTS`" command:`r`n"
    writeToFile -file $outputFile -path $folderLocation -str (NET ACCOUNTS)
    # check if the computer is in a domain
    writeToFile -file $outputFile -path $folderLocation -str "============= Domain Account Policy ============="
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            writeToFile -file $outputFile -path $folderLocation -str "Output of `"NET ACCOUNTS /domain`" command:`r`n" 
            writeToFile -file $outputFile -path $folderLocation -str (NET ACCOUNTS /domain) 
        }    
        else
            {
                writeToLog -str "Function dataAccountPolicy: Error No connection to the domain."
                writeToFile -file $outputFile -path $folderLocation -str "Error: No connection to the domain." 
            }
    }
    else
    {
        writeToLog -str "Function dataAccountPolicy: Error The computer is not part of a domain."
        writeToFile -file $outputFile -path $folderLocation -str "Error: The computer is not part of a domain."
    }
}

# get local users + admins
function dataLocalUsers {
    param (
        $name
    )
    # only run if no running on a domain controller
    writeToLog -str "running dataLocalUsers function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2)
    {
        writeToScreen -str "Getting local users and administrators..." -ForegroundColor Yellow
        writeToFile -file $outputFile -path $folderLocation -str "============= Local Administrators ============="
        writeToFile -file $outputFile -path $folderLocation -str "Output of `"NET LOCALGROUP administrators`" command:`r`n"
        writeToFile -file $outputFile -path $folderLocation -str (NET LOCALGROUP administrators)
        writeToFile -file $outputFile -path $folderLocation -str "============= Local Users ============="
        # Get-LocalUser exists only in Windows 10 / 2016
        try
        {
            writeToFile -file $outputFile -path $folderLocation -str "Output of `"Get-LocalUser`" PowerShell command:`r`n" 
            writeToFile -file $outputFile -path $folderLocation -str (Get-LocalUser | Format-Table name, enabled, AccountExpires, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon, description, SID | Out-String -Width 180 | Out-String)
        }
        catch
        {
            if($psVer -ge 3){
                writeToFile -file $outputFile -path $folderLocation -str "Getting information regarding local users from WMI.`r`n"
                writeToFile -file $outputFile -path $folderLocation -str "Output of `"Get-CimInstance win32_useraccount -Namespace `"root\cimv2`" -Filter `"LocalAccount=`'$True`'`"`" PowerShell command:`r`n"
                writeToFile -file $outputFile -path $folderLocation -str (Get-CimInstance win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" | Select-Object Caption,Disabled,Lockout,PasswordExpires,PasswordRequired,Description,SID | format-table -autosize | Out-String -Width 180 | Out-String)
            }
            else{
                writeToLog -str "Function dataLocalUsers: unsupported powershell version to run Get-CimInstance skipping..."
            }
        }
    }
    
}

# get Windows Firewall configuration
function dataWinFirewall {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running dataWinFirewall function"
    writeToScreen -str "Getting Windows Firewall configuration..." -ForegroundColor Yellow
    if ((Get-Service mpssvc).status -eq "Running")
    {
        writeToFile -file $outputFile -path $folderLocation -str "The Windows Firewall service is running."
        # The NetFirewall commands are supported from Windows 8/2012 (version 6.2) and powershell is 4 and above
        if ($psVer -ge 4 -and (($winVersion.Major -gt 6) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -ge 2)))) # version should be 6.2+
        { 
            writeToFile -file $outputFile -path $folderLocation -str "----------------------------------`r`n"
            writeToFile -file $outputFile -path $folderLocation -str "The output of Get-NetFirewallProfile is:"
            writeToFile -file $outputFile -path $folderLocation -str (Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String)   
            writeToFile -file $outputFile -path $folderLocation -str "----------------------------------`r`n"
            writeToFile -file $outputFile -path $folderLocation -str "The output of Get-NetFirewallRule can be found in the Windows-Firewall-Rules CSV file. No port and IP information there."
            if($runningAsAdmin){
                    
                $temp = $folderLocation + "\" + (getNameForFile -name $name -extension ".csv")
                #Get-NetFirewallRule -PolicyStore ActiveStore | Export-Csv $temp -NoTypeInformation - removed replaced by Nir's Offer
                writeToLog -str "Function dataWinFirewall: Exporting to CSV"
                Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq $True } | Select-Object -Property PolicyStoreSourceType, Name, DisplayName, DisplayGroup,
                @{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
                @{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},
                @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
                @{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},
                @{Name='Service';Expression={($PSItem | Get-NetFirewallServiceFilter).Service}},
                @{Name='Program';Expression={($PSItem | Get-NetFirewallApplicationFilter).Program}},
                @{Name='Package';Expression={($PSItem | Get-NetFirewallApplicationFilter).Package}},
                Enabled, Profile, Direction, Action | export-csv -NoTypeInformation $temp
                }
            else{
                writeToLog -str "Function dataWinFirewall: Not running as administrator not exporting to CSV (Get-NetFirewallRule requires admin permissions)"
            }
        }
        else{
            writeToLog -str "Function dataWinFirewall: unable to run NetFirewall commands - skipping (old OS \ powershell is below 4)"
        }
        if ($runningAsAdmin)
        {
            writeToFile -file $outputFile -path $folderLocation -str "----------------------------------`r`n"
            writeToLog -str "Function dataWinFirewall: Exporting to wfw" 
            $temp = $folderLocation + "\" + (getNameForFile -name $name -extension ".wfw")
            netsh advfirewall export $temp | Out-Null
            writeToFile -file $outputFile -path $folderLocation -str "Firewall rules exported into $temp" 
            writeToFile -file $outputFile -path $folderLocation -str "To view it, open gpmc.msc in a test environment, create a temporary GPO, get to Computer=>Policies=>Windows Settings=>Security Settings=>Windows Firewall=>Right click on Firewall icon=>Import Policy"
        }
    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "The Windows Firewall service is not running." 
    }
}

# get various system info (can take a few seconds)
function dataSystemInfo {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running dataSystemInfo function"
    writeToScreen -str "Running systeminfo..." -ForegroundColor Yellow
    # Get-ComputerInfo exists only in PowerShell 5.1 and above
    if ($PSVersionTable.PSVersion.ToString() -ge 5.1)
    {
        writeToFile -file $outputFile -path $folderLocation -str "============= Get-ComputerInfo =============" 
        writeToFile -file $outputFile -path $folderLocation -str (Get-ComputerInfo | Out-String)
    }
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= systeminfo ============="
    writeToFile -file $outputFile -path $folderLocation -str (systeminfo | Out-String)
}

# get audit Policy configuration
function dataAuditPolicy {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running dataAuditSettings function"
    writeToScreen -str "Getting audit policy configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Audit Policy configuration (auditpol /get /category:*) ============="
    if ($winVersion.Major -ge 6)
    {
        if($runningAsAdmin)
        {writeToFile -file $outputFile -path $folderLocation -str (auditpol /get /category:* | Format-Table | Out-String)}
        else{
            writeToLog -str "Function dataAuditSettings: unable to run auditpol command - not running as elevated admin."
        }
    }
}

#<-------------------------  Configuration Checks Functions ------------------------->

# getting credential guard settings (for Windows 10/2016 and above only)
function checkCredentialGuard {
    param (
        $name
    )
    writeToLog -str "running checkCredentialGuard function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    if ($winVersion.Major -ge 10)
    {
        writeToScreen -str "Getting Credential Guard settings..." -ForegroundColor Yellow
        $DevGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        writeToFile -file $outputFile -path $folderLocation -str "============= Credential Guard Settings from WMI ============="
        if ($null -eq $DevGuard.SecurityServicesConfigured)
            {
                writeToFile -file $outputFile -path $folderLocation -str "The WMI query for Device Guard settings has failed. Status unknown."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-wmi" -status $csvUn -finding "WMI query for Device Guard settings has failed." -risk $csvR3
            }
        else {
            if (($DevGuard.SecurityServicesConfigured -contains 1) -and ($DevGuard.SecurityServicesRunning -contains 1))
            {
                writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is configured and running. Which is good."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-wmi" -status $csvSt -finding "Credential Guard is configured and running." -risk $csvR3
            }
        else
            {
                writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-wmi" -status $csvOp -finding "Credential Guard is turned off." -risk $csvR3
        }    
        }
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw Device Guard Settings from WMI (Including Credential Guard) ============="
        writeToFile -file $outputFile -path $folderLocation -str ($DevGuard | Out-String)
        $DevGuardPS = Get-ComputerInfo dev*
        writeToFile -file $outputFile -path $folderLocation -str "============= Credential Guard Settings from Get-ComputerInfo ============="
        if ($null -eq $DevGuardPS.DeviceGuardSecurityServicesRunning)
            {
                writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-PS" -status $csvOp -finding "Credential Guard is turned off." -risk $csvR3
        }
        else
        {
            if ($null -ne ($DevGuardPS.DeviceGuardSecurityServicesRunning | Where-Object {$_.tostring() -eq "CredentialGuard"}))
                {
                    writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is configured and running. Which is good."
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-PS" -status $csvSt -finding "Credential Guard is configured and running." -risk $csvR3
                }
            else
                {
                    writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is turned off. A possible finding."
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-PS" -status $csvOp -finding "Credential Guard is turned off." -risk $csvR3
                }
        }
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw Device Guard Settings from Get-ComputerInfo ============="
        writeToFile -file $outputFile -path $folderLocation -str ($DevGuardPS | Out-String)
    }
    else{
        writeToLog -str "Function checkCredentialGuard: not supported OS no check is needed..."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-PS" -status $csvOp -finding "OS not supporting Credential Guard." -risk $csvR3
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Credential Guard" -checkID "machine_LSA-CG-wmi" -status $csvOp -finding "OS not supporting Credential Guard." -risk $csvR3
    }
    
}

# getting LSA protection configuration (for Windows 8.1 and above only)
function checkLSAProtectionConf {
    param (
        $name
    )
    writeToLog -str "running checkLSAProtectionConf function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    if (($winVersion.Major -ge 10) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -eq 3)))
    {
        writeToScreen -str "Getting LSA protection settings..." -ForegroundColor Yellow
        $RunAsPPL = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Control\Lsa" -regName "RunAsPPL"
        if ($null -eq $RunAsPPL)
            {
                writeToFile -file $outputFile -path $folderLocation -str "RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "LSA Protection - PPL" -checkID "machine_LSA-ppl" -status $csvOp -finding "RunAsPPL registry value does not exists. LSA protection is off." -risk $csvR5
            }
        else
        {
            writeToFile -file $outputFile -path $folderLocation -str ("RunAsPPL registry value is: " +$RunAsPPL.RunAsPPL )
            if ($RunAsPPL.RunAsPPL -eq 1)
                {
                    writeToFile -file $outputFile -path $folderLocation -str "LSA protection is on. Which is good."
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "LSA Protection - PPL" -checkID "machine_LSA-ppl" -status $csvSt -finding "LSA protection is enabled." -risk $csvR5

                }
            else
                {
                    writeToFile -file $outputFile -path $folderLocation -str "LSA protection is off. Which is bad and a possible finding."
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "LSA Protection - PPL" -checkID "machine_LSA-ppl" -status $csvOp -finding "LSA protection is off (PPL)." -risk $csvR5
            }
        }
    }
    else{
        writeToLog -str "Function checkLSAProtectionConf: not supported OS no check is needed"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "LSA Protection - PPL" -checkID "machine_LSA-ppl" -status $csvOp -finding "OS is not supporting LSA protection (PPL)." -risk $csvR5
    }
}

# test for internet connectivity
function checkInternetAccess{
    param (
        $name 
    )
    if($isServer){
        $currentRisk = $csvR4
    }
    else{
        $currentRisk = $csvR3
    }
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkInternetAccess function"    
    writeToScreen -str "Checking if internet access if allowed... " -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= ping -n 2 8.8.8.8 =============" 
    writeToFile -file $outputFile -path $folderLocation -str (ping -n 2 8.8.8.8)
    writeToFile -file $outputFile -path $folderLocation -str "============= DNS request for 8.8.8.8 =============" 
    $naOutput =""
    $naStdPorts = $false
    $naNStdPorts = $false
    if($psVer -ge 4)
    {
        $test = Resolve-DnsName -Name google.com -Server 8.8.8.8 -QuickTimeout -NoIdn -ErrorAction SilentlyContinue
        if ($null -ne $test){
            writeToFile -file $outputFile -path $folderLocation -str " > DNS request to 8.8.8.8 DNS server was successful. This may be considered a finding, at least on servers."
            writeToFile -file $outputFile -path $folderLocation -str " > DNS request output: "
            writeToFile -file $outputFile -path $folderLocation -str ($test | Out-String)
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - DNS" -checkID "machine_na-dns" -status $csvOp -finding "Public DNS server (8.8.8.8) is accessible from the machine." -risk $currentRisk
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - DNS" -checkID "machine_na-dns" -status $csvSt -finding "Public DNS is not accessible." -risk $currentRisk
        }
    }
    else{
        $result = nslookup google.com 8.8.8.8
        if ($result -like "*DNS request timed out*"){
            writeToFile -file $outputFile -path $folderLocation -str " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - DNS" -checkID "machine_na-dns" -status $csvSt -finding "Public DNS is not accessible." -risk $currentRisk
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > DNS request to 8.8.8.8 DNS server didn't receive a timeout. This may be considered a finding, at least on servers."
            writeToFile -file $outputFile -path $folderLocation -str " > DNS request output: "
            writeToFile -file $outputFile -path $folderLocation -str ($result | Out-String)
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - DNS" -checkID "machine_na-dns" -status $csvOp -finding "Public DNS server (8.8.8.8) is accessible from the machine." -risk $currentRisk
        }
    }
    if($psVer -ge 4){
        
        writeToFile -file $outputFile -path $folderLocation -str "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net =============" 
        $test = $null
        try{
            $test = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net" -ErrorAction SilentlyContinue
        }
        catch{
            $test = $null
        }
        if($null -ne $test){
            if($test.StatusCode -eq 200){
                writeToFile -file $outputFile -path $folderLocation -str " > Port 80 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $naOutput += "Port 80: Open"
                $naStdPorts = $true
            }
            else {
                $str = " > test received http code: "+$test.StatusCode+" Port 80 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $outputFile -path $folderLocation -str $str 
                $naOutput += "Port 80: Blocked" 
            }
        }
        else{
            $naOutput += "Port 80: Blocked" 
            writeToFile -file $outputFile -path $folderLocation -str " > Port 80 outbound access to internet failed - received a time out."
        }

        writeToFile -file $outputFile -path $folderLocation -str "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:443 =============" 
        $test = $null
        try{
            $test = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:443" -ErrorAction SilentlyContinue
        }
        catch{
            $test = $null
        }
        
        if($null -ne $test){
            if($test.StatusCode -eq 200){
                writeToFile -file $outputFile -path $folderLocation -str " > Port 443 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $naOutput += "; Port 443: Open"
                $naStdPorts = $true
            }
            else {
                $str = " > test received http code: "+$test.StatusCode+" Port 443 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $outputFile -path $folderLocation -str $str  
                $naOutput += "; Port 443: Blocked"
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Port 443 outbound access to internet failed - received a time out."
            $naOutput += "; Port 443: Blocked"
        }

        writeToFile -file $outputFile -path $folderLocation -str "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:666 =============" 
        $test = $null
        try{
            $test = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:666" -ErrorAction SilentlyContinue
        }
        catch{
            $test = $null
        }
        if($null -ne $test){
            if($test.StatusCode -eq 200){
                writeToFile -file $outputFile -path $folderLocation -str " > Port 666 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $naOutput += "; Port 663: Open"
                $naNStdPorts = $true
            }
            else {
                $str = " > test received http code: "+$test.StatusCode+" Port 666 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $outputFile -path $folderLocation -str $str  
                $naOutput += "; Port 663: Blocked"
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Port 666 outbound access to internet failed - received a time out."
            $naOutput += "; Port 663: Blocked"
        }

        writeToFile -file $outputFile -path $folderLocation -str "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:8080 =============" 
        $test = $null
        try{
            $test = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:8080" -ErrorAction SilentlyContinue
        }
        catch{
            $test = $null
        }
        
        if($null -ne $test){
            if($test.StatusCode -eq 200){
                writeToFile -file $outputFile -path $folderLocation -str " > Port 8080 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $naOutput += "; Port 8080: Open"
                $naNStdPorts = $true
            }
            else {
                $str = " > test received http code: "+$test.StatusCode+" Port 8080 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $outputFile -path $folderLocation -str $str  
                $naOutput += "; Port 8080: Blocked"
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Port 8080 outbound access to internet failed - received a time out."
            $naOutput += "; Port 8080: Blocked"
        }
        if($naStdPorts -and $naNStdPorts){
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - Browsing" -checkID "machine_na-browsing" -status $csvOp -finding "All ports are open for this machine: $naOutput." -risk $currentRisk
        }
        elseif ($naStdPorts){
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - Browsing" -checkID "machine_na-browsing" -status $csvUn -finding "Standard ports (e.g., 80,443) are open for this machine (bad for servers ok for workstations): $naOutput." -risk $currentRisk
        }
        elseif ($naNStdPorts){
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - Browsing" -checkID "machine_na-browsing" -status $csvOp -finding "Non-standard ports are open (maybe miss configuration?) for this machine (bad for servers ok for workstations): $naOutput." -risk $currentRisk
        }
        else{
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - Browsing" -checkID "machine_na-browsing" -status $csvSt -finding "Access to the arbitrary internet addresses is blocked over all ports that were tested (80, 443, 663, 8080)." -risk $currentRisk
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell is lower then version 4. Other checks are not supported."
        writeToLog -str "Function checkInternetAccess: PowerShell executing the script does not support curl command. Skipping network connection test."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Internet access - Browsing" -checkID "machine_na-browsing" -status $csvUn -finding "PowerShell executing the script does not support curl command. (e.g., PSv3 and below)." -risk $currentRisk
    }
    <#
    # very long test - skipping it for now 
    writeToFile -file $outputFile -path $folderLocation -str "============= tracert -d -w 100 8.8.8.8 =============" 
    writeToFile -file $outputFile -path $folderLocation -str (tracert -d -h 10 -w 50 8.8.8.8)
    #>
}


# check SMB protocol hardening
function checkSMBHardening {
    param (
        $name
    )
    writeToLog -str "running checkSMBHardening function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToScreen -str "Getting SMB hardening configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= SMB versions Support (Server Settings) =============" 
    # Check if Windows Vista/2008 or above and powershell version 4 and up 
    if ($winVersion.Major -ge 6)
    {
        $SMB1 = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -regName "SMB1"
        $SMB2 = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -regName "SMB2" 
        if ($SMB1.SMB1 -eq 0)
            {
                writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is not supported (based on registry values). Which is nice." 
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB1" -checkID "domain_SMBv1" -status $csvSt -finding "SMB1 Server is not supported." -risk $csvR3
            }
        else
            {
                writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is supported (based on registry values). Which is pretty bad and a finding." 
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB1" -checkID "domain_SMBv1" -status $csvOp -finding "SMB1 Server is supported (based on registry values)." -risk $csvR3
            }
        # unknown var will all return false always
        <#
        if (!$smbConfig.EnableSMB1Protocol) 
            {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is not supported (based on Get-SmbServerConfiguration). Which is nice."}
        else
            {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is supported (based on Get-SmbServerConfiguration). Which is pretty bad and a finding."}
            writeToFile -file $outputFile -path $folderLocation -str "---------------------------------------" 
        #>
        if ($SMB2.SMB2 -eq 0)
            {
                writeToFile -file $outputFile -path $folderLocation -str "SMB2 and SMB3 Server are not supported (based on registry values). Which is weird, but not a finding." 
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB2-3" -checkID "domain_SMBv2-3-reg" -status $csvOp -finding "SMB2 and SMB3 Server are not supported (based on registry values)." -risk $csvR1
            }
        else
            {
                writeToFile -file $outputFile -path $folderLocation -str "SMB2 and SMB3 Server are supported (based on registry values). Which is OK."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB2-3" -checkID "domain_SMBv2-3-reg" -status $csvSt -finding "SMB2 and SMB3 Server are supported." -risk $csvR1
             }
        if($psVer -ge 4){
            $smbServerConfig = Get-SmbServerConfiguration
            $smbClientConfig = Get-SmbClientConfiguration
            if (!$smbServerConfig.EnableSMB2Protocol)
                {
                    writeToFile -file $outputFile -path $folderLocation -str "SMB2 Server is not supported (based on Get-SmbServerConfiguration). Which is weird, but not a finding." 
                    addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB2-3" -checkID "domain_SMBv2-3-PS" -status $csvOp -finding "SMB2 Server is not supported (based on powershell)." -risk $csvR1
                }
            else
                {
                    writeToFile -file $outputFile -path $folderLocation -str "SMB2 Server is supported (based on Get-SmbServerConfiguration). Which is OK." 
                    addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB2-3" -checkID "domain_SMBv2-3-PS" -status $csvSt -finding "SMB2 Server is supported." -risk $csvR1
                }
        }
        else{
            addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB2-3" -checkID "domain_SMBv2-3-PS" -status $csvUn -finding "Running in Powershell 3 or lower - not supporting this test" -risk $csvR1
        }
        
    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "Old Windows versions (XP or 2003) support only SMB1." 
        writeToLog -str "Function checkSMBHardening: unable to run windows too old"
        addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB supported versions - SMB2-3" -checkID "domain_SMBv2-3-PS" -status $csvOp -finding "Old Windows versions (XP or 2003) support only SMB1." -risk $csvR1
    }
    writeToFile -file $outputFile -path $folderLocation -str "============= SMB versions Support (Client Settings) ============="
    # Check if Windows Vista/2008 or above
    if ($winVersion.Major -ge 6)
    {
        $SMB1Client = (sc.exe qc lanmanworkstation | Where-Object {$_ -like "*START_TYPE*"}).split(":")[1][1]
        Switch ($SMB1Client)
        {
            "0" {
                writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." 
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB1 - Client" -checkID "domain_SMBv1-client" -status $csvOp -finding "SMB1 Client is set to 'Boot'." -risk $csvR2
            }
            "1" {
                writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'System'. Which is not weird. although disabled is better."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB1 - Client" -checkID "domain_SMBv1-client" -status $csvOp -finding "SMB1 Client is set to 'System'." -risk $csvR2
            }
            "2" {
                writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB1 - Client" -checkID "domain_SMBv1-client" -status $csvOp -finding "SMB 1 client is not disabled." -risk $csvR2
            }
            "3" {
                writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB1 - Client" -checkID "domain_SMBv1-client" -status $csvSt -finding "SMB1 Client is set to 'Manual' (Turned off, but can be started)." -risk $csvR2
            }
            "4" {
                writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Disabled'. Which is nice."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB1 - Client" -checkID "domain_SMBv1-client" -status $csvSt -finding "SMB1 Client is set to 'Disabled'." -risk $csvR2
            }
        }
    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "Old Windows versions (XP or 2003) support only SMB1."
        addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB1 - Client" -checkID "domain_SMBv1-client" -status $csvOp -finding "Old Windows versions (XP or 2003) support only SMB1." -risk $csvR5
    }
    writeToFile -file $outputFile -path $folderLocation -str "============= SMB Signing (Server Settings) ============="
    $SmbServerRequireSigning = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -regName "RequireSecuritySignature"
    $SmbServerSupportSigning = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -regName "EnableSecuritySignature"
    if ($SmbServerRequireSigning.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (always) = Enabled"
        writeToFile -file $outputFile -path $folderLocation -str "SMB signing is required by the server, Which is good." 
        addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB2 - Server signing" -checkID "domain_SMBv2-srvSign" -status $csvSt -finding "SMB signing is required by the server." -risk $csvR4

    }
    else
    {
        if ($SmbServerSupportSigning.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (always) = Disabled" 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding."
            addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB2 - Server signing" -checkID "domain_SMBv2-srvSign" -status $csvOp -finding "SMB signing is enabled by the server, but not required." -risk $csvR4
        }
        else
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (always) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." 
            addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB2 - Server signing" -checkID "domain_SMBv2-srvSign" -status $csvOp -finding "SMB signing is disabled by the server." -risk $csvR4
        }
    }
    # potentially, we can also check SMB signing configuration using PowerShell:
    <#if ($smbServerConfig -ne $null)
    {
        "---------------------------------------" | Out-File $outputFileName -Append
        "Get-SmbServerConfiguration SMB server-side signing details:" | Out-File $outputFileName -Append
        $smbServerConfig | fl *sign* | Out-File $outputFileName -Append
    }#>
    writeToFile -file $outputFile -path $folderLocation -str "============= SMB Signing (Client Settings) =============" 
    $SmbClientRequireSigning = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -regName "RequireSecuritySignature"
    $SmbClientSupportSigning = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -regName "EnableSecuritySignature"
    if ($SmbClientRequireSigning.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (always) = Enabled"
        writeToFile -file $outputFile -path $folderLocation -str "SMB signing is required by the client, Which is good." 
        addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB2 - Client signing" -checkID "domain_SMBv2-clientSign" -status $csvSt -finding "SMB signing is required by the client" -risk $csvR3
    }
    else
    {
        if ($SmbClientSupportSigning.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (always) = Disabled" 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding."
            addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB2 - Client signing" -checkID "domain_SMBv2-clientSign" -status $csvOp -finding "SMB signing is enabled by the client, but not required."  -risk $csvR3
        }
        else
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (always) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding."
            addToCSV -relatedFile $outputFile -category "Domain Hardening - SMB" -checkName "SMB2 - Client signing" -checkID "domain_SMBv2-clientSign" -status $csvOp -finding "SMB signing is disabled by the client." -risk $csvR3
        }
    }
    if ($psVer -ge 4 -and($null -ne $smbServerConfig) -and ($null -ne $smbClientConfig)) {
        # potentially, we can also check SMB signing configuration using PowerShell:
        <#"---------------------------------------" | Out-File $outputFileName -Append
        "Get-SmbClientConfiguration SMB client-side signing details:" | Out-File $outputFileName -Append
        $smbClientConfig | fl *sign* | Out-File $outputFileName -Append #>
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw Data - Get-SmbServerConfiguration =============" 
        writeToFile -file $outputFile -path $folderLocation -str ($smbServerConfig | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw Data - Get-SmbClientConfiguration ============="
        writeToFile -file $outputFile -path $folderLocation -str ($smbClientConfig | Out-String)
    }
    else{
        writeToLog -str "Function checkSMBHardening: unable to run Get-SmbClientConfiguration and Get-SmbServerConfiguration - Skipping checks " 
    }
    
}

# Getting RDP security settings
function checkRDPSecurity {
    param (
        $name
    )
    writeToLog -str "running checkRDPSecurity function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToScreen -str "Getting RDP security settings..." -ForegroundColor Yellow
    
    $WMIFilter = "TerminalName=`"RDP-tcp`"" # there might be issues with the quotation marks - to debug
    $RDP = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter $WMIFilter
    writeToFile -file $outputFile -path $folderLocation -str "============= RDP service status ============="
    $reg = getRegValue -HKLM $true -regPath "\System\CurrentControlSet\Control\Terminal Server" -regName "fDenyTSConnections" #There is false positive in this test

    if($null -ne $reg -and $reg.fDenyTSConnections -eq 1)
    {
        writeToFile -file $outputFile -path $folderLocation -str " > RDP Is disabled on this machine."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP status" -checkID "machine_RDP-reg" -status $csvSt -finding "RDP Is disabled on this machine." -risk $csvR1 
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > RDP Is enabled on this machine."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP status" -checkID "machine_RDP-reg" -finding "RDP Is enabled on this machine." -risk $csvR1

    }
    writeToFile -file $outputFile -path $folderLocation -str "============= Remote Desktop Users ============="
    $test = NET LOCALGROUP "Remote Desktop Users"
    $test = $test -split("`n")
    $flag = $false
    $rdpGenUsersFlag = $false
    $rdpAdmins = $false
    $rdpUsers
    $rdpGenUsersStr
    foreach($line in $test){
        
        if($line -eq "The command completed successfully."){
            $flag = $false
        }
        if($flag){
            if($line -like "Everyone" -or $line -like "*\Domain Users" -or $line -like "*authenticated users*" -or $line -eq "Guest"){
                writeToFile -file $outputFile -path $folderLocation -str " > $line - This is a finding"
                $rdpGenUsersFlag = $true
                if($null -eq $rdpGenUsersStr){
                    $rdpGenUsersStr += $line
                }
                else{
                    $rdpGenUsersStr += ",$line"
                }

            }
            elseif($line -eq "Administrator"){
                writeToFile -file $outputFile -path $folderLocation -str " > $line - local admin can logging throw remote desktop this is a finding"
                $rdpAdmins = $true
            }
            else{
                $rdpUsers += $line
                writeToFile -file $outputFile -path $folderLocation -str " > $line"
            }
        }
        if($line -like "---*---")
        {
            $flag = $true
        }
    }
    if($rdpGenUsersFlag -and $rdpAdmins){
        addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP allowed users" -checkID "machine_RDP-Users" -status $csvOp -finding "RDP Allowed users is highly permissive: $rdpGenUsersStr additionally local admin are allows to remotely login the rest of the allowed RDP list (not including default groups like administrators):$rdpUsers" -risk $csvR3
    }
    elseif($rdpGenUsersFlag){
        addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP allowed users" -checkID "machine_RDP-Users" -status $csvOp -finding "RDP Allowed users is highly permissive: $rdpGenUsersStr rest of the allowed RDP list(not including default groups like administrators):$rdpUsers" -risk $csvR3
    }
    elseif($rdpAdmins){
        addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP allowed users" -checkID "machine_RDP-Users" -status $csvOp -finding "Local admin are allows to remotely login the the allowed RDP users and groups list(not including default groups like administrators):$rdpUsers"  -risk $csvR3
    }
    else{
        if($rdpUsers -eq ""){
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP allowed users" -checkID "machine_RDP-Users" -status $csvUn -finding "Only Administrators of the machine are allowed to RDP" -risk $csvR3
        }
        else{
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP allowed users" -checkID "machine_RDP-Users" -status $csvUn -finding "Allowed RDP users and groups list(not including default groups like administrators):$rdpUsers" -risk $csvR3
        }
    }
     
    writeToFile -file $outputFile -path $folderLocation -str "============= NLA (Network Level Authentication) ============="
    if ($RDP.UserAuthenticationRequired -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "NLA is required, which is fine."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP - Network Level Authentication" -checkID "machine_RDP-NLA" -status $csvSt -finding "NLA is required for RDP connections." -risk $csvR2
        }
    if ($RDP.UserAuthenticationRequired -eq 0)
        {
            writeToFile -file $outputFile -path $folderLocation -str "NLA is not required, which is bad. A possible finding."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP - Network Level Authentication" -checkID "machine_RDP-NLA" -status $csvOp -finding "NLA is not required for RDP connections." -risk $csvR2

        }
        writeToFile -file $outputFile -path $folderLocation -str "============= Security Layer (SSL/TLS) ============="
    if ($RDP.SecurityLayer -eq 0)
        {
            writeToFile -file $outputFile -path $folderLocation -str "Native RDP encryption is used instead of SSL/TLS, which is bad. A possible finding."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP - Security Layer (SSL/TLS)" -checkID "machine_RDP-TLS" -status $csvOp -finding "Native RDP encryption is used instead of SSL/TLS." -risk $csvR2
         }
    if ($RDP.SecurityLayer -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP - Security Layer (SSL/TLS)" -checkID "machine_RDP-TLS" -status $csvOp -finding "SSL/TLS is supported, but not required." -risk $csvR2
        }
    if ($RDP.SecurityLayer -eq 2)
        {
            writeToFile -file $outputFile -path $folderLocation -str "SSL/TLS is required for connecting. Which is good."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP - Security Layer (SSL/TLS)" -checkID "machine_RDP-TLS" -status $csvSt -finding "SSL/TLS is required for RDP connections." -risk $csvR2
        }
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw RDP Timeout Settings (from Registry) ============="
    $RDPTimeout = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
    if ($RDPTimeout.ValueCount -eq 0)
        {
            writeToFile -file $outputFile -path $folderLocation -str "RDP timeout is not configured. A possible finding."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP - Timeout" -checkID "machine_RDP-Timeout" -status $csvOp -finding "RDP timeout is not configured." -risk $csvR4

    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "The following RDP timeout properties were configured:" 
        writeToFile -file $outputFile -path $folderLocation -str ($RDPTimeout |Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "MaxConnectionTime = Time limit for active RDP sessions" 
        writeToFile -file $outputFile -path $folderLocation -str "MaxIdleTime = Time limit for active but idle RDP sessions"
        writeToFile -file $outputFile -path $folderLocation -str "MaxDisconnectionTime = Time limit for disconnected RDP sessions" 
        writeToFile -file $outputFile -path $folderLocation -str "fResetBroken = Log off session (instead of disconnect) when time limits are reached" 
        writeToFile -file $outputFile -path $folderLocation -str "60000 = 1 minute, 3600000 = 1 hour, etc."
        writeToFile -file $outputFile -path $folderLocation -str "`r`nFor further information, see the GPO settings at: Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session\Session Time Limits"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - RDP" -checkName "RDP - Timeout" -checkID "machine_RDP-Timeout" -status $csvSt -finding "RDP timeout is configured - Check manual file to find specific configuration" -risk $csvR4
    } 
    writeToFile -file $outputFile -path $folderLocation -str "============= Raw RDP Settings (from WMI) ============="
    writeToFile -file $outputFile -path $folderLocation -str ($RDP | Format-List Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-String )
}

# search for sensitive information (i.e. cleartext passwords) if the flag exists
function checkSensitiveInfo {
    param (
        $name
    )   
    $outputFile = getNameForFile -name $name -extension ".txt"
    if ($EnableSensitiveInfoSearch)
    {
        writeToLog -str "running checkSensitiveInfo function"
        writeToScreen -str "Searching for sensitive information..." -ForegroundColor Yellow
        writeToFile -file $outputFile -path $folderLocation -str "============= Looking for clear-text passwords ============="
        # recursive searches in c:\temp, current user desktop, default IIS website root folder
        # add any other directory that you want. searching in C:\ may take a while.
        $paths = "C:\Temp",[Environment]::GetFolderPath("Desktop"),"c:\Inetpub\wwwroot"
        foreach ($path in $paths)
        {
            writeToFile -file $outputFile -path $folderLocation -str "============= recursive search in $path ============="
            # find txt\ini\config\xml\vnc files with the word password in it, and dump the line
            # ignore the files outputted during the assessment...
            $includeFileTypes = @("*.txt","*.ini","*.config","*.xml","*vnc*")
            $filesWithPattern = Get-ChildItem -Path $path -Include $includeFileTypes -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$hostname.txt"} | Select-String -Pattern password | Out-String
            writeToFile -file $outputFile -path $folderLocation -str ($filesWithPattern)
            # find files with the name pass\cred\config\vnc\p12\pfx and dump the whole file, unless it is too big
            # ignore the files outputted during the assessment...
            $includeFilePatterns = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
            $files = Get-ChildItem -Path $path -Include $includeFilePatterns -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$hostname.txt"}
            $fileNames = @()
            foreach ($file in $files)
            {
                writeToFile -file $outputFile -path $folderLocation -str "------------- $file -------------"
                $fileSize = (Get-Item $file.FullName).Length
                if ($fileSize -gt 300kb) {writeToFile -file $outputFile -path $folderLocation -str ("The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB).") }
                else {
                    $fileNames += Get-Content $file.FullName
                    writeToFile -file $outputFile -path $folderLocation -str (Get-Content $file.FullName)
                }
            }
            if($null -ne $filesWithPattern -and $filesWithPattern -ne ""){
               addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "No clear-text passwords" -checkID "machine_clearTextPass" -status $csvOp -finding "Clear text passwords where found in: $fileNames" -risk $csvR5 
            }
            else{
               addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "No clear-text passwords" -checkID "machine_clearTextPass" -status $csvSt -finding "No clear text passwords where found" -risk $csvR5 
            }
        }
    }
    else{
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "No clear-text passwords" -checkID "machine_clearTextPass" -status $csvUn -finding "Clear text passwords check has not been preformed" -risk $csvR5 
    }
    
}

# get antivirus status
# partial csv integration
function checkAntiVirusStatus {
    param (
        $name
    )
    writeToLog -str "running checkAntiVirusStatus function"
    $outputFile = getNameForFile -name $name -extension ".txt"
    # works only on Windows Clients, Not on Servers (2008, 2012, etc.). Maybe the "Get-MpPreference" could work on servers - wasn't tested.
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
    {
        writeToScreen -str "Getting Antivirus status..." -ForegroundColor Yellow
        if ($winVersion.Major -ge 6)
        {
            $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
            $FirewallProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct
            $AntiSpywareProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiSpywareProduct
            writeToFile -file $outputFile -path $folderLocation -str "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter2`".`r`n"
        }
        else
        {
            $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct
            $FirewallProducts = Get-WmiObject -Namespace root\SecurityCenter -Class FirewallProduct
            $AntiSpywareProducts = Get-WmiObject -Namespace root\SecurityCenter -Class AntiSpywareProduct
            writeToFile -file $outputFile -path $folderLocation -str "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter`".`r`n"
        }
        if ($null -eq $AntiVirusProducts)
            {
                writeToFile -file $outputFile -path $folderLocation -str "No Anti Virus products were found."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Security" -checkName "AntiVirus installed system" -checkID "machine_AVName" -status $csvOp -finding "No AntiVirus detected on machine."   -risk $csvR5
            }
        writeToFile -file $outputFile -path $folderLocation -str "============= Antivirus Products Status ============="
        $sumOutput = ""
        $outOfDateAV = $false
        $notEnabledAV = $false
        foreach ($av in $AntiVirusProducts)
        {    
            writeToFile -file $outputFile -path $folderLocation -str ("Product Display name: " + $av.displayname )
            writeToFile -file $outputFile -path $folderLocation -str ("Product Executable: " + $av.pathToSignedProductExe )
            writeToFile -file $outputFile -path $folderLocation -str ("Time Stamp: " + $av.timestamp)
            writeToFile -file $outputFile -path $folderLocation -str ("Product (raw) state: " + $av.productState)
            $sumOutput += ("Product Display name: " + $av.displayname ) + "`n" + ("Product Executable: " + $av.pathToSignedProductExe ) + "`n" + ("Time Stamp: " + $av.timestamp) + "`n" + ("Product (raw) state: " + $av.productState)
            # check the product state
            $hx = '0x{0:x}' -f $av.productState
            if ($hx.Substring(3,2) -match "00|01")
                {
                    writeToFile -file $outputFile -path $folderLocation -str "AntiVirus is NOT enabled" 
                    $notEnabledAV = $true
            }
            else
                {writeToFile -file $outputFile -path $folderLocation -str "AntiVirus is enabled"}
            if ($hx.Substring(5) -eq "00")
                {writeToFile -file $outputFile -path $folderLocation -str "Virus definitions are up to date"}
            else
                {
                    writeToFile -file $outputFile -path $folderLocation -str "Virus definitions are NOT up to date"
                    $outOfDateAV = $true
            }
        }
        if($sumOutput -ne ""){
            if($outOfDateAV -and $notEnabledAV){
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Security" -checkName "AntiVirus installed system" -checkID "machine_AVName" -status $csvOp -finding "AntiVirus is not enabled and not up to date `n $sumOutput." -risk $csvR5
            }
            elseif ($outOfDateAV) {
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Security" -checkName "AntiVirus installed system" -checkID "machine_AVName" -status $csvOp -finding "AntiVirus is not up to date `n $sumOutput." -risk $csvR5
            }
            elseif ($notEnabledAV){
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Security" -checkName "AntiVirus installed system" -checkID "machine_AVName" -status $csvOp -finding "AntiVirus is not enabled `n $sumOutput." -risk $csvR5
            }
            else{
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Security" -checkName "AntiVirus installed system" -checkID "machine_AVName" -status $csvSt -finding "AntiVirus is up to date and enabled `n $sumOutput." -risk $csvR5
            }
        }
        
        writeToFile -file $outputFile -path $folderLocation -str "============= Antivirus Products Status (Raw Data) ============="
        writeToFile -file $outputFile -path $folderLocation -str ($AntiVirusProducts |Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "============= Firewall Products Status (Raw Data) =============" 
        writeToFile -file $outputFile -path $folderLocation -str ($FirewallProducts | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "============= Anti-Spyware Products Status (Raw Data) =============" 
        writeToFile -file $outputFile -path $folderLocation -str ($AntiSpywareProducts | Out-String)
        
        # check Windows Defender settings - registry query #not adding this section to csv might be added in the future. 
        writeToFile -file $outputFile -path $folderLocation -str "============= Windows Defender Settings Status =============`r`n"
        $WinDefenderSettings = getRegValue -HKLM $true -regPath "\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        if ($null -eq $WinDefenderSettings)
        {
            writeToFile -file $outputFile -path $folderLocation -str "Could not query registry values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager."
        }
        else
        {
            switch ($WinDefenderSettings.AllowRealtimeMonitoring)
            {
                $null {writeToFile -file $outputFile -path $folderLocation -str "AllowRealtimeMonitoring registry value was not found."}
                0 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Real Time Monitoring is off."}
                1 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Real Time Monitoring is on."}
            }
            switch ($WinDefenderSettings.EnableNetworkProtection)
            {
                $null {writeToFile -file $outputFile -path $folderLocation -str "EnableNetworkProtection registry value was not found."}
                0 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Network Protection is off."}
                1 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Network Protection is on."}
                2 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Network Protection is set to audit mode."}
            }
            writeToFile -file $outputFile -path $folderLocation -str "---------------------------------"
            writeToFile -file $outputFile -path $folderLocation -str "Values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:"
            writeToFile -file $outputFile -path $folderLocation -str ($WinDefenderSettings | Out-String)
            writeToFile -file $outputFile -path $folderLocation -str "---------------------------------" 
        }
        
        # check Windows Defender settings - Get-MpPreference command
        $MpPreference = Get-MpPreference
        writeToFile -file $outputFile -path $folderLocation -str "Raw output of Get-MpPreference (Defender settings):"        
        writeToFile -file $outputFile -path $folderLocation -str ($MpPreference | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "---------------------------------" 
        $MpComputerStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if($null -ne $MpComputerStatus){
            writeToFile -file $outputFile -path $folderLocation -str "Enabled Defender features:" 
            writeToFile -file $outputFile -path $folderLocation -str ($MpComputerStatus | Format-List *enabled* | Out-String)
            writeToFile -file $outputFile -path $folderLocation -str "Defender Tamper Protection:"
            writeToFile -file $outputFile -path $folderLocation -str ($MpComputerStatus | Format-List *tamper* | Out-String)
            writeToFile -file $outputFile -path $folderLocation -str "Raw output of Get-MpComputerStatus:"
            writeToFile -file $outputFile -path $folderLocation -str ($MpComputerStatus | Out-String)
            writeToFile -file $outputFile -path $folderLocation -str "---------------------------------" 
        }
        writeToFile -file $outputFile -path $folderLocation -str "Attack Surface Reduction Rules Ids:"
        writeToFile -file $outputFile -path $folderLocation -str ($MpPreference.AttackSurfaceReductionRules_Ids | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "Attack Surface Reduction Rules Actions:"
        writeToFile -file $outputFile -path $folderLocation -str ($MpPreference.AttackSurfaceReductionRules_Actions | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "Attack Surface Reduction Only Exclusions:" 
        writeToFile -file $outputFile -path $folderLocation -str $MpPreference.AttackSurfaceReductionOnlyExclusions
    }
    else{
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Security" -checkName "AntiVirus installed system" -checkID "machine_AVName" -status $csvUn -finding "AntiVirus test is currently not running on server."   -risk $csvR5
    }
}

# check if LLMNR and NETBIOS-NS are enabled
function checkLLMNRAndNetBIOS {
    param (
        $name
    )
    # LLMNR and NETBIOS-NS are insecure legacy protocols for local multicast DNS queries that can be abused by Responder/Inveigh
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkLLMNRAndNetBIOS function"
    writeToScreen -str "Getting LLMNR and NETBIOS-NS configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= LLMNR Configuration ============="
    writeToFile -file $outputFile -path $folderLocation -str "GPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution"
    $LLMNR = getRegValue -HKLM $true -regPath "\Software\policies\Microsoft\Windows NT\DNSClient" -regName "EnableMulticast"
    $LLMNR_Enabled = $LLMNR.EnableMulticast
    writeToFile -file $outputFile -path $folderLocation -str "Registry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $LLMNR_Enabled"
    if ($LLMNR_Enabled -eq 0)
        {
            writeToFile -file $outputFile -path $folderLocation -str "LLMNR is disabled, which is secure."
            addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "LLMNR" -checkID "domain_LLMNR" -status $csvSt -finding "LLMNR is disabled." -risk $csvR4

    }
    else
        {
            writeToFile -file $outputFile -path $folderLocation -str "LLMNR is enabled, which is a finding, especially for workstations."
            addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "LLMNR" -checkID "domain_LLMNR" -status $csvOp -finding "LLMNR is enabled." -risk $csvR4

        }
        writeToFile -file $outputFile -path $folderLocation -str "============= NETBIOS Name Service Configuration ============="
        writeToFile -file $outputFile -path $folderLocation -str "Checking the NETBIOS Node Type configuration - see 'https://getadmx.com/?Category=KB160177#' for details...`r`n"
        
    $NodeType = (getRegValue -HKLM $true -regPath "\System\CurrentControlSet\Services\NetBT\Parameters" -regName "NodeType").NodeType
    if ($NodeType -eq 2)
        {
            writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to P-node (only point-to-point name queries to a WINS name server), which is secure."
            addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS Node type" -checkID "domain_NetBIOSNT" -status $csvSt -finding "NetBIOS Name Service is disabled (node type set to P-node)." -risk $csvR4
        }
    else
    {
        switch ($NodeType)
        {
            $null {
                writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to the default setting (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS Node type" -checkID "domain_NetBIOSNT" -status $csvOp -finding "NetBIOS Node Type is set to the default setting (broadcast queries)." -risk $csvR4
            }
            1 {
                writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to B-node (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS Node type" -checkID "domain_NetBIOSNT" -status $csvOp -finding "NetBIOS Node Type is set to B-node (broadcast queries)." -risk $csvR4
            }
            4 {
                writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server), which is not secure and a finding."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS Node type" -checkID "domain_NetBIOSNT" -status $csvOp -finding "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server)." -risk $csvR4
            }
            8 {
                writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts), which is not secure and a finding."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS Node type" -checkID "domain_NetBIOSNT" -status $csvOp -finding "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts)." -risk $csvR4
            }        
        }

        writeToFile -file $outputFile -path $folderLocation -str "Checking the NETBIOS over TCP/IP configuration for each network interface."
        writeToFile -file $outputFile -path $folderLocation -str "Network interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting"
        writeToFile -file $outputFile -path $folderLocation -str "`r`nNetbiosOptions=0 is default, and usually means enabled, which is not secure and a possible finding."
        writeToFile -file $outputFile -path $folderLocation -str "NetbiosOptions=1 is enabled, which is not secure and a possible finding."
        writeToFile -file $outputFile -path $folderLocation -str "NetbiosOptions=2 is disabled, which is secure."
        writeToFile -file $outputFile -path $folderLocation -str "If NetbiosOptions is set to 2 for the main interface, NetBIOS Name Service is protected against poisoning attacks even though the NodeType is not set to P-node, and this is not a finding."
        $interfaces = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -regName "NetbiosOptions"
        writeToFile -file $outputFile -path $folderLocation -str ($interfaces | Select-Object PSChildName,NetbiosOptions | Out-String)
        $defaultFlag = $false
        $defaultList = ""
        $enforcedEnabled = $false
        $enforcedEnabledList = ""
        foreach ($item in ($interfaces | Select-Object PSChildName,NetbiosOptions)){
            switch ($item.NetbiosOptions) {
                0 {
                    if($NodeType -ne 2){
                        $defaultFlag = $true
                        if($defaultList -eq ""){
                        $defaultList += $item.PSChildName
                        }
                        else{
                            $defaultList += ", " + $item.PSChildName 
                        }
                    }
                }
                1 {
                    $enforcedEnabled = $true
                    if($enforcedEnabledList -eq ""){
                        $enforcedEnabledList += $item.PSChildName
                    }
                    else{
                        $enforcedEnabledList += ", " + $item.PSChildName
                    }
                }
                2 {
                    #disabled
                }
            }
        }
        if($defaultFlag -and $enforcedEnabled){
            addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS interfaces configuration" -checkID "domain_NetBIOSInt" -status $csvOp -finding "Interfaces NetBIOS is using both vulnerable default setting and enforced enable " -comment "Default NetBIOS setting is applied on:$defaultList and NetBIOS is enabled by force on:$enforcedEnabledList" -risk $csvR4
        }
        elseif ($defaultFlag) {
            addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS interfaces configuration" -checkID "domain_NetBIOSInt" -status $csvOp -finding "Interfaces NetBIOS is using vulnerable default setting" -comment "Default NetBIOS setting is applied on:$defaultList" -risk $csvR4
        }
        elseif ($enforcedEnabled) {
            addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS interfaces configuration" -checkID "domain_NetBIOSInt" -status $csvOp -finding "Interfaces are enforced to enable NetBIOS" -comment "NetBIOS is enabled by force on:$enforcedEnabledList" -risk $csvR4
        }
        else{
            addToCSV -relatedFile $outputFile -category "Domain Hardening - Network" -checkName "NetBIOS interfaces configuration" -checkID "domain_NetBIOSInt" -status $csvSt -finding "Interfaces NetBIOS is configured with secure default or disabled" -risk $csvR4
        }
    }
    
}

# check if cleartext credentials are saved in lsass memory for WDigest
function checkWDigest {
    param (
        $name
    )

    # turned on by default for Win7/2008/8/2012, to fix it you must install kb2871997 and than fix the registry value below
    # turned off by default for Win8.1/2012R2 and above
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkWDigest function"
    writeToScreen -str "Getting WDigest credentials configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= WDigest Configuration ============="
    $WDigest = getRegValue -HKLM $true -regPath "\System\CurrentControlSet\Control\SecurityProviders\WDigest" -regName "UseLogonCredential"
    if ($null -eq $WDigest)
    {
        writeToFile -file $outputFile -path $folderLocation -str "WDigest UseLogonCredential registry value wasn't found."
        # check if running on Windows 6.3 or above
        if (($winVersion.Major -ge 10) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -eq 3)))
            {
                writeToFile -file $outputFile -path $folderLocation -str  "The WDigest protocol is turned off by default for Win8.1/2012R2 and above. So it is OK, but still recommended to set the UseLogonCredential registry value to 0, to revert malicious attempts of enabling WDigest."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "WDigest Clear-Text passwords in LSASS" -checkID "domain_WDigest" -status $csvSt -comment "The WDigest protocol is turned off by default for Win8.1/2012R2 and above." -risk $csvR5
            }
        else
        {
            # check if running on Windows 6.1/6.2, which can be hardened, or on older version
            if (($winVersion.Major -eq 6) -and ($winVersion.Minor -ge 1))    
                {
                    writeToFile -file $outputFile -path $folderLocation -str "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding."
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "WDigest Clear-Text passwords in LSASS" -checkID "domain_WDigest" -status $csvOp -finding "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012." -risk $csvR5
                }
            else
            {
                writeToFile -file $outputFile -path $folderLocation -str "The operating system version is not supported. You have worse problems than WDigest configuration."
                writeToFile -file $outputFile -path $folderLocation -str "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "WDigest Clear-Text passwords in LSASS" -checkID "domain_WDigest" -status $csvOp -finding "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS." -risk $csvR5

            }
        }
    }
    else
    {    
        if ($WDigest.UseLogonCredential -eq 0)
        {
            writeToFile -file $outputFile -path $folderLocation -str "WDigest UseLogonCredential registry key set to 0."
            writeToFile -file $outputFile -path $folderLocation -str "WDigest doesn't store cleartext user credentials in memory, which is good. The setting was intentionally hardened."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "WDigest Clear-Text passwords in LSASS" -checkID "domain_WDigest" -status $csvSt -finding "WDigest doesn't store cleartext user credentials in memory." -risk $csvR5

        }
        if ($WDigest.UseLogonCredential -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "WDigest UseLogonCredential registry key set to 1."
            writeToFile -file $outputFile -path $folderLocation -str "WDigest stores cleartext user credentials in memory, which is bad and a finding. The configuration was either intentionally configured by an admin for some reason, or was set by a threat actor to fetch clear-text credentials."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "WDigest Clear-Text passwords in LSASS" -checkID "domain_WDigest" -status $csvOp -finding "WDigest stores cleartext user credentials in memory." -risk $csvR5
        }
    }
    
}

# check for Net Session enumeration permissions
function checkNetSessionEnum {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    if($isDomainController){
        $currentRisk = $csvR5
    }
    else{
        $currentRisk = $csvR3
    }
    writeToLog -str "running checkNetSessionEnum function"
    writeToScreen -str "Getting NetSession configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= NetSession Configuration ============="
    writeToFile -file $outputFile -path $folderLocation -str "By default, on Windows 2016 (and below) and old builds of Windows 10, any authenticated user can enumerate the SMB sessions on a computer, which is a major vulnerability mainly on Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $outputFile -path $folderLocation -str "See more details here:"
    writeToFile -file $outputFile -path $folderLocation -str "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b"
    writeToFile -file $outputFile -path $folderLocation -str "https://www.powershellgallery.com/packages/NetCease/1.0.3"
    writeToFile -file $outputFile -path $folderLocation -str "--------- Security Descriptor Check ---------"
    # copied from Get-NetSessionEnumPermission
    writeToFile -file $outputFile -path $folderLocation -str "Below are the permissions granted to enumerate net sessions."
    writeToFile -file $outputFile -path $folderLocation -str "If the Authenticated Users group has permissions, this is a finding.`r`n"
    $SessionRegValue = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" -regName "SrvsvcSessionInfo"
    $SessionRegValue = $SessionRegValue.SrvsvcSessionInfo
    $SecurityDesc = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($true,$false,$SessionRegValue,0)
    $SecurityDescList = $SecurityDesc.DiscretionaryAcl | ForEach-Object {$_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru}
    writeToFile -file $outputFile -path $folderLocation -str ($SecurityDescList | Out-String)
    $flag = $false
    foreach ($item in $SecurityDescList){
        if($item.TranslatedSID -like "*Authenticated Users*"){
            $flag = $true
        }
    }
    if($flag){
        addToCSV -relatedFile $outputFile -category "Domain Hardening - Enumeration" -checkName "NetSession enumeration permissions" -checkID "domain_NetSessionEnum" -status $csvOp -finding "Net session enumeration permissions are not hardened - Authenticated user can enumerate the SMB sessions on this computer" -comment "This is a major vulnerability mainly on Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound." -risk $currentRisk
    }
    else{
        addToCSV -relatedFile $outputFile -category "Domain Hardening - Enumeration" -checkName "NetSession enumeration permissions" -checkID "domain_NetSessionEnum" -status $csvOp -finding "Net session enumeration permissions are hardened - Authenticated user cannot enumerate the SMB sessions on this computer" -risk $currentRisk
    }
    writeToFile -file $outputFile -path $folderLocation -str "--------- Raw Registry Value Check ---------" 
    writeToFile -file $outputFile -path $folderLocation -str "For comparison, below are the beginning of example values of the SrvsvcSessionInfo registry key, which holds the ACL for NetSessionEnum:"
    writeToFile -file $outputFile -path $folderLocation -str "Default value for Windows 2019 and newer builds of Windows 10 (hardened): 1,0,4,128,160,0,0,0,172"
    writeToFile -file $outputFile -path $folderLocation -str "Default value for Windows 2016, older builds of Windows 10 and older OS versions (not secure - finding): 1,0,4,128,120,0,0,0,132"
    writeToFile -file $outputFile -path $folderLocation -str "Value after running NetCease (hardened): 1,0,4,128,20,0,0,0,32"
    writeToFile -file $outputFile -path $folderLocation -str "`r`nThe SrvsvcSessionInfo registry value under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity is set to:"
    $test = ($SessionRegValue | Out-String).trim() -replace("`r`n",",")
    writeToFile -file $outputFile -path $folderLocation -str $test
}

# check for SAM enumeration permissions
function checkSAMEnum{
    param(
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkSAMEnum function"
    writeToScreen -str "Getting SAM enumeration configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= Remote SAM (SAMR) Configuration ============="
    writeToFile -file $outputFile -path $folderLocation -str "`r`nBy default, in Windows 2016 (and above) and Windows 10 build 1607 (and above), only Administrators are allowed to make remote calls to SAM with the SAMRPC protocols, and (among other things) enumerate the members of the local groups."
    writeToFile -file $outputFile -path $folderLocation -str "However, in older OS versions, low privileged domain users can also query the SAM with SAMRPC, which is a major vulnerability mainly on non-Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $outputFile -path $folderLocation -str "These old OS versions (Windows 7/2008R2 and above) can be hardened by installing a KB and configuring only the Local Administrators group in the following GPO policy: 'Network access: Restrict clients allowed to make remote calls to SAM'."
    writeToFile -file $outputFile -path $folderLocation -str "The newer OS versions are also recommended to be configured with the policy, though it is not essential."
    writeToFile -file $outputFile -path $folderLocation -str "`r`nSee more details here:"
    writeToFile -file $outputFile -path $folderLocation -str "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    writeToFile -file $outputFile -path $folderLocation -str "https://blog.stealthbits.com/making-internal-reconnaissance-harder-using-netcease-and-samri1o"
    writeToFile -file $outputFile -path $folderLocation -str "`r`n----------------------------------------------------"
    $RestrictRemoteSAM = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Control\Lsa" -regName "RestrictRemoteSAM"
    if ($null -eq $RestrictRemoteSAM)
    {
        writeToFile -file $outputFile -path $folderLocation -str "The 'RestrictRemoteSAM' registry value was not found. SAM enumeration permissions are configured as the default for the OS version, which is $winVersion."
        if (($winVersion.Major -ge 10) -and ($winVersion.Build -ge 14393))
            {
                writeToFile -file $outputFile -path $folderLocation -str "This OS version is hardened by default."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - Enumeration" -checkName "SAM enumeration permissions" -checkID "domain_SAMEnum" -status $csvSt -comment "Remote SAM enumeration permissions are hardened, as the default OS settings." -risk $csvR4
        }
        else
            {
                writeToFile -file $outputFile -path $folderLocation -str "This OS version is not hardened by default and this issue can be seen as a finding."
                addToCSV -relatedFile $outputFile -category "Domain Hardening - Enumeration" -checkName "SAM enumeration permissions" -checkID "domain_SAMEnum" -status $csvOp -finding "Using default settings - this OS version is not hardened by default." -risk $csvR4
            }
    }
    else
    {
        $RestrictRemoteSAMValue = $RestrictRemoteSAM.RestrictRemoteSAM
        writeToFile -file $outputFile -path $folderLocation -str "The 'RestrictRemoteSAM' registry value is set to: $RestrictRemoteSAMValue"
        $RestrictRemoteSAMPermissions = ConvertFrom-SDDLString -Sddl $RestrictRemoteSAMValue
        writeToFile -file $outputFile -path $folderLocation -str "Below are the permissions for SAM enumeration. Make sure that only Administrators are granted Read permissions."
        writeToFile -file $outputFile -path $folderLocation -str ($RestrictRemoteSAMPermissions | Out-String)
        addToCSV -relatedFile $outputFile -category "Domain Hardening - Enumeration" -checkName "SAM enumeration permissions" -checkID "domain_SAMEnum" -status $csvUn -finding "RestrictRemoteSAM configuration existing please go to the full result to make sure that only Administrators are granted Read permissions." -risk $csvR4
    }
}


# check for PowerShell v2 installation, which lacks security features (logging, AMSI)
function checkPowershellVer {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkPowershellVer function"
    writeToScreen -str "Getting PowerShell versions..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "PowerShell 1/2 are legacy versions which don't support logging and AMSI."
    writeToFile -file $outputFile -path $folderLocation -str "It's recommended to uninstall legacy PowerShell versions and make sure that only PowerShell 5+ is installed."
    writeToFile -file $outputFile -path $folderLocation -str "See the following article for details on PowerShell downgrade attacks: https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks" 
    writeToFile -file $outputFile -path $folderLocation -str ("This script is running on PowerShell version " + $PSVersionTable.PSVersion.ToString())
    # Checking if PowerShell Version 2/5 are installed, by trying to run command (Get-Host) with PowerShellv2 and v5 Engine.
    writeToFile -file $outputFile -path $folderLocation -str "============= Running Test Commands ============="
    try
    {
        $temp = Start-Job {Get-Host} -PSVersion 2.0 -Name "PSv2Check"
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell version 2 is installed and was able to run commands. This is a finding!"
        #addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Powershell version 2 support - 1" -checkID "machine_PSv2.1" -status $csvOp -finding "PowerShell version 2 is installed and was able to run commands." -risk $csvR4
    }
    catch
    {
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell version 2 was not able to run. This is secure."
        #addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Powershell version 2 support - 1" -checkID "machine_PSv2.1" -status $csvSt -finding "PowerShell version 2 was not able to run." -risk $csvR4
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # same as above, for PSv5
    try
    {
        $temp = Start-Job {Get-Host} -PSVersion 5.0 -Name "PSv5Check"
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell version 5 is installed and was able to run commands." 
    }
    catch
    {
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell version 5 was not able to run."
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # use Get-WindowsFeature if running on Windows SERVER 2008R2 or above and powershell is equal or above version 4
    if ($psVer -ge 4 -and (($winVersion.Major -ge 7) -or (($winVersion.Major -ge 6) -and ($winVersion.Minor -ge 1)))) # version should be 7+ or 6.1+
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3)) # type should be server or DC
        {
            writeToFile -file $outputFile -path $folderLocation -str "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsFeature =============" 
            writeToFile -file $outputFile -path $folderLocation -str (Get-WindowsFeature -Name PowerShell-V2 | Out-String)
        }    
    }
    else {
        writeToLog -str "Function checkPowershellVer: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
    }
    # use Get-WindowsOptionalFeature if running on Windows 8/2012 or above, and running as admin and powershell is equal or above version 4
    if ($psVer -ge 4 -and (($winVersion.Major -gt 6) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -ge 2)))) # version should be 6.2+
    {    
        writeToFile -file $outputFile -path $folderLocation -str "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsOptionalFeature =============" 
        if ($runningAsAdmin)
        {
            writeToFile -file $outputFile -path $folderLocation -str (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | Format-Table DisplayName, State -AutoSize | Out-String)
        }
        else
        {
            writeToFile -file $outputFile -path $folderLocation -str "Cannot run Get-WindowsOptionalFeature when non running as admin." 
        }
    }
    else {
        writeToLog -str "Function checkPowershellVer: unable to run Get-WindowsOptionalFeature - require windows server 8/2012R2 and above and powershell version 4"
    }
    # run registry check
    writeToFile -file $outputFile -path $folderLocation -str "============= Registry Check =============" 
    writeToFile -file $outputFile -path $folderLocation -str "Based on the registry value described in the following article:"
    writeToFile -file $outputFile -path $folderLocation -str "https://devblogs.microsoft.com/powershell/detection-logic-for-powershell-installation"
    $LegacyPowerShell = getRegValue -HKLM $true -regPath "\Software\Microsoft\PowerShell\1\PowerShellEngine" -regName "PowerShellVersion"
    if (($LegacyPowerShell.PowerShellVersion -eq "2.0") -or ($LegacyPowerShell.PowerShellVersion -eq "1.0"))
    {
        writeToFile -file $outputFile -path $folderLocation -str ("PowerShell version " + $LegacyPowerShell.PowerShellVersion + " is installed, based on the registry value mentioned above.")
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Powershell version 2 support - 2" -checkID "machine_PSv2" -status $csvOp -finding ("PowerShell version " + $LegacyPowerShell.PowerShellVersion + " is installed, based on the registry value.") -risk $csvR4
    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell version 1/2 is not installed." 
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Powershell version 2 support - 2" -checkID "machine_PSv2" -status $csvSt -finding ("PowerShell version 1/2 is not installed.") -risk $csvR4
    }
    
}

# NTLMv2 enforcement check - check if there is a GPO that enforce the use of NTLMv2 (checking registry)
function checkNTLMv2 {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkNTLMv2 function"
    writeToScreen -str "Getting NTLM version configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= NTLM Version Configuration ============="
    writeToFile -file $outputFile -path $folderLocation -str "NTLMv1 & LM are legacy authentication protocols that are reversible and can be exploited for all kinds of attacks, including RCE. For example, see: https://github.com/NotMedic/NetNTLMtoSilverTicket"
    writeToFile -file $outputFile -path $folderLocation -str "If there are specific legacy systems in the domain that may need NTLMv1 and LM, configure Level 3 NTLM hardening on the Domain Controllers - this way only the legacy system will use the legacy authentication. Otherwise, select Level 5 on Domain Controllers - so they will refuse NTLMv1 and LM attempts. For the member servers - ensure at least Level 3."
    writeToFile -file $outputFile -path $folderLocation -str "For more information, see: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication `r`n"
    $temp = getRegValue -HKLM $true -regPath "\SYSTEM\CurrentControlSet\Control\Lsa" -regName "LmCompatibilityLevel"
    if(!($partOfDomain)){
        writeToFile -file $outputFile -path $folderLocation -str " > Machine is not part of a domain." #using system default depends on OS version
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $csvSt -finding "Machine is not part of a domain." -risk $csvR1
    }
    else{
        if($isDomainController){
            $statusLevel34 = $csvOp
            $riskLevel34 = $csvR2
        }
        else{
            $statusLevel34 = $csvSt
            $riskLevel34 = $csvR2
        }
        if($null -eq $temp){
            writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3), which is quite secure. `r`n" #using system default depends on OS version
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $csvSt -finding "NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3)." -risk $csvR4
        }
        else{
            switch ($temp.lmcompatibilitylevel) {
                (0) { 
                    writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level 0) Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $csvOp -finding "Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security. (Level 0)" -risk $csvR4
                }
                (1) { 
                    writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level 1) Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $csvOp -finding "Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 1)" -risk $csvR4
                }
                (2) { 
                    writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level 2) Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $csvOp -finding "Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 2)" -risk $csvR4
                }
                (3) { 
                    writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level 3) Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - Not a finding if all servers are with the same configuration.`r`n"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $statusLevel34 -finding "Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it.(Level 3)" -risk $riskLevel34
                }
                (4) { 
                    writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level 4) Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2) - Not a finding if all servers are with the same configuration. If this is a DC, it means that LM is not applicable in the domain at all.`r`n"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $statusLevel34 -finding "Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 4)" -risk $riskLevel34
                }
                (5) { 
                    writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level 5) Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2 - This is the most hardened configuration. If this is a DC, it means that NTLMv2 and LM are not applicable in the domain at all.)`r`n"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $csvSt -finding "Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it.(Level 5)" -risk $csvR4
                }
                Default {
                    writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authentication setting: (Level Unknown) - " + $temp.lmcompatibilitylevel + "`r`n"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "NTLM compatibility level" -checkID "domain_NTLMComLevel" -status $csvUn -finding ("(Level Unknown) :" + $temp.lmcompatibilitylevel +".")  -risk $csvR4

                }
            }
        }
    }
}


# GPO reprocess check - need to explain more
function checkGPOReprocess {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkGPOReprocess function"
    writeToScreen -str "Getting GPO reprocess configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= GPO Reprocess Check ============="
    writeToFile -file $outputFile -path $folderLocation -str "If GPO reprocess is not enabled, the GPO settings can be overridden locally by an administrator. Upon the next gpupdate process, the GPO settings will not be reapplied, until the next GPO change."
    writeToFile -file $outputFile -path $folderLocation -str "It is recommended that all security settings will be repossessed (reapplied) every time the system checks for GPO change, even if there were no GPO changes."
    writeToFile -file $outputFile -path $folderLocation -str "For more information, see: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448`r`n"
    
    # checking registry that contains registry policy reprocess settings
    $temp = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -regName "NoGPOListChanges"
    if ($null -eq $temp) {
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO registry policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Registry policy" -checkID "domain_GPOReRegistry" -status $csvSt -finding "GPO registry policy reprocess is not configured." -risk $csvR3
    }
    else {
        if ($temp.NoGPOListChanges -eq 0) {
            writeToFile -file $outputFile -path $folderLocation -str ' > GPO registry policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Registry policy" -checkID "domain_GPOReRegistry" -status $csvSt -finding "GPO registry policy reprocess is enabled." -risk $csvR3

        }
        else {
            writeToFile -file $outputFile -path $folderLocation -str ' > GPO registry policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Registry policy" -checkID "domain_GPOReRegistry" -status $csvOp -finding "GPO registry policy reprocess is disabled (this setting was set on purpose)." -risk $csvR3

        }
    }

    # checking registry that contains script policy reprocess settings
    $temp = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\Group Policy\{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" -regName "NoGPOListChanges"
    if ($null -eq $temp) {
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO script policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Script policy" -checkID "domain_GPOReScript" -status $csvOp -finding "GPO script policy reprocess is not configured." -risk $csvR3
    }
    else {
        if ($temp.NoGPOListChanges -eq 0) {
            writeToFile -file $outputFile -path $folderLocation -str ' > GPO script policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Script policy" -checkID "domain_GPOReScript" -status $csvSt -finding "GPO script policy reprocess is enabled." -risk $csvR3
        }
        else {
            writeToFile -file $outputFile -path $folderLocation -str ' > GPO script policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Script policy" -checkID "domain_GPOReScript" -status $csvOp -finding "GPO script policy reprocess is disabled (this setting was set on purpose)." -risk $csvR3
        }
    }

    # checking registry that contains security policy reprocess settings 
    $temp = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -regName "NoGPOListChanges"
    if ($null -eq $temp) {
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO security policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Security policy" -checkID "domain_GPOReSecurity" -status $csvOp -finding "GPO security policy reprocess is not configured." -risk $csvR3
    }
    else {
        if ($temp.NoGPOListChanges -eq 0) {
            writeToFile -file $outputFile -path $folderLocation -str ' > GPO security policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Security policy" -checkID "domain_GPOReSecurity" -status $csvSt -finding "GPO security policy reprocess is enabled." -risk $csvR3
        }
        else {
            writeToFile -file $outputFile -path $folderLocation -str ' > GPO security policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $outputFile -category "Domain Hardening - General" -checkName "GPO reprocess enforcement - Security policy" -checkID "domain_GPOReSecurity" -status $csvOp -finding "GPO security policy reprocess is disabled (this setting was set on purpose)." -risk $csvR3
        }
    }    
}

# Check always install elevated setting
function checkInstallElevated {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkInstallElevated function"
    writeToScreen -str "Getting Always install with elevation setting..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Always install elevated Check ============="
    writeToFile -file $outputFile -path $folderLocation -str "Checking if GPO is configured to force installation as administrator - can be used by an attacker to escalate permissions."
    writeToFile -file $outputFile -path $folderLocation -str "For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated`r`n"    
    $temp = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\Installer" -regName "AlwaysInstallElevated"
    if($null -eq $temp){
        writeToFile -file $outputFile -path $folderLocation -str ' > No GPO settings exist for "Always install with elevation" - this is good.'
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Always install with elevated privileges" -checkID "machine_installWithElevation" -status $csvSt -finding "No GPO settings exist for `"Always install with elevation`"." -risk $csvR3
    }
    elseif ($temp.AlwaysInstallElevated -eq 1) {
        writeToFile -file $outputFile -path $folderLocation -str ' > Always install with elevated is enabled - this is a finding!'
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Always install with elevated privileges" -checkID "machine_installWithElevation" -status $csvOp -finding "Always install with elevated is enabled." -risk $csvR3

    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO for "Always install with elevated" exists but not enforcing installing with elevation - this is good.'
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Always install with elevated privileges" -checkID "machine_installWithElevation" -status $csvSt -finding "GPO for 'Always install with elevated' exists but not enforcing installing with elevation." -risk $csvR3
    }    
}

# Powershell Logging settings check
function checkPowerShellAudit {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkPowershellAudit function"
    writeToScreen -str "Getting PowerShell logging policies..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= PowerShell Audit ============="
    writeToFile -file $outputFile -path $folderLocation -str "PowerShell Logging is configured by three main settings: Module Logging, Script Block Logging and Transcription:"
    writeToFile -file $outputFile -path $folderLocation -str " - Module Logging - audits the modules used in PowerShell commands\scripts."
    writeToFile -file $outputFile -path $folderLocation -str " - Script Block - audits the use of script block in PowerShell commands\scripts."
    writeToFile -file $outputFile -path $folderLocation -str " - Transcript - audits the commands running in PowerShell."
    writeToFile -file $outputFile -path $folderLocation -str " - For more information, see: https://www.mandiant.com/resources/greater-visibilityt"
    writeToFile -file $outputFile -path $folderLocation -str "For comprehensive audit trail all of those need to be configured and each of them has a special setting that need to be configured to work properly (for example in Module Logging you need to specify which modules to audit).`r`n"
    # --- Start Of Module Logging ---
    writeToFile -file $outputFile -path $folderLocation -str "--- PowerShell Module audit: "
    $temp = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -regName "EnableModuleLogging"
    if($null -eq $temp){
        $temp = getRegValue -HKLM $false -regPath "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -regName "EnableModuleLogging"
        if($null -ne $temp -and $temp.EnableModuleLogging -eq 1){
            $booltest = $false
            $temp2 = getRegValue -HKLM $false -regPath "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
            }
            if(!$booltest){
                writeToFile -file $outputFile -path $folderLocation -str  " > PowerShell - Module Logging is enabled on all modules but only on the user."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Modules" -checkID "machine_PSModuleLog" -status $csvSt -finding "Powershell Module Logging is enabled on all modules (Only on current user)." -risk $csvR4

            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module logging is enabled only on the user and not on all modules."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Modules" -checkID "machine_PSModuleLog" -status $csvOp -finding "Powershell Module Logging is not enabled on all modules (Configuration is only on user) - (please check the script output for more information)." -risk $csvR4
                writeToFile -file $outputFile -path $folderLocation -str ($temp2 | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
            } 
        }
        else {
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module Logging is not enabled."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Modules" -checkID "machine_PSModuleLog" -status $csvOp -finding "PowerShell Module logging is not enabled."  -risk $csvR4

        }
    }
    elseif($temp.EnableModuleLogging -eq 1){
        $booltest = $false
        $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
        foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
            if($item -eq "*"){
                $booltest = $True
            }
        }
        if(!$booltest){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module Logging is not enabled on all modules:" 
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Modules" -checkID "machine_PSModuleLog" -status $csvOp -finding "Powershell Module Logging is not enabled on all modules (please check the script output for more information)." -risk $csvR4
            writeToFile -file $outputFile -path $folderLocation -str ($temp2 | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module Logging is enabled on all modules."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Modules" -checkID "machine_PSModuleLog" -status $csvSt -finding "Powershell Module Logging is enabled on all modules." -risk $csvR4
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module logging is not enabled!"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Modules" -checkID "machine_PSModuleLog" -status $csvOp -finding "PowerShell Module logging is not enabled." -risk $csvR4
    }

    # --- End Of Module Logging ---
    # --- Start of ScriptBlock logging
    writeToFile -file $outputFile -path $folderLocation -str "--- PowerShell Script block logging: "
    $temp = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -regName "EnableScriptBlockLogging"
    if($null -eq $temp -or $temp.EnableScriptBlockLogging -ne 1){
        $temp = getRegValue -HKLM $false -regPath "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -regName "EnableScriptBlockLogging"

        if($null -ne $temp -and $temp.EnableScriptBlockLogging -eq 1){
            $temp2 = getRegValue -HKLM $false -regPath "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -regName "EnableScriptBlockInvocationLogging"
            if($null -eq $temp2 -or $temp2.EnableScriptBlockInvocationLogging -ne 1){
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block Logging is enabled but Invocation logging is not enabled - only on user." 
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Script Block" -checkID "machine_PSScriptBlock" -status $csvSt -finding "Script Block Logging is enabled but Invocation logging is not enabled (Only on user)." -risk $csvR4
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block Logging is enabled - only on user."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Script Block" -checkID "machine_PSScriptBlock" -status $csvSt -finding "PowerShell Script Block Logging is enabled (Only on current user)." -risk $csvR4

            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block Logging is not enabled!"
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Script Block" -checkID "machine_PSScriptBlock" -status $csvOp -finding "PowerShell Script Block Logging is disabled." -risk $csvR4
        }
    }
    else{
        $temp2 = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -regName "EnableScriptBlockInvocationLogging"
        if($null -eq $temp2 -or $temp2.EnableScriptBlockInvocationLogging -ne 1){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block Logging is enabled but Invocation logging is not."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Script Block" -checkID "machine_PSScriptBlock" -status $csvSt -finding "PowerShell Script Block logging is enabled but Invocation logging is not." -risk $csvR4
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block Logging is enabled."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Script Block" -checkID "machine_PSScriptBlock" -status $csvSt -finding "PowerShell Script Block Logging is enabled." -risk $csvR4

        }
    }
    # --- End of ScriptBlock logging
    # --- Start Transcription logging 
    writeToFile -file $outputFile -path $folderLocation -str "--- PowerShell Transcription logging:"
    $temp = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -regName "EnableTranscripting"
    $bollCheck = $false
    if($null -eq $temp -or $temp.EnableTranscripting -ne 1){
        $temp = getRegValue -HKLM $false -regPath "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -regName "EnableTranscripting"
        if($null -ne $temp -and $temp.EnableTranscripting -eq 1){
            $temp2 = getRegValue -HKLM $false -regPath "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -regName "EnableInvocationHeader"
            if($null -eq $temp2 -or $temp2.EnableInvocationHeader -ne 1){
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled but Invocation Header logging is not."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Transcription" -checkID "machine_PSTranscript" -status $csvOp -finding "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced. (Only on current user)" -risk $csvR3
                $bollCheck = $True
            }
            $temp2 = getRegValue -HKLM $false -regPath "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -regName "OutputDirectory"
            if($null -eq $temp2 -or $temp2.OutputDirectory -eq ""){
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled but no folder is set to save the log."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Transcription" -checkID "machine_PSTranscript" -status $csvOp -finding "PowerShell Transcription logging is enabled but no folder is set to save the log. (Only on current user)" -risk $csvR3
                $bollCheck = $True
            }
            if(!$bollCheck){
                writeToFile -file $outputFile -path $folderLocation -str " > Powershell - Transcription logging is enabled correctly but only on the user."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Transcription" -checkID "machine_PSTranscript" -status $csvSt -finding "PowerShell Transcription logging is enabled and configured correctly. (Only on current user)" -risk $csvR3
                $bollCheck = $True
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is not enabled (logging input and output of PowerShell commands)."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Transcription" -checkID "machine_PSTranscript" -status $csvOp -finding "PowerShell Transcription logging is not enabled." -risk $csvR3
            $bollCheck = $True
        }
    }
    else{
        $temp2 = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -regName "EnableInvocationHeader"
        if($null -eq $temp2 -or $temp2.EnableInvocationHeader -ne 1){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced." 
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Transcription" -checkID "machine_PSTranscript" -status $csvOp -finding "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced." -risk $csvR3
            $bollCheck = $True
        }
        $temp2 = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -regName "OutputDirectory"
        if($null -eq $temp2 -or $temp2.OutputDirectory -eq ""){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled but no folder is set to save the log." 
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Transcription" -checkID "machine_PSTranscript" -status $csvOp -finding "PowerShell Transcription logging is enabled but no folder is set to save the log." -risk $csvR3
            $bollCheck = $True
        }
    }
    if(!$bollCheck){
        writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled and configured correctly." 
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "PowerShell Logging - Transcription" -checkID "machine_PSTranscript" -status $csvSt -finding "PowerShell Transcription logging is enabled and configured correctly." -risk $csvR3
    }
    
}

#check if command line audit is enabled
function checkCommandLineAudit {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkCommandLineAudit function"
    writeToScreen -str "Getting command line audit configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Command line process auditing ============="
    writeToFile -file $outputFile -path $folderLocation -str "Command line process auditing tracks all commands running in the CLI."
    writeToFile -file $outputFile -path $folderLocation -str "Supported Windows versions are 8/2012R2 and above."
    writeToFile -file $outputFile -path $folderLocation -str "For more information, see:"
    writeToFile -file $outputFile -path $folderLocation -str "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing"
    writeToFile -file $outputFile -path $folderLocation -str "https://www.stigviewer.com/stig/windows_8_8.1/2014-04-02/finding/V-43239`n"
    $reg = getRegValue -HKLM $true -regPath "\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -regName "ProcessCreationIncludeCmdLine_Enabled"
    if ((($winVersion.Major -ge 7) -or ($winVersion.Minor -ge 2))){
        if($null -eq $reg){
            writeToFile -file $outputFile -path $folderLocation -str " > Command line process auditing policy is not configured - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Command line process auditing" -checkID "machine_ComLineLog" -status $csvOp -finding "Command line process auditing policy is not configured." -risk $csvR3
        }
        elseif($reg.ProcessCreationIncludeCmdLine_Enabled -ne 1){
            writeToFile -file $outputFile -path $folderLocation -str " > Command line process auditing policy is not configured correctly - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Command line process auditing" -checkID "machine_ComLineLog" -status $csvOp -finding "Command line process auditing policy is not configured correctly." -risk $csvR3
        }
        else{
            if($runningAsAdmin)
            {
                $test = auditpol /get /category:*
                foreach ($item in $test){
                    if($item -like "*Process Creation*No Auditing"){
                        writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured) - this can be considered a finding." 
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Command line process auditing" -checkID "machine_ComLineLog" -status $csvOp -finding "Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured)." -risk $csvR3
                    }
                    elseif ($item -like "*Process Creation*") {
                        writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is configured correctly - this is the hardened configuration."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Command line process auditing" -checkID "machine_ComLineLog" -status $csvSt -finding "Command line audit policy is configured correctly." -risk $csvR3
                    }
                }
            }
            else{
                writeToLog -str "Function checkCommandLineAudit: unable to run auditpol command to check audit policy - not running as elevated admin."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Command line process auditing" -checkID "machine_ComLineLog" -status $csvUn -finding "Unable to run auditpol command to check audit policy (Test did not run in elevation)." -risk $csvR3
            }
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is not supported in this OS (legacy version) - this is bad..." 
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Command line process auditing" -checkID "machine_ComLineLog" -status $csvOp -finding "Command line audit policy is not supported in this OS (legacy version)." -risk $csvR3
    }
}

# check log file size configuration
function checkLogSize {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkLogSize function"
    writeToScreen -str "Getting Event Log size configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= log size configuration ============="
    $applicationLogMaxSize = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\EventLog\Application" -regName "MaxSize"
    $securityLogMaxSize = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\EventLog\Security" -regName "MaxSize"
    $setupLogMaxSize = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\EventLog\Setup" -regName "MaxSize"
    $systemLogMaxSize = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\EventLog\System" -regName "MaxSize"
    $setupLogging = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\EventLog\Setup" -regName "Enabled"

    writeToFile -file $outputFile -path $folderLocation -str "`r`n--- Application ---"
    if($null -ne $applicationLogMaxSize){
        
        $size = "MB"
        $Calc = [double]::Parse($applicationLogMaxSize.MaxSize) / 1024
        $Calc = [Math]::Ceiling($Calc)
        if($Calc -ge 1024){
            $Calc = $Calc / 1024
            $Calc = [Math]::Ceiling($Calc)
            $size = "GB"
        }

        $size = $Calc.tostring() + $size
        writeToFile -file $outputFile -path $folderLocation -str " > Application maximum log file is $size"
        if($applicationLogMaxSize.MaxSize -lt 32768){
            writeToFile -file $outputFile -path $folderLocation -str " > Application maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Application events maximum log file size" -checkID "machine_AppMaxLog" -status $csvOp -finding "Application maximum log file size is: $size this is smaller then the recommendation (32768KB)." -risk $csvR3

        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Application maximum log file size is equal or larger then 32768KB - this is good."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Application events maximum log file size" -checkID "machine_AppMaxLog" -status $csvSt -finding "Application maximum log file size is: $size this is equal or larger then 32768KB." -risk $csvR3
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > Application maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Application events maximum log file size" -checkID "machine_AppMaxLog" -status $csvOp -finding "Application maximum log file is not configured, the default is 1MB." -risk $csvR3
    }

    writeToFile -file $outputFile -path $folderLocation -str "`r`n--- System ---"
    if($null -ne $systemLogMaxSize){
        
        $size = "MB"
        $Calc = [double]::Parse($systemLogMaxSize.MaxSize) / 1024
        $Calc = [Math]::Ceiling($Calc)
        if($Calc -ge 1024){
            $Calc = $Calc / 1024
            $Calc = [Math]::Ceiling($Calc)
            $size = "GB"
        }
        $size = $Calc.tostring() + $size
        writeToFile -file $outputFile -path $folderLocation -str " > System maximum log file is $size"
        if($systemLogMaxSize.MaxSize -lt 32768){
            writeToFile -file $outputFile -path $folderLocation -str " > System maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "System events maximum log file size" -checkID "machine_SysMaxLog" -status $csvOp -finding "System maximum log file size is:$size this is smaller then the recommendation (32768KB)." -risk $csvR3
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > System maximum log file size is equal or larger then (32768KB) - this is good."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "System events maximum log file size" -checkID "machine_SysMaxLog" -status $csvSt -finding "System maximum log file size is:$size this is equal or larger then (32768KB)." -risk $csvR3
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > System maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "System events maximum log file size" -checkID "machine_SysMaxLog" -status $csvOp -finding "System maximum log file is not configured, the default is 1MB." -risk $csvR3
    }

    writeToFile -file $outputFile -path $folderLocation -str "`r`n--- Security ---"
    if($null -ne $securityLogMaxSize){
        
        $size = "MB"
        $Calc = [double]::Parse($securityLogMaxSize.MaxSize) / 1024
        $Calc = [Math]::Ceiling($Calc)
        if($Calc -ge 1024){
            $Calc = $Calc / 1024
            $Calc = [Math]::Ceiling($Calc)
            $size = "GB"
        }
        $size = $Calc.tostring() + $size
        writeToFile -file $outputFile -path $folderLocation -str " > Security maximum log file is $size"
        if($securityLogMaxSize.MaxSize -lt 196608){
            writeToFile -file $outputFile -path $folderLocation -str " > Security maximum log file size is smaller then the recommendation (196608KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Security events maximum log file size" -checkID "machine_SecMaxLog" -status $csvOp -finding "Security maximum log file size is:$size this is smaller then the recommendation (196608KB)." -risk $csvR4
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Security maximum log file size is equal or larger then 196608KB - this is good."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Security events maximum log file size" -checkID "machine_SecMaxLog" -status $csvSt -finding "System maximum log file size is:$size this is equal or larger then (196608KB)." -risk $csvR4
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > Security maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Security events maximum log file size" -checkID "machine_SecMaxLog" -status $csvOp -finding "Security maximum log file is not configured, the default is 1MB." -risk $csvR4
    }

    writeToFile -file $outputFile -path $folderLocation -str "`r`n--- Setup ---"
    if($null -ne $setupLogMaxSize){
        if($setupLogging.Enable -eq 1){
            $size = "MB"
            $Calc = [double]::Parse($setupLogMaxSize.MaxSize) / 1024
            $Calc = [Math]::Ceiling($Calc)
            if($Calc -ge 1024){
                $Calc = $Calc / 1024
                $Calc = [Math]::Ceiling($Calc)
                $size = "GB"
            }
            $size = [String]::Parse($Calc) + $size
            writeToFile -file $outputFile -path $folderLocation -str " > Setup maximum log file is $size"
            if($setupLogMaxSize.MaxSize -lt 32768){
                writeToFile -file $outputFile -path $folderLocation -str " > Setup maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Setup events maximum log file size" -checkID "machine_SetupMaxLog" -status $csvOp -finding "Setup maximum log file size is:$size and smaller then the recommendation (32768KB)." -risk $csvR1
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Setup maximum log file size is equal or larger then 32768KB - this is good."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Setup events maximum log file size" -checkID "machine_SetupMaxLog" -status $csvSt -finding "Setup maximum log file size is:$size and equal or larger then (32768KB)."  -risk $csvR1

            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Setup log are not enabled."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Setup events maximum log file size" -checkID "machine_SetupMaxLog" -finding "Setup log are not enabled." -risk $csvR1
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > Setup maximum log file is not configured or enabled."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Audit" -checkName "Setup events maximum log file size" -checkID "machine_SetupMaxLog" -finding "Setup maximum log file is not configured or enabled." -risk $csvR1
    }

}

#Check if safe mode access by non-admins is blocked
function checkSafeModeAcc4NonAdmin {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkSafeModeAcc4NonAdmin function"
    writeToScreen -str "Checking if safe mode access by non-admins is blocked..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Safe mode access by non-admins (SafeModeBlockNonAdmins registry value) ============="
    writeToFile -file $outputFile -path $folderLocation -str "If safe mode can be accessed by non admins there is an option of privilege escalation on this machine for an attacker - required direct access"
    $reg = getRegValue -HKLM $true -regPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -regName "SafeModeBlockNonAdmins"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > No hardening on Safe mode access by non admins - may be considered a finding if you feel pedant today."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Safe mode access by non-admins" -checkID "machine_SafeModeAcc4NonAdmin" -status $csvOp -finding "No hardening on Safe mode access by non admins." -risk $csvR3

    }
    else{
        if($reg.SafeModeBlockNonAdmins -eq 1){
            writeToFile -file $outputFile -path $folderLocation -str " > Block Safe mode access by non-admins is enabled - this is a good thing."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Safe mode access by non-admins" -checkID "machine_SafeModeAcc4NonAdmin" -status $csvSt -finding "Block Safe mode access by non-admins is enabled." -risk $csvR3

        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Block Safe mode access by non-admins is disabled - may be considered a finding if you feel pedant today."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Operation system" -checkName "Safe mode access by non-admins" -checkID "machine_SafeModeAcc4NonAdmin" -status $csvOp -finding "Block Safe mode access by non-admins is disabled."  -risk $csvR3
        }
    }
}
#check proxy settings (including WPAD)
function checkProxyConfiguration {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkProxyConfiguration function"
    writeToScreen -str "Getting proxy configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Proxy Configuration ============="
    $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -regName "ProxySettingsPerUser"
    if($null -ne $reg -and $reg.ProxySettingsPerUser -eq 0){
        writeToFile -file $outputFile -path $folderLocation -str " > Proxy is configured on the machine (enforced on all users forced by GPO)"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Proxy configuration location" -checkID "machine_proxyConf" -status $csvSt -finding "Internet proxy is configured (enforced on all users forced by GPO)."  -risk $csvR2
    }
    else{
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Proxy configuration location" -checkID "machine_proxyConf" -status $csvOp -finding "Internet Proxy is configured only on the user." -comment "Proxy is configured on the user space and not on the machine (e.g., an administrator might have Proxy but a standard user might not.)" -risk $csvR2
    }
    #checking internet settings (IE and system use the same configuration)
    $userProxy = getRegValue -HKLM $false -regPath "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $reg = getRegValue -HKLM $false -regPath "Software\Microsoft\Windows\CurrentVersion\Internet Settings" -regName "ProxyEnable"
    if($null -ne $reg -and $reg.ProxyEnable -eq 1){
        writeToFile -file $outputFile -path $folderLocation -str ($userProxy | Out-String)
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Proxy settings" -checkID "machine_proxySet" -status $csvUn -comment (($userProxy | Out-String)+".") -risk $csvR1
    }
    else {
        writeToFile -file $outputFile -path $folderLocation -str " > User proxy is disabled"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Proxy settings" -checkID "machine_proxySet" -status $csvSt -comment "User proxy is disabled. (e.g., no configuration found)" -risk $csvR1
    }

    if (($winVersion.Major -ge 7) -or ($winVersion.Minor -ge 2)){
        $reg = getRegValue -HKLM $true -regPath "SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -regName "DProxiesAuthoritive"
        if($null -ne $reg -and $reg.DProxiesAuthoritive -eq 1){
            writeToFile -file $outputFile -path $folderLocation -str " > Windows Network Isolation's automatic proxy discovery is disabled."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Network Isolation's automatic proxy discovery" -checkID "machine_autoIsoProxyDiscovery" -status $csvSt -finding "Windows Network Isolation's automatic proxy discovery is disabled."  -risk $csvR2
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Windows Network Isolation's automatic proxy discovery is enabled! "
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Network Isolation's automatic proxy discovery" -checkID "machine_autoIsoProxyDiscovery" -status $csvOp -finding "Windows Network Isolation's automatic proxy discovery is enabled."  -risk $csvR2
        }
    }
    writeToFile -file $outputFile -path $folderLocation -str "=== Internet Explorer Settings (System-default) ==="
    $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Internet Explorer\Control Panel" -regName "Proxy"
    $reg2 = getRegValue -HKLM $false -regPath "Software\Policies\Microsoft\Internet Explorer\Control Panel" -regName "Proxy"
    if($null -ne $reg -and $reg.Proxy -eq 1){
        writeToFile -file $outputFile -path $folderLocation -str " > All users cannot change proxy setting - prevention is on the computer level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Permissions to configure proxy" -checkID "machine_accConfProxy" -status $csvSt -finding "All users are not allowed to change proxy settings."  -risk $csvR2
    }
    elseif($null -ne $reg2 -and $reg2.Proxy -eq 1){
        writeToFile -file $outputFile -path $folderLocation -str " > User cannot change proxy setting - prevention is on the user level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Permissions to configure proxy" -checkID "machine_accConfProxy" -status $csvUn -finding "User cannot change proxy setting - Other users might have the ability to change this setting." -comment "Configuration is set on the user space." -risk $csvR2
    }
    else {
        writeToFile -file $outputFile -path $folderLocation -str " > User can change proxy setting (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Permissions to configure proxy" -checkID "machine_accConfProxy" -status $csvOp -finding "Low privileged users can modify proxy settings."  -risk $csvR2
    }

    $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -regName "EnableAutoProxyResultCache"
    if($null -ne $reg -and $reg.EnableAutoProxyResultCache -eq 0){
        writeToFile -file $outputFile -path $folderLocation -str " > Caching of Auto-Proxy scripts is Disable (WPAD Disabled)" # need to check
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Caching of Auto-Proxy scripts (WPAD)" -checkID "machine_AutoProxyResultCache" -status $csvSt -finding "Caching of Auto-Proxy scripts is Disable (WPAD disabled)." -risk $csvR3
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > Caching of Auto-Proxy scripts is enabled (WPAD enabled)" # need to check
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Caching of Auto-Proxy scripts (WPAD)" -checkID "machine_AutoProxyResultCache" -status $csvOp -finding "Caching of Auto-Proxy scripts is enabled (WPAD enabled)." -risk $csvR3
    }
    writeToFile -file $outputFile -path $folderLocation -str "`r`n=== WinHTTP service (Auto Proxy) ==="
    $proxySrv = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($null -ne $proxySrv)
    {
        if($proxySrv.Status -eq "Running" )
        {writeToFile -file $outputFile -path $folderLocation -str " > WPAD service status is running - WinHTTP Web Proxy Auto-Discovery Service"}
        else{
            writeToFile -file $outputFile -path $folderLocation -str (" > WPAD service status is "+$proxySrv.Status+" - WinHTTP Web Proxy Auto-Discovery Service")
        }
        if($proxySrv.StartType -eq "Disable"){
            writeToFile -file $outputFile -path $folderLocation -str " > WPAD service start type is disabled - WinHTTP Web Proxy Auto-Discovery Service"
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "WPAD service" -checkID "machine_WPADSvc" -status $csvSt -finding "WPAD service start type is disabled (WinHTTP Web Proxy Auto-Discovery)."  -risk $csvR2

        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str (" > WPAD service start type is "+$proxySrv.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service")
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "WPAD service" -checkID "machine_WPADSvc" -status $csvOp -finding ("WPAD service start type is "+$proxySrv.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service.") -risk $csvR2
        }
        writeToFile -file $outputFile -path $folderLocation -str "`r`n=== Raw data:"
        writeToFile -file $outputFile -path $folderLocation -str ($proxySrv | Format-Table -Property Name, DisplayName,Status,StartType,ServiceType| Out-String)
    }



    writeToFile -file $outputFile -path $folderLocation -str "`r`n=== netsh winhttp show proxy - output ==="
    writeToFile -file $outputFile -path $folderLocation -str (netsh winhttp show proxy)
    writeToFile -file $outputFile -path $folderLocation -str "`r`n=== User proxy setting ==="
    
    <# Browser specific tests need to work on it
    #checking if chrome is installed
    $chromeComp = $null -ne (Get-ItemProperty HKLM:\Software\Google\Chrome)
    $chromeUser = $null -ne (Get-ItemProperty HKCU:\Software\Google\Chrome)
    if($chromeComp -or $chromeUser){
        writeToFile -file $outputFile -path $folderLocation -str "`r`n=== Chrome proxy setting ==="
        if($null -ne $chromeComp){
            $prefix = "HKLM:\"
        }
        else{
            $prefix = "HKCU:\"
        }
        $chromeReg = Get-ItemProperty ($prefix+"Software\Policies\Google\Chrome") -Name "ProxySettings" -ErrorAction SilentlyContinue 
        if($null -ne $chromeReg)
        {writeToFile -file $outputFile -path $folderLocation -str ($chromeReg.ProxySettings | Out-String)}

    }
    #checking if Firefox is installed
    $firefoxComp = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    $firefoxUser = $null -ne (Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    if($firefoxComp -or $firefoxUser){
        #checking Firefox proxy setting
        writeToFile -file $outputFile -path $folderLocation -str "`r`n=== Firefox proxy setting ==="
        if($null -ne $firefoxComp){
            $prefix = "HKLM:\"
        }
        else{
            $prefix = "HKCU:\"
        }
        $firefoxReg =  Get-ItemProperty ($prefix+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Locked" -ErrorAction SilentlyContinue 
        if($null -ne $firefoxReg -and $firefoxReg.Locked -eq 1){
            writeToFile -file $outputFile -path $folderLocation -str " > Firefox proxy setting is locked"
        }
        $firefoxReg =  Get-ItemProperty ($prefix+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Mode" -ErrorAction SilentlyContinue 
        switch ($firefoxReg.Mode) {
            "" {writeToFile -file $outputFile -path $folderLocation -str " > Firefox proxy: not using proxy"}
            "system" {writeToFile -file $outputFile -path $folderLocation -str " > Firefox proxy: using system settings"}
            "manual" {writeToFile -file $outputFile -path $folderLocation -str " > Firefox proxy: using manual configuration"}
            "autoDetect" {writeToFile -file $outputFile -path $folderLocation -str " > Firefox proxy: Auto detect"}
            "autoConfig" {writeToFile -file $outputFile -path $folderLocation -str " > Firefox proxy: Auto config"}
            Default {writeToFile -file $outputFile -path $folderLocation -str " > Firefox proxy: unknown probably no proxy"}
        }
        $firefoxReg =  Get-ItemProperty ($prefix+"Software\Policies\Mozilla\Firefox\Proxy") -Name "HTTPProxy" -ErrorAction SilentlyContinue 
        if($null -ne $firefoxReg){
            writeToFile -file $outputFile -path $folderLocation -str (" > Firefox proxy server:"+$firefoxReg.HTTPProxy)
        }
        $firefoxReg =  Get-ItemProperty ($prefix+"Software\Policies\Mozilla\Firefox\Proxy") -Name "UseHTTPProxyForAllProtocols" -ErrorAction SilentlyContinue 
        if($null -ne $firefoxReg -and $firefoxReg.UseHTTPProxyForAllProtocols -eq 1){
            writeToFile -file $outputFile -path $folderLocation -str (" > Firefox proxy: using http proxy for all protocols")
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str (" > Firefox proxy: not using http proxy for all protocols - check manual")
        }
    }
    #>  
}

#check windows update configuration + WSUS
function checkWinUpdateConfig{
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkWSUSConfig function"
    writeToScreen -str "Getting Windows Update configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Windows update configuration ============="
    $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -regName "NoAutoUpdate"
    if($null -ne $reg -and $reg.NoAutoUpdate -eq 0){
        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is disabled - can be considered a finding."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update" -checkID "machine_autoUpdate" -status $csvOp -finding "Windows automatic update is disabled." -risk $csvR2
    }
    else{
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update" -checkID "machine_autoUpdate" -status $csvSt -finding "Windows automatic update is enabled." -risk $csvR2
        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is enabled."
    }
    $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -regName "AUOptions"
    switch ($reg.AUOptions) {
        2 { 
            writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to notify for download and notify for install - this may be considered a finding (allows users to not update)." 
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status $csvOp -finding "Windows automatic update is configured to notify for download and notify for install." -risk $csvR2
            
        }
        3 { 
            writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to auto download and notify for install - this depends if this setting if this is set on servers and there is a manual process to update every month. If so it is OK; otherwise it is not recommended."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status $csvUn -finding "Windows automatic update is configured to auto download and notify for install (if this setting if this is set on servers and there is a manual process to update every month. If so it is OK)."  -risk $csvR2
         }
        4 { 
            writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to auto download and schedule the install - this is a good thing." 
            $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -regName "ScheduledInstallDay"
            if($null -ne $reg){
                switch ($reg.ScheduledInstallDay) {
                    0 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every day"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every day." -risk $csvR2
                     }
                    1 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every Sunday"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every Sunday." -risk $csvR2
                      }
                    2 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every Monday" 
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every Monday." -risk $csvR2
                 }
                    3 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every Tuesday"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every Tuesday." -risk $csvR2
                        
                    }
                    4 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every Wednesday"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every Wednesday." -risk $csvR2
                      }
                    5 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every Thursday"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every Thursday." -risk $csvR2
                      }
                    6 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every Friday"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every Friday." -risk $csvR2
                    }
                    7 { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to update every Saturday" 
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status "false" -finding "Windows automatic update is configured to update every Saturday." -risk $csvR2
                     }
                    Default { 
                        writeToFile -file $outputFile -path $folderLocation -str " > Windows Automatic update day is not configured"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status $csvUn -finding "Windows Automatic update day is not configured" -risk $csvR2
                     }
                }
            }
            $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -regName "ScheduledInstallTime"
            if($null -ne $reg){
                writeToFile -file $outputFile -path $folderLocation -str  (" > Windows automatic update to update at " + $reg.ScheduledInstallTime + ":00")
            }

          }
        5 { 
            writeToFile -file $outputFile -path $folderLocation -str " > Windows automatic update is configured to allow local admin to choose setting."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status $csvOp -finding "Windows automatic update is configured to allow local admin to choose setting." -risk $csvR2
     }
        Default {
            writeToFile -file $outputFile -path $folderLocation -str " > Unknown Windows update configuration."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "Windows automatic update schedule" -checkID "machine_autoUpdateSchedule" -status $csvUn -finding "Unknown Windows update configuration." -risk $csvR2
    }
    }
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= WSUS configuration ============="
    $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -regName "UseWUServer"
    if ($null -ne $reg -and $reg.UseWUServer -eq 1 ){
        $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WindowsUpdate" -regName "WUServer"
        if ($null -eq $reg) {
            writeToFile -file $outputFile -path $folderLocation -str " > WSUS configuration found but no server has been configured."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "WSUS update" -checkID "machine_wsusUpdate" -status $csvOp -finding "WSUS configuration found but no server has been configured." -risk $csvR2
        }
        else {
            $test = $reg.WUServer
            if ($test -like "http://*") {
                writeToFile -file $outputFile -path $folderLocation -str " > WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation and may be considered a finding."
                writeToFile -file $outputFile -path $folderLocation -str " > For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus"
                writeToFile -file $outputFile -path $folderLocation -str " > Note that SCCM with Enhanced HTTP configured my be immune to this attack. For more information, see: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http"
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "WSUS update" -checkID "machine_wsusUpdate" -status $csvOp -finding "WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation." -risk $csvR2

                $test = $test.Substring(7)
                if($test.IndexOf("/") -ge 0){
                    $test = $test.Substring(0,$test.IndexOf("/"))
                }
            }
            else {
                writeToFile -file $outputFile -path $folderLocation -str " > WSUS is configured with HTTPS connection - this is the hardened configuration."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "WSUS update" -checkID "machine_wsusUpdate" -status $csvSt -finding "WSUS is configured with HTTPS connection." -risk $csvR2
                $test = $test.Substring(8)
                if($test.IndexOf("/") -ge 0){
                    $test = $test.Substring(0,$test.IndexOf("/"))
                }
            }
            try {
                [IPAddress]$test | Out-Null
                writeToFile -file $outputFile -path $folderLocation -str " > WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "WSUS update address" -checkID "machine_wsusUpdateAddress" -status $csvOp -finding "WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."  -risk $csvR2
            }
            catch {
                writeToFile -file $outputFile -path $folderLocation -str " > WSUS is configured with a URL address (using kerberos authentication)."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "WSUS update address" -checkID "machine_wsusUpdateAddress" -status $csvSt -finding "WSUS is configured with a URL address (using kerberos authentication)."  -risk $csvR2
            }
            writeToFile -file $outputFile -path $folderLocation -str (" > WSUS Server is: "+ $reg.WUServer)
        }
    }
    else{
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "WSUS update" -checkID "machine_wsusUpdate" -status $csvUn -finding "No WSUS configuration found (might be managed in another way)." -risk $csvR1
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Patching" -checkName "WSUS update address" -checkID "machine_wsusUpdateAddress" -status $csvUn -finding "No WSUS configuration found (might be managed in another way)."  -risk $csvR1
        writeToFile -file $outputFile -path $folderLocation -str " > No WSUS configuration found."
    }
}

#check for unquoted path vulnerability in services running on the machine
function checkUnquotedSePath {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkUnquotedSePath function"
    #writeToScreen -str "Checking if the system has a service vulnerable to Unquoted path escalation attack" -ForegroundColor Yellow
    writeToScreen -str "Checking for services vulnerable to unquoted path privilege escalation..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Unquoted path vulnerability ============="
    writeToFile -file $outputFile -path $folderLocation -str "This test is checking all services on the computer if there is a service that is not running from a quoted path and starts outside of the protected folder (i.e. Windows folder)"
    writeToFile -file $outputFile -path $folderLocation -str "for more information about the attack: https://attack.mitre.org/techniques/T1574/009"
    $services = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName
    $badPaths = @()
    $boolBadPath = $false
    foreach ($service in $services){
        $test = $service.PathName
        if ($null -ne $test){
            if ($test -notlike "`"*" -and $test -notlike "C:\Windows\*"){
                $badPaths += $service
                $boolBadPath = $true
            }
        }
    }
    if ($boolBadPath){
        addToCSV -relatedFile $outputFile -category "Machine Vulnerabilities" -checkName "Unquoted path" -checkID "vul_quotedPath" -status $csvOp -finding ("There are vulnerable services in this machine:"+($badPaths | Out-String)+".")  -risk $csvR5
        writeToFile -file $outputFile -path $folderLocation -str " > There are vulnerable services in this machine:"
        writeToFile -file $outputFile -path $folderLocation -str  ($badPaths | Out-String)
    }
    else{
        addToCSV -relatedFile $outputFile -category "Machine Vulnerabilities" -checkName "Unquoted path" -checkID "vul_quotedPath" -status $csvSt -finding "No services that are vulnerable to unquoted path privilege escalation vector were found." -risk $csvR5
        writeToFile -file $outputFile -path $folderLocation -str " > The check did not find any service that is vulnerable to unquoted path escalation attack. This is good."
    }
}

#check if there is hardening preventing user from connecting to multiple networks simultaneous 
function checkSimulEhtrAndWifi {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkSimulEhtrAndWifi function"
    writeToScreen -str "Checking if simultaneous connection to Ethernet and Wi-Fi is allowed..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Check if simultaneous Ethernet and Wi-Fi is allowed ============="
    if ((($winVersion.Major -ge 7) -or ($winVersion.Minor -ge 2))) {
        writeToFile -file $outputFile -path $folderLocation -str "`r`n=== checking if GPO Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured"
        $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -regName "fMinimizeConnections"
        if ($null -ne $reg){
            switch ($reg.fMinimizeConnections) {
                0 {
                     writeToFile -file $outputFile -path $folderLocation -str " > Machine is not hardened and allow simultaneous connections" 
                     addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Ethernet simultaneous connections" -checkID "machine_ethSim" -status $csvOp -finding "Machine allows simultaneous Ethernet connections." -risk $csvR2
                    }
                1 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network." 
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Ethernet simultaneous connections" -checkID "machine_ethSim" -status $csvSt -finding "Machine block's any new automatic internet connection when the computer has at least one active internet connection to a preferred type of network." -risk $csvR2
                }
                2 {
                     writeToFile -file $outputFile -path $folderLocation -str " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." 
                     addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Ethernet simultaneous connections" -checkID "machine_ethSim" -status $csvSt -finding "Machine is configured to minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." -risk $csvR2
                    }
                3 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Machine is hardened and disallow Wi-Fi when connected to Ethernet."
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Ethernet simultaneous connections" -checkID "machine_ethSim" -status $csvSt -finding "Machine is configured to disallow Wi-Fi when connected to Ethernet." -risk $csvR2
                }
                Default {
                    writeToFile -file $outputFile -path $folderLocation -str " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured with unknown configuration"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Ethernet simultaneous connections" -checkID "machine_ethSim" -status $csvUn -finding "Machine is configured with unknown configuration." -risk $csvR2
                }
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is not configured"
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Ethernet simultaneous connections" -checkID "machine_ethSim" -status $csvUn -finding "Machine is missing configuration for simultaneous Ethernet connections (e.g., for servers it is fine to not configure this setting)." -risk $csvR2
        }

        writeToFile -file $outputFile -path $folderLocation -str "`r`n=== checking if GPO Prohibit connection to non-domain networks when connected to domain authenticated network is configured"
        $reg = getRegValue -HKLM $true -regPath "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -regName "fBlockNonDomain"

        if($null -ne $reg){
            if($reg.fBlockNonDomain -eq 1){
                writeToFile -file $outputFile -path $folderLocation -str " > Machine is hardened and prohibit connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Prohibit connection to non-domain networks" -checkID "machine_PCTNDNetwork" -status $csvSt -finding "Machine is configured to prohibit connections to non-domain networks when connected to domain authenticated network." -risk $csvR2
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Machine allows connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Prohibit connection to non-domain networks" -checkID "machine_PCTNDNetwork" -status $csvOp -finding "Machine is configured to allow connections to non-domain networks when connected to domain authenticated network." -risk $csvR2
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > No configuration found to restrict machine connection to non-domain networks when connected to domain authenticated network"
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Prohibit connection to non-domain networks" -checkID "machine_PCTNDNetwork" -status $csvUn -finding "No configuration found to restrict machine connection to non-domain networks(e.g., for servers it is fine to not configure this setting)." -risk $csvR2
        }
      
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > OS is obsolete and those not support network access restriction based on GPO"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Ethernet simultaneous connections" -checkID "machine_ethSim" -status $csvUn -finding "OS is obsolete and those not support network access restriction based on GPO" -risk $csvR2
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Networking" -checkName "Prohibit connection to non-domain networks" -checkID "machine_PCTNDNetwork" -status $csvUn -finding "OS is obsolete and those not support network access restriction based on GPO." -risk $csvR2
    }
    
}

#Check Macro and DDE (OLE) settings
function checkMacroAndDDE{
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkMacroAndDDE function"
    writeToScreen -str "Checking Macros and DDE configuration" -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Macros and DDE configuration ============="
    #Get-WmiObject win32_product | where{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | select Name,Version
    $versions = Get-WmiObject win32_product | Where-Object{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | Select-Object Version
    $versionCut = @()
    foreach ($ver in $versions.version){
        $tmp = $ver.IndexOf(".")
        $flag = $true
        foreach ($n in $versionCut ){
            if ($n -eq $ver.Substring(0,$tmp+2)){
                $flag = $false
            }
        }
        if($flag){
            $versionCut += $ver.Substring(0,$tmp+2)
        }
    }
    if ($versionCut.Count -ge 1){
        writeToFile -file $outputFile -path $folderLocation -str "`r`n=== DDE Configuration"
        foreach($n in $versionCut){
            writeToFile -file $outputFile -path $folderLocation -str "Office version $n"
            #Excel
            if($n -ge 12.0){
                $reg = getRegValue -HKLM $false -regPath "Software\Microsoft\Office\$n\Excel\Security" -regName "WorkbookLinkWarnings"
                if($null -ne $reg){
                    if($reg.WorkbookLinkWarnings -eq 2){
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Excel WorkbookLinkWarnings (DDE)" -checkID "machine_excelDDE" -status $csvOp -finding "Excel WorkbookLinkWarnings (DDE) is disabled." -risk $csvR3
                        writeToFile -file $outputFile -path $folderLocation -str " > Excel WorkbookLinkWarnings (DDE) is disabled."
                    }
                    else{
                        writeToFile -file $outputFile -path $folderLocation -str " > Excel WorkbookLinkWarnings (DDE) is enabled."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Excel WorkbookLinkWarnings (DDE)" -checkID "machine_excelDDE" -status $csvSt -finding "Excel WorkbookLinkWarnings (DDE) is enabled." -risk $csvR3
                    }
                }
                else{
                    writeToFile -file $outputFile -path $folderLocation -str " > Excel no configuration found for DDE in this version."
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Excel WorkbookLinkWarnings (DDE)" -checkID "machine_excelDDE" -status $csvUn -finding "Excel WorkbookLinkWarnings (DDE) hardening is not configured.(might be managed by other mechanism)." -risk $csvR3
                }
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Office excel version is older then 2007 no DDE option to disable."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Excel WorkbookLinkWarnings (DDE)" -checkID "machine_excelDDE" -status $csvOp -finding "Office excel version is older then 2007 no DDE option to disable." -risk $csvR3
            }
            if($n -ge 14.0){
                #Outlook
                $reg = getRegValue -HKLM $false -regPath "Software\Microsoft\Office\$n\Word\Options\WordMail" -regName "DontUpdateLinks"
                if($null -ne $reg){
                    if($reg.DontUpdateLinks -eq 1){
                        writeToFile -file $outputFile -path $folderLocation -str " > Outlook update links (DDE) is disabled."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Outlook update links (DDE)" -checkID "machine_outlookDDE" -status $csvOp -finding "Outlook update links (DDE) is disabled." -risk $csvR3
                    }
                    else{
                        writeToFile -file $outputFile -path $folderLocation -str " > Outlook update links (DDE) is enabled."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Outlook update links (DDE)" -checkID "machine_outlookDDE" -status $csvSt -finding "Outlook update links (DDE) is enabled." -risk $csvR3
                    }
                }
                else {
                    writeToFile -file $outputFile -path $folderLocation -str " > Outlook no configuration found for DDE in this version"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Outlook update links (DDE)" -checkID "machine_outlookDDE" -status $csvUn -finding "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)." -risk $csvR3
                }

                #Word
                $reg = getRegValue -HKLM $false -regPath "Software\Microsoft\Office\$n\Word\Options" -regName "DontUpdateLinks"
                if($null -ne $reg){
                    if($reg.DontUpdateLinks -eq 1){
                        writeToFile -file $outputFile -path $folderLocation -str " > Word update links (DDE) is disabled."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Word update links (DDE)" -checkID "machine_wordDDE" -status $csvOp -finding "Word update links (DDE) is disabled." -risk $csvR3
                    }
                    else{
                        writeToFile -file $outputFile -path $folderLocation -str " > Word update links (DDE) is enabled."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Word update links (DDE)" -checkID "machine_wordDDE" -status $csvSt -finding "Word update links (DDE) is enabled." -risk $csvR3
                    }
                }
                else {
                    writeToFile -file $outputFile -path $folderLocation -str " > Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Word update links (DDE)" -checkID "machine_wordDDE" -status $csvUn -finding "Word update links (DDE) hardening is not configured.(might be managed by other mechanism)." -risk $csvR3
                }

            }
            elseif ($n -eq 12.0) {
                $reg = getRegValue -HKLM $false -regPath "Software\Microsoft\Office\12.0\Word\Options\vpre" -regName "fNoCalclinksOnopen_90_1"
                if($null -ne $reg){
                    if($reg.fNoCalclinksOnopen_90_1 -eq 1){
                        writeToFile -file $outputFile -path $folderLocation -str " > Outlook and Word update links (DDE) is disabled."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Outlook update links (DDE)" -checkID "machine_outlookDDE" -status $csvOp -finding "Outlook update links (DDE) is disabled." -risk $csvR3

                    }
                    else{
                        writeToFile -file $outputFile -path $folderLocation -str " > Outlook and Word update links (DDE) is enabled."
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Outlook update links (DDE)" -checkID "machine_outlookDDE" -status $csvSt -finding "Outlook update links (DDE) is enabled." -risk $csvR3
                    }
                }
                else {
                    writeToFile -file $outputFile -path $folderLocation -str " > Outlook and Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Outlook update links (DDE)" -checkID "machine_outlookDDE" -status $csvUn -finding "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)" -risk $csvR3
                }
                
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Office outlook version is older then 2007 no DDE option to disable"
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Outlook update links (DDE)" -checkID "machine_outlookDDE" -status $csvOp -finding "Office outlook version is older then 2007 no DDE option to disable." -risk $csvR3
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Software" -checkName "Word update links (DDE)" -checkID "machine_wordDDE" -status $csvOp -finding "Office word version is older then 2007 no DDE option to disable."  -risk $csvR3

            }

        }

        ## Macros need to add every office has it's own checks
        # site is unavailable to continue
        # https://admx.help/?Category=Office2007&Policy=ppt12.Office.Microsoft.Policies.Windows::L_VBAWarningsPolicy
        # https://admx.help/?Category=Office2016&Policy=word16.Office.Microsoft.Policies.Windows::L_VBAWarningsPolicy
        # https://www.heelpbook.net/2016/how-to-control-macro-settings-using-registry-keys-or-gpos/

    }
}

#check Kerberos security settings
function checkKerberos{
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running Kerberos security check function"
    writeToScreen -str "Getting Kerberos security settings..." -ForegroundColor Yellow
    if($partOfDomain){
        writeToFile -file $outputFile -path $folderLocation -str "============= Kerberos Security settings ============="
        writeToFile -file $outputFile -path $folderLocation -str ""
        if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2){
            writeToFile -file $outputFile -path $folderLocation -str "This machine is not a domain controller so missing configuration is not a finding! (kerberos settings need to be set only on domain controllers)"
        }
        # supported encryption
        # good values: 0x8(8){AES128} , 0x10(16){AES256}, 0x18(24){AES128+AES256},0x7fffffe8(2147483624){AES128+fe}, 0x7ffffff0(2147483632){AES256+fe}, 0x7ffffff8(2147483640){AES128+AES256+fe},  , need to add combinations that use Future encryption types
        writeToFile -file $outputFile -path $folderLocation -str "Kerberos supported encryption"
        $reg = getRegValue -HKLM $true -regPath "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -regName "supportedencryptiontypes"
        if($null -ne $reg){
            switch ($reg.supportedencryptiontypes) {
                8 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows AES128 only - this is a good thing" 
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvSt -finding "Kerberos encryption allows AES128 only." -risk $csvR2
                }
                16 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows AES256 only - this is a good thing"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvSt -finding "Kerberos encryption allows AES256 only." -risk $csvR2
                }
                24 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows AES128 + AES256 only - this is a good thing"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvSt -finding "Kerberos encryption allows AES128 + AES256 only." -risk $csvR2
                }
                2147483624 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows AES128 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvSt -finding "Kerberos encryption allows AES128 + Future encryption types." -risk $csvR2
                 }
                2147483632 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows AES256 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvSt -finding "Kerberos encryption allows AES256 + Future encryption types." -risk $csvR2
                 }
                2147483640 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows AES128 + AES256 + Future encryption types only - this is a good thing"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvSt -finding "Kerberos encryption allows AES128 + AES256 + Future encryption types."  -risk $csvR2
                 }
                2147483616 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows Future encryption types only - things will not work properly inside the domain (probably)"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvOp -finding "Kerberos encryption allows Future encryption types only (e.g., dose not allow any encryption."  -risk $csvR2
                }

                0 { 
                    writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
                    addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvOp -finding "Kerberos encryption allows Default authentication (RC4 and up)."  -risk $csvR2
                 }
                Default {
                    if($reg.supportedencryptiontypes -ge 2147483616){
                        $temp = $reg.supportedencryptiontypes - 2147483616
                        writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows low encryption the Decimal Value is: $temp and it is including also Future encryption types (subtracted from the number) - this is a finding"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvOp -finding "Kerberos encryption allows low encryption the Decimal Value is: $temp and it is including also Future encryption types (subtracted from the number)."  -risk $csvR2

                    }
                    else
                    {
                        writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows low encryption the Decimal Value is:"+ $reg.supportedencryptiontypes +" - this is a finding"
                        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvOp -finding "Kerberos encryption allows low encryption the Decimal Value is: $temp."  -risk $csvR2
                    }
                    writeToFile -file $outputFile -path $folderLocation -str " > For more information: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797"
                }
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -status $csvOp -finding "Kerberos encryption allows Default authentication (RC4 and up)." -risk $csvR2
        }
        <# Additional check might be added in the future 
        $kerbPath =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        # maximum diff allowed
        writeToFile -file $outputFile -path $folderLocation -str "The maximum time difference that is permitted between the client computer and the server that accepts Kerberos authentication"
        $reg = Get-ItemProperty $kerbPath -Name "SkewTime" -ErrorAction SilentlyContinue
        if($null -ne $reg){
            if($reg.SkewTime -ge 5){
                writeToFile -file $outputFile -path $folderLocation -str " > The maximum time difference is set to "+$reg.SkewTime+" it is configured to higher then the default - might be a finding"
            }
            elseif ( $reg.SkewTime -eq 5){
                writeToFile -file $outputFile -path $folderLocation -str " > The maximum time difference is set to "+$reg.SkewTime+" this is the default configuration - this is fine"
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > The maximum time difference is set to "+$reg.SkewTime+ " this is better then the default configuration (5) - this is a good thing"
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > No configuration found default setting is 5 minutes"
        }
        # log collection
        writeToFile -file $outputFile -path $folderLocation -str "Kerberos events are logged in the system event log."
        $reg = Get-ItemProperty $kerbPath -Name "LogLevel" -ErrorAction SilentlyContinue
        if($null -ne $reg -and $reg.LogLevel -ne 0){
            writeToFile -file $outputFile -path $folderLocation -str " > Kerberos events are logged in the system event log"
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Kerberos events are NOT logged in the system event log - this is a finding!"
        }
        # Max Packet Size before using UDP for authentication
        writeToFile -file $outputFile -path $folderLocation -str "Kerberos max packet size before using UDP."
        $reg = Get-ItemProperty $kerbPath -Name "MaxPacketSize" -ErrorAction SilentlyContinue
        if($null -eq $reg -or $reg.MaxPacketSize -eq 0){
            writeToFile -file $outputFile -path $folderLocation -str " > Kerberos max packet size is not configured or set to 0 (e.g., not using UDP at all) - this is a ok"
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Kerberos max packet size is set to " + $reg.MaxPacketSize + " - this is a finding!"
        }
        #>
        
    }
    else{
        writeToLog -str "Kerberos security check skipped machine is not part of a domain"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Kerberos supported encryption" -checkID "domain_kerbSupEnc" -finding "Machine is not part of a domain."  -risk $csvR2
    }
}

#check storage of passwords and credentials
function checkPrevStorOfPassAndCred {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkPrevStorOfPassAndCred function"
    writeToScreen -str "Checking if storage of passwords and credentials are blocked..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Prevent storage of passwords and credentials ============="
    writeToFile -file $outputFile -path $folderLocation -str "Checking Network access: Do not allow storage of passwords and credentials for network authentication is enabled."
    writeToFile -file $outputFile -path $folderLocation -str "This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine as that may lead to account compromise."
    writeToFile -file $outputFile -path $folderLocation -str "For more information: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
    $reg = getRegValue -HKLM $true -regPath "\System\CurrentControlSet\Control\Lsa\" -regName "DisableDomainCreds"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Do not allow storage of passwords and credentials for network authentication hardening is not configured"
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Storage of passwords and credentials" -checkID "domain_PrevStorOfPassAndCred" -status $csvOp -finding "Storage of network passwords and credentials is not configured." -risk $csvR3 -comment "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"

    }
    else{
        if($reg.DisableDomainCreds -eq 1){
            writeToFile -file $outputFile -path $folderLocation -str " > Do not allow storage of passwords and credentials for network authentication hardening is enabled - this is a good thing."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Storage of passwords and credentials" -checkID "domain_PrevStorOfPassAndCred" -status $csvSt -finding "Storage of network passwords and credentials is disabled. (hardened)" -risk $csvR3 -comment "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Do not allow storage of passwords and credentials for network authentication hardening is disabled - This is a finding."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "Storage of passwords and credentials" -checkID "domain_PrevStorOfPassAndCred" -status $csvOp -finding "Storage of network passwords and credentials is enabled. (Configuration is disabled)" -risk $csvR3 -comment "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
    }
}

#CredSSP Checks
# https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsSSP::AllowDefaultCredentials
function checkCredSSP {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extension ".txt"
    writeToLog -str "running checkCredSSP function"
    writeToScreen -str "Checking CredSSP Configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= CredSSP Configuration ============="
    writeToFile -file $outputFile -path $folderLocation -str "The Credential Security Support Provider protocol (CredSSP) is a Security Support Provider that is implemented by using the Security Support Provider Interface (SSPI)."
    writeToFile -file $outputFile -path $folderLocation -str "CredSSP lets an application delegate the user's credentials from the client to the target server for remote authentication."
    writeToFile -file $outputFile -path $folderLocation -str "CredSSP provides an encrypted Transport Layer Security Protocol channel."
    writeToFile -file $outputFile -path $folderLocation -str "The client is authenticated over the encrypted channel by using the Simple and Protected Negotiate (SPNEGO) protocol with either Microsoft Kerberos or Microsoft NTLM."
    writeToFile -file $outputFile -path $folderLocation -str "For more information about CredSSP: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider"
    writeToFile -file $outputFile -path $folderLocation -str "Risk related to CredSSP:"
    writeToFile -file $outputFile -path $folderLocation -str "1. An attacker runs as admin on the client machine and delegating default credentials is enabled: Grab cleartext password from lsass."
    writeToFile -file $outputFile -path $folderLocation -str "2. An attacker runs as admin on the client machine and delegating default credentials is enabled: wait for new users to login, grab their password."
    writeToFile -file $outputFile -path $folderLocation -str "3. An attacker runs in the user context(none admin) and delegating default credentials enabled: running Kekeo server and Kekeo client to get passwords form the machine."
    writeToFile -file $outputFile -path $folderLocation -str "Other attacks exist that will utilize CredSSP for lateral movement and privilege escalation, such as using downgraded NTLM and saved credentials to catch hashes without raising alerts."

    #Allow delegating default credentials
    writeToFile -file $outputFile -path $folderLocation -str "`r`n------------- Allow delegation of default credentials -------------"
    writeToFile -file $outputFile -path $folderLocation -str "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials can be delegated (default credentials are those that you use when first logging on to Windows)."
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "AllowDefaultCredentials"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Not allowing delegation of default credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials" -checkID "domain_CredSSPDefaultCred" -status $csvSt -finding "CredSSP - Do not allow delegation of default credentials - default setting set to false." -comment "Delegation of default credentials is not permitted to any computer. Applications depending upon this delegation behavior might fail authentication." -risk $csvR3
    }
    else{
        if($reg.AllowDefaultCredentials -eq 1){
            $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $booltest = $false
            $serverList =""
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
                if($serverList -eq ""){
                    $serverList = $item
                }
                else{
                    $serverList += ", $item"
                }
            }
            if($booltest){
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of default credentials for any server."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials" -checkID "domain_CredSSPDefaultCred" -status $csvOp -finding "CredSSP - Allows delegation of default credentials for any server. Server list:$serverList" -risk $csvR3
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of default credentials for servers."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials" -checkID "domain_CredSSPDefaultCred" -status $csvOp -finding "CredSSP - Allows delegation of default credentials. Server list:$serverList" -risk $csvR3
            }
            writeToFile -file $outputFile -path $folderLocation -str " > Server list: $serverList"           
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Do not allows delegation of default credentials."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials" -checkID "domain_CredSSPDefaultCred" -status $csvSt -finding "CredSSP - Do not allow delegation of default credentials." -risk $csvR3
        }
    }

    #Allow delegating default credentials with NTLM-only server authentication
    writeToFile -file $outputFile -path $folderLocation -str "`r`n------------- Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $outputFile -path $folderLocation -str "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nThis policy setting applies when server authentication was achieved via NTLM. "
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "AllowDefCredentialsWhenNTLMOnly"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Not allowing delegation of default credentials with NTLM-only - No configuration found default setting is set to false."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials with NTLM-Only" -checkID "domain_CredSSPSavedCred" -status $csvSt -finding "CredSSP - Not allowing delegation of default credentials with NTLM-only - default setting set to false." -comment "delegation of default credentials is not permitted to any machine." -risk $csvR3
    }
    else{
        if($reg.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $booltest = $false
            $serverList =""
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
                if($serverList -eq ""){
                    $serverList = $item
                }
                else{
                    $serverList += ", $item"
                }
            }
            if($booltest){
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of default credentials in NTLM for any server."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials with NTLM-Only" -checkID "domain_CredSSPSavedCred" -status $csvOp -finding "CredSSP - Allows delegation of default credentials in NTLM for any server. Server list:$serverList" -risk $csvR3
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of default credentials in NTLM for servers."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials with NTLM-Only" -checkID "domain_CredSSPSavedCred" -status $csvOp -finding "CredSSP - Allows delegation of default credentials in NTLM for servers. Server list:$serverList" -risk $csvR3
            }
            writeToFile -file $outputFile -path $folderLocation -str " > Server list: $serverList"
            }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Not allowing delegation of default credentials with NTLM-only."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of default credentials with NTLM-Only" -checkID "domain_CredSSPSavedCred" -status $csvSt -finding "CredSSP - Not allowing delegation of default credentials with NTLM-only." -risk $csvR3
        
        }
    }

    #Allow delegating saved credentials
    writeToFile -file $outputFile -path $folderLocation -str "`r`n------------- Allow delegation of saved credentials -------------"
    writeToFile -file $outputFile -path $folderLocation -str "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "AllowSavedCredentials"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Allowing delegation of saved credentials - No configuration found default setting is set to true. - After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials" -checkID "domain_CredSSPSavedCred" -status $csvOp -finding "CredSSP - Allowing delegation of saved credentials. - default setting set to true." -comment "After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine." -risk $csvR3
    }
    else{
        if($reg.AllowSavedCredentials -eq 1){
            $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $booltest = $false
            $serverList =""
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
                if($serverList -eq ""){
                    $serverList = $item
                }
                else{
                    $serverList += ", $item"
                }
            }
            if($booltest){
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of saved credentials for any server."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials" -checkID "domain_CredSSPSavedCred" -status $csvOp -finding "CredSSP - Allows delegation of saved credentials for any server. Server list:$serverList" -risk $csvR3
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of saved credentials for servers."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials" -checkID "domain_CredSSPSavedCred" -status $csvOp -finding "CredSSP - Allows delegation of saved credentials for servers. Server list:$serverList" -risk $csvR3
            }
            writeToFile -file $outputFile -path $folderLocation -str " > Server list: $serverList"
            }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Not allowing delegation of saved credentials."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials" -checkID "domain_CredSSPSavedCred" -status $csvSt -finding "CredSSP - Not allowing delegation of saved credentials." -risk $csvR3
        
        }
        }

    #Allow delegating saved credentials with NTLM-only server authentication
    writeToFile -file $outputFile -path $folderLocation -str "`r`n-------------Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $outputFile -path $folderLocation -str "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "AllowSavedCredentialsWhenNTLMOnly"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials with NTLM-Only" -checkID "domain_CredSSPSavedCredNTLM" -status $csvOp -finding "CredSSP - Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true." -risk $csvR3

    }
    else{
        if($reg.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $booltest = $false
            $serverList =""
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
                if($serverList -eq ""){
                    $serverList = $item
                }
                else{
                    $serverList += ", $item"
                }
            }
            if($booltest){
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of saved credentials in NTLM for any server."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials with NTLM-Only" -checkID "domain_CredSSPSavedCredNTLM" -status $csvOp -finding "CredSSP - Allows delegation of saved credentials in NTLM for any server. Server list:$serverList" -risk $csvR3
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Allows delegation of saved credentials in NTLM for servers."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials with NTLM-Only" -checkID "domain_CredSSPSavedCredNTLM" -status $csvOp -finding "CredSSP - Allows delegation of saved credentials in NTLM for servers. Server list:$serverList" -risk $csvR3
            }
            writeToFile -file $outputFile -path $folderLocation -str " > Server list: $serverList"
            }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Not allowing delegation of saved credentials with NTLM-only."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allow delegation of saved credentials with NTLM-Only" -checkID "domain_CredSSPSavedCredNTLM" -status $csvSt -finding "CredSSP - Not allowing delegation of saved credentials with NTLM-only." -risk $csvR3
        
        }
    }

    #Deny delegating default credentials
    writeToFile -file $outputFile -path $folderLocation -str "`r`n------------- Deny delegating default credentials -------------"
    writeToFile -file $outputFile -path $folderLocation -str "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials cannot be delegated (default credentials are those that you use when first logging on to Windows)."
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "DenyDefaultCredentials"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > No explicit deny of delegation for default credentials. - No configuration found default setting is set to false."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of default credentials" -checkID "domain_CredSSPDefaultCredDeny" -status $csvOp -finding "CredSSP - Allowing delegation of default credentials - No configuration found default setting is set to false (No explicit deny)." -risk $csvR1

    }
    else{
        if($reg.DenyDefaultCredentials -eq 1){
            $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyDefaultCredentials" -ErrorAction SilentlyContinue
            $booltest = $false
            $serverList =""
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
                if($serverList -eq ""){
                    $serverList = $item
                }
                else{
                    $serverList += ", $item"
                }
            }
            if($booltest){
                writeToFile -file $outputFile -path $folderLocation -str " > Denying delegation of default credentials for any server."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of default credentials" -checkID "domain_CredSSPDefaultCredDeny" -status $csvSt -finding "CredSSP - Do not allow delegation of default credentials for any server. Server list:$serverList" -risk $csvR1
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Denying delegation of default credentials."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of default credentials" -checkID "domain_CredSSPDefaultCredDeny" -status $csvSt -finding "CredSSP - Do not allow delegation of default credentials. Server list:$serverList" -risk $csvR1
            }
            writeToFile -file $outputFile -path $folderLocation -str " > Server list: $serverList"
            }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > No explicit deny of delegation for default credentials."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of default credentials" -checkID "domain_CredSSPDefaultCredDeny" -status $csvOp -finding "CredSSP - Allowing delegation of default credentials." -risk $csvR1
        
        }
    }
    #Deny delegating saved credentials
    writeToFile -file $outputFile -path $folderLocation -str "`r`n------------- Deny delegating saved credentials -------------"
    writeToFile -file $outputFile -path $folderLocation -str "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials cannot be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "DenySavedCredentials"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Deny delegation of saved credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of saved credentials" -checkID "domain_CredSSPSavedCredDeny" -status $csvOp -finding "CredSSP - No Specific deny list for delegations of saved credentials exist." -comment "No configuration found default setting is set to false (No explicit deny)." -risk $csvR1

    }
    else{
        if($reg.DenySavedCredentials -eq 1){
            $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenySavedCredentials" -ErrorAction SilentlyContinue
            $booltest = $false
            $serverList =""
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
                if($serverList -eq ""){
                    $serverList = $item
                }
                else{
                    $serverList += ", $item"
                }
            }
            if($booltest){
                writeToFile -file $outputFile -path $folderLocation -str " > Denying delegation of saved credentials for any server."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of saved credentials" -checkID "domain_CredSSPSavedCredDeny" -status $csvSt -finding "CredSSP - Do not allow delegation of saved credentials for any server. Server list:$serverList" -risk $csvR1
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > Denying delegation of saved credentials."
                addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of saved credentials" -checkID "domain_CredSSPSavedCredDeny" -status $csvSt -finding "CredSSP - Do not allow delegation of saved credentials. Server list:$serverList" -risk $csvR1
            }
            writeToFile -file $outputFile -path $folderLocation -str " > Server list: $serverList"
            }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > No explicit deny of delegations for saved credentials."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Deny delegation of saved credentials" -checkID "domain_CredSSPSavedCredDeny" -status $csvOp -finding "CredSSP - No Specific deny list for delegations of saved credentials exist (Setting is disabled)" -risk $csvR1
        
        }
    }
    #Remote host allows delegation of non-exportable credentials
    writeToFile -file $outputFile -path $folderLocation -str "`r`n------------- Remote host allows delegation of non-exportable credentials -------------"
    writeToFile -file $outputFile -path $folderLocation -str "Remote host allows delegation of non-exportable credentials.`r`nWhen using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host.`r`nIf the Policy is enabled, the host supports Restricted Admin or Remote Credential Guard mode. "
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "AllowProtectedCreds"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Remote host allows delegation of non-exportable credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allows delegation of non-exportable credentials" -checkID "domain_CredSSPNonExportableCred" -status $csvOp -finding "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported. (Default Setting)" -comment "User will always need to pass their credentials to the host." -risk $csvR2

    }
    else{
        if($reg.AllowProtectedCreds -eq 1){
            writeToFile -file $outputFile -path $folderLocation -str " > The host supports Restricted Admin or Remote Credential Guard mode."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allows delegation of non-exportable credentials" -checkID "domain_CredSSPNonExportableCred" -status $csvSt -finding "CredSSP - The host supports Restricted Admin or Remote Credential Guard mode" -risk $csvR2
            }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Restricted Administration and Remote Credential Guard mode are not supported. - User will always need to pass their credentials to the host."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Allows delegation of non-exportable credentials" -checkID "domain_CredSSPNonExportableCred" -status $csvOp -finding "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported." -comment "User will always need to pass their credentials to the host." -risk $csvR2
        
        }
    }
    #Restrict delegation of credentials to remote servers https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsSSP::RestrictedRemoteAdministration
    writeToFile -file $outputFile -path $folderLocation -str "`r`n------------- Restrict delegation of credentials to remote servers -------------"
    writeToFile -file $outputFile -path $folderLocation -str "When running in Restricted Admin or Remote Credential Guard mode, participating apps do not expose signed in or supplied credentials to a remote host. Restricted Admin limits access to resources located on other servers or networks from the remote host because credentials are not delegated. Remote Credential Guard does not limit access to resources because it redirects all requests back to the client device. - Supported apps: RDP"
    writeToFile -file $outputFile -path $folderLocation -sty "Restrict credential delegation: Participating applications must use Restricted Admin or Remote Credential Guard to connect to remote hosts."
    writeToFile -file $outputFile -path $folderLocation -sty "Require Remote Credential Guard: Participating applications must use Remote Credential Guard to connect to remote hosts."
    writeToFile -file $outputFile -path $folderLocation -sty "Require Restricted Admin: Participating applications must use Restricted Admin to connect to remote hosts."
    writeToFile -file $outputFile -path $folderLocation -str "Note: To disable most credential delegation, it may be sufficient to deny delegation in Credential Security Support Provider (CredSSP) by modifying Administrative template settings (located at Computer Configuration\Administrative Templates\System\Credentials Delegation).`r`n Note: On Windows 8.1 and Windows Server 2012 R2, enabling this policy will enforce Restricted Administration mode, regardless of the mode chosen. These versions do not support Remote Credential Guard."
    $reg = getRegValue -HKLM $true -regPath "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -regName "RestrictedRemoteAdministration"
    if($null -eq $reg){
        writeToFile -file $outputFile -path $folderLocation -str " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
        addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Restrict delegation of credentials to remote servers" -checkID "domain_CredSSPResDelOfCredToRemoteSrv" -status $csvOp -finding "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices. - Default Setting" -risk $csvR2

    }
    else{
        if($reg.RestrictedRemoteAdministration -eq 1){
            writeToFile -file $outputFile -path $folderLocation -str " > Restrict delegation of credentials to remote servers is enabled - Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin"
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Restrict delegation of credentials to remote servers" -checkID "domain_CredSSPResDelOfCredToRemoteSrv" -status $csvOp -finding "Restrict delegation of credentials to remote servers is enabled" -comment "Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin" -risk $csvR2
            }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
            addToCSV -relatedFile $outputFile -category "Machine Hardening - Authentication" -checkName "CredSSP - Restrict delegation of credentials to remote servers" -checkID "domain_CredSSPResDelOfCredToRemoteSrv" -status $csvOp -finding "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices." -risk $csvR2
        
        }
    }

}

### General values
# get hostname to use as the folder name and file names
$hostname = hostname
#CSV Status Types
$csvOp = "Opportunity" ; $csvSt = "Strength" ; $csvUn = "Unknown"
#CSV Risk level
$csvR1 = "Informational" ; $csvR2 = "Low" ; $csvR3 = "Medium" ; $csvR4 = "High" ; $csvR5 = "Critical"
$isDomainController = $false
$partOfDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if($partOfDomain){
    $domainName = ((Get-WmiObject -class Win32_ComputerSystem).Domain)
    # add is DC check 
    $folderRootLocation = $hostname+"_"+$domainName
    $folderLocation = $folderRootLocation +"\Detailed information"
}
else{
    $temp = (Get-WMIObject win32_operatingsystem).name
    $temp = $temp.Replace(" ","")
    $temp = $temp.Trim("Microsoft")
    $temp = $temp.Replace("Windows","Win")
    $temp = $temp.Substring(0,$temp.IndexOf("|"))
    $folderRootLocation = $hostname+"_"+$temp
    $folderLocation = $folderRootLocation +"\Detailed information"
}
if(Test-Path $folderRootLocation){
    Remove-Item -Recurse -Path $folderRootLocation -Force -ErrorAction SilentlyContinue |Out-Null
}
try{
    New-Item -Path $folderRootLocation -ItemType Container -Force |Out-Null
    New-Item -Path $folderLocation -ItemType Container -Force |Out-Null
}
catch{
    writeToScreen -ForegroundColor "Red" -str "Failed to create folder for output in:"$pwd.Path
    exit -1
}

$transcriptFile = getNameForFile -name "Log-ScriptTranscript" -extension ".txt"
# get the windows version for later use
$winVersion = [System.Environment]::OSVersion.Version
# powershell version 
$psVer = Get-Host | Select-Object Version
$psVer = $psVer.Version.Major
if($psVer -ge 4){
    Start-Transcript -Path ($folderRootLocation + "\" + $transcriptFile) -Append -ErrorAction SilentlyContinue
}
else{
    writeToLog -str " Transcript creation is not passible running in powershell v2"
}
$script:checksArray = @()
### start of script ###
$startTime = Get-Date
writeToScreen -str "Hello dear user!" -ForegroundColor "Green"
writeToScreen -str "This script will output the results to a folder or a zip file with the name $folderLocation" -ForegroundColor "Green"
#check if running as an elevated admin
$runningAsAdmin = $null -ne (whoami /groups | select-string S-1-16-12288)
if (!$runningAsAdmin)
    {writeToScreen -str "Please run the script as an elevated admin, or else some output will be missing! :-(" -ForegroundColor Red}


# output log
writeToLog -str "Computer Name: $hostname"
addToCSV -category "Information" -checkName "Computer name" -checkID "info_cName" -status $null -finding $hostname -risk $csvR1
addToCSV -category "Information" -checkName "Script version" -checkID "info_sVer" -status $null -finding $Version -risk $csvR1
writeToLog -str ("Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption)
addToCSV -category "Information" -checkName "Windows version" -checkID "info_wVer" -status $null -finding ((Get-WmiObject -class Win32_OperatingSystem).Caption) -risk $csvR1
switch ((Get-WmiObject -Class Win32_OperatingSystem).ProductType){
    1 {
        $OSType = "Workstation"
        $isServer = $false
    }
    2 {
        $OSType = "Domain Controller"
        $isServer = $true
        $isDomainController = $true
    }
    3 {
        $OSType = "Member Server"
        $isServer = $true
    }
    default: {$OSType = "Unknown"}
}
addToCSV -category "Information" -checkName "Computer type" -checkID "info_computerType" -status $null -finding $OSType -risk $csvR1
writeToLog -str  "Part of Domain: $partOfDomain" 
if ($partOfDomain)
{
    addToCSV -category "Information" -checkName "Domain name" -checkID "info_dName" -status $null -finding $domainName -risk $csvR1
    writeToLog -str  ("Domain Name: " + $domainName)
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2)
        {writeToLog -str  "Domain Controller: True" }
    else
        {writeToLog -str  "Domain Controller: False"}    
}
else{
    addToCSV -category "Information" -checkName "Domain name" -checkID "info_dName" -status $null -finding "WorkGroup" -risk $csvR1
}
$user = whoami
writeToLog -str "Running User: $user"
writeToLog -str "Running As Admin: $runningAsAdmin"
$uptimeDate = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
writeToLog -str ("System Uptime: Since " + $uptimeDate.ToString("dd/MM/yyyy HH:mm:ss")) 
writeToLog -str "Script Version: $Version"
writeToLog -str "Powershell version running the script: $psVer"
writeToLog -str ("Script Start Time: " + $startTime.ToString("dd/MM/yyyy HH:mm:ss") )

####Start of Checks
#########################################################

# get current user privileges
dataWhoAmI -name "Whoami"

# get IP settings
dataIpSettings -name "Ipconfig"

# test proxy settings
checkProxyConfiguration -name "Internet-Connectivity"

# test for internet connectivity
checkInternetAccess -name "Internet-Connectivity"

# get network connections (run-as admin is required for -b associated application switch)
getNetCon -name "Netstat"

# get GPOs
dataGPO -name "GPResult"

# get security policy settings (secpol.msc), run as admin is required
dataSecurityPolicy -name "Security-Policy"

# get windows features (Windows vista/2008 or above is required)
dataWinFeatures -name "Windows-Features"

# get installed hotfixes (/format:htable doesn't always work)
dataInstalledHotfixes -name "Hotfixes"

# check Windows update configuration
checkWinUpdateConfig -name "Windows-updates"

# get processes (new powershell version and run-as admin are required for IncludeUserName)
dataRunningProcess -name "Process-list"

# get services
dataServices -name "Services"

# check for unquoted path vulnerability in services running on the machine
checkUnquotedSePath -name "Services"

# get installed software
dataInstalledSoftware -name "Software"

# get shared folders (share permissions are missing for older PowerShell versions)
dataSharedFolders -name "Shares"

# get local and domain account policy
dataAccountPolicy -name "AccountPolicy"

# get local users and admins
dataLocalUsers -name "Local-Users"

# NTLMv2 enforcement check
checkNTLMv2 -name "Domain-authentication"

# check SMB protocol hardening
checkSMBHardening -name "SMB"

# Getting RDP security settings
checkRDPSecurity -name "RDP"

# getting credential guard settings (for Windows 10/2016 and above only)
checkCredentialGuard -name "Credential-Guard"

# getting LSA protection configuration (for Windows 8.1 and above only)
checkLSAProtectionConf -name "LSA-Protection"

# get antivirus status
checkAntiVirusStatus -name "Antivirus"

# get Windows Firewall configuration
dataWinFirewall -name "Windows-Firewall"

# check if LLMNR and NETBIOS-NS are enabled
checkLLMNRAndNetBIOS -name "LLMNR_and_NETBIOS"

# check if cleartext credentials are saved in lsass memory for WDigest
checkWDigest -name "WDigest"

# check for Net Session enumeration permissions
checkNetSessionEnum -name "NetSession"

# check for SAM enumeration permissions
checkSAMEnum -name "SAM-Enumeration"

# check for PowerShell v2 installation, which lacks security features (logging, AMSI)
checkPowershellVer -name "PowerShell-Versions"

# GPO reprocess check
checkGPOReprocess -name "GPO-reprocess"

# Command line Audit settings check
checkCommandLineAudit -name "Audit-Policy"

# Powershell Audit settings check
checkPowerShellAudit -name "Audit-Policy"

# Check Event Log size
checkLogSize -name "Audit-Policy"

# Audit policy settings check
dataAuditPolicy -name "Audit-Policy"

# Check always install elevated setting
checkInstallElevated -name "Machine-Hardening"

# Check if safe mode access by non-admins is blocked
checkSafeModeAcc4NonAdmin -name "Machine-Hardening"

# Check if there is hardening preventing user from connecting to multiple networks simultaneous 
checkSimulEhtrAndWifi -name "Internet-Connectivity"

# Get Kerberos security settings
checkKerberos -name "Domain-authentication"

# Check if credentials and password are stored in LSASS for network authentication.
checkPrevStorOfPassAndCred  -name "Domain-authentication"

# Check CredSSP configuration
checkCredSSP -name "CredSSP"

# search for sensitive information (i.e., cleartext passwords) if the flag exists
checkSensitiveInfo -name "Sensitive-Info"

# get various system info (can take a few seconds)
dataSystemInfo -name "Systeminfo"

# Add Controls list to CSV file
addControlsToCSV


#########################################################

$script:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | Export-Csv -Path ($folderRootLocation+"\"+(getNameForFile -name "Hardening_Checks_BETA" -extension ".csv")) -NoTypeInformation -ErrorAction SilentlyContinue
if($psVer -ge 3){
    $script:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | ConvertTo-Json | Add-Content -Path ($folderRootLocation+"\"+(getNameForFile -name "Hardening_Checks_BETA" -extension ".json"))
}


$currTime = Get-Date
writeToLog -str ("Script End Time (before zipping): " + $currTime.ToString("dd/MM/yyyy HH:mm:ss"))
writeToLog -str ("Total Running Time (before zipping): " + [int]($currTime - $startTime).TotalSeconds + " seconds")  
if($psVer -ge 4){
    Stop-Transcript
}

# compress the files to a zip. works for PowerShell 5.0 (Windows 10/2016) only. sometimes the compress fails because the file is still in use.
if($psVer -ge 5){
    $fullPath = Get-Location
    $fullPath = $fullPath.path
    $fullPath += "\"+$folderRootLocation
    $zipLocation = $fullPath+".zip"
    if(Test-Path $zipLocation){
        Remove-Item -Force -Path $zipLocation
    }
    Compress-Archive -Path $folderRootLocation\* -DestinationPath $zipLocation -Force -ErrorAction SilentlyContinue
    if(Test-Path $zipLocation){
        Remove-Item -Recurse -Force -Path $folderRootLocation -ErrorAction SilentlyContinue
        writeToScreen -str "All Done! Please send the output ZIP file." -ForegroundColor Green
    }
    else{
        writeToScreen -str "All Done! Please ZIP all the files and send it back." -ForegroundColor Green
        writeToLog -str "failed to create a zip file unknown reason"
    }
    
    
}
elseif ($psVer -eq 4 ) {
        $fullPath = Get-Location
        $fullPath = $fullPath.path
        $fullPath += "\"+$folderRootLocation
        $zipLocation = $fullPath+".zip"
        if(Test-Path $zipLocation){
            Remove-Item -Force -Path $zipLocation
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($fullPath,$zipLocation)
        if(Test-Path $zipLocation){
            Remove-Item -Recurse -Force -Path $folderRootLocation -ErrorAction SilentlyContinue
            writeToScreen -str "All Done! Please send the output ZIP file." -ForegroundColor Green
        }
        else{
            writeToScreen -str "All Done! Please ZIP all the files and send it back." -ForegroundColor Green
            writeToLog -str "failed to create a zip file unknown reason"
        }
}
else{
    writeToScreen -str "All Done! Please ZIP all the files and send it back." -ForegroundColor Green
    writeToLog -str "powershell running the script is below version 4 script is not supporting compression to zip below that"
}

$endTime = Get-Date
$elapsed = $endTime - $startTime
writeToScreen -str ("The script took "+([int]$elapsed.TotalSeconds) +" seconds. Thank you.") -ForegroundColor Green
Start-Sleep -Seconds 2
