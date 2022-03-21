param ([Switch]$EnableSensitiveInfoSearch = $false)
# add the "EnableSensitiveInfoSearch" flag to search for sensitive data

$Version = "1.21" # used for logging purposes
###########################################################
<# TODO:
- Output the results to a single file with a simple table
- Improve the Firewall Rules export functionality - integrate Nir's offer (currently commented out) - Done
- Add OS version into the output file name (for example, "SERVERNAME_Win2008R2")
- Add AD permissions checks from here: https://github.com/haim-n/ADDomainDaclAnalysis
- Check for bugs in the SMB1 check
- Log errors to a log file using Start/Stop-Transcript
- Debug the FirewallProducts check
- Check for Windows Update / WSUS settings, check for WSUS over HTTP (reg key)
- Update PSv2 checks - speak with Nir/Liran, use this: https://robwillis.info/2020/01/disabling-powershell-v2-with-group-policy/, https://github.com/robwillisinfo/Disable-PSv2/blob/master/Disable-PSv2.ps1
- Debug the RDP check on multiple OS versions
- Integrate more checks from https://adsecurity.org/?p=3299
- Determine more stuff that are found only in the Security-Policy/GPResult files:
-- Check Kerberos encryption algorithms
-- Determine if local users can connect over the network ("Deny access to this computer from the network")
-- Check the CredSSP registry key - Allow delegating default credentials (general and NTLM)
-- Determine if the local administrators group is configured as a restricted group with fixed members (based on Security-Policy inf file)
-- Determine if Domain Admins cannot login to lower tier computers (Security-Policy inf file: Deny log on locally/remote/service/batch)
- Determine if computer is protected against IPv6 based DNS spoofing (mitm6) - IPv6 disabled (Get-NetAdapterBinding -ComponentID ms_tcpip6) or inbound ICMPv6 / outbound DHCPv6 blocked by FW
- Add WPAD check
- Test on Windows 2008
- Check AV/Defender configuration also on non-Windows 10
- Move lists to CSV format instead of TXT
- When the script is running by an admin but without UAC, pop an UAC confirmation (https://gallery.technet.microsoft.com/scriptcenter/1b5df952-9e10-470f-ad7c-dc2bdc2ac946)
- Check event log size settings
- Check Macro and DDE (OLE) settings
- Check if safe mode access by non-admins is blocked (based on SafeModeBlockNonAdmins reg value)
- Check if ability to enable mobile hotspot is blocked (GPO Prohibit use of Internet Connection Sharing on your DNS domain network, reg NC_ShowSharedAccessUI)
- Look for additional checks from windows_hardening.cmd script / Seatbelt
- Enhance internet connectivity checks (add traceroute, curl to websites over http/s, use proxy configuration, test TCP on few sample ports towards portquiz)
- Check if internet DNS servers (8.8.8.8, etc.) are accessible
- Check for Lock with screen saver after time-out (\Control Panel\Personalization\) and "Interactive logon: Machine inactivity limit"? Relevant mostly for desktops
- Check for Device Control (GPO or dedicated software)
- Check ability to connect to Wi-Fi while connected to wired (Interface settings \ Disable Upon Wired Connect)
- Find misconfigured services which allow elevation of privileges
- Add More settings from hardening docs
- Log the time of each operation to the log file (create a function for it and reuse)
- Run the script from remote location to a list of servers - psexec, remote ps, etc.
- Change script structure to functions - Done
##########################################################
Controls Checklist:
- OS is up to date (hotfixes file shows recent updates)
- LSA Protection is enabled (LSA-Protection file, Win 8.1/2012R2 and above)
- Credential guard is running (Credential-Guard file, Win 10/2016 and above)
- SMB Signing is enforced (SMB file)
- SMB1 Server is not installed (SMB file)
- NTLMv2 is enforced  (Domain-Hardning file)
- LLMNR is disabled (LLMNR_and_NETBIOS file)
- NETBIOS Name Service is disabled (LLMNR_and_NETBIOS file)
- WDigest is disabled (WDigest file)
- Net Session permissions are hardened (NetSession file)
- SAM enumeration permissions are hardened (SAM-Enumeration file)
- RDP timeout for disconnected sessions is configured (RDP file)
- RDP NLA is required (RDP file)
- PowerShell v2 is uninstalled (PowerShellv2 file, and/or Windows-Features file: PowerShell-V2 feature)
- PowerShell logging is enabled (Audit-Policy file)
- Audit policy is sufficient (Audit-Policy file, admin needed)
- Only AES encryption is allowed for Kerberos, especially on Domain Controllers (Security-Policy inf file: Network security: Configure encryption types allowed for Kerberos, admin needed)
- Local users are all disabled or have their password rotated (Local-Users file) or cannot connect over the network (Security-Policy inf file: Deny access to this computer from the network)
- Group policy settings are reapplied even when not changed (gpresult file: Administrative Templates > System > Group Policy > Configure registry policy processing, admin needed)
- Credential delegation is not configured or disabled (gpresult file: Administrative Templates > System > Credentials Delegation > Allow delegating default credentials + with NTLM, admin needed)
- Local administrators group is configured as a restricted group with fixed members (Security-Policy inf file: Restricted Groups, admin needed)
- Access to SCCM server configured with encrypted HTTPS (gpresult file: Windows Components> Windows Update > Specify intranet Microsoft update service location)
- Number of cached credentials is limited (Security-Policy inf file: Interactive logon: Number of previous logons to cache, admin needed)
- UAC is enabled (Security-Policy inf file: User Account Control settings, admin needed)
- Antivirus is running and updated, advanced Windows Defender features are utilized (AntiVirus file)
- Domain Admins cannot login to lower tier computers (Security-Policy inf file: Deny log on locally/remote/service/batch, admin needed)
- Service Accounts cannot login interactively (Security-Policy inf file: Deny log on locally/remote, admin needed)
- Local and domain password policies are sufficient (AccountPolicy file)
- No overly permissive shares exists (Shares file)
- No clear-text passwords are stored in files (Sensitive-Info file - if the EnableSensitiveInfoSearch was set)
- Reasonable number or users/groups have local admin permissions (Local-Users file)
- User Rights Assignment privileges don't allow privilege escalation by non-admins (Security-Policy inf file: User Rights Assignment, admin needed)
- Services are not running with overly permissive privileges (Services file)
- No irrelevant/malicious processes/services/software exists (Services, Process-list, Software, Netstat files)
- Outbound internet access is restricted (Internet-Connectivity file)
- Event Log size is enlarged and/or logs are exported to SIEM
- Macros are restricted
- Defender ASR rules are configured (AntiVirus file)
- Host firewall rules are configured to block inbound (Windows-Firewall and Windows-Firewall-Rules files)
- GPO Enforce reprocess check (Domain-Hardning file)
- Always install with elevated privileges setting (Domain-Hardning file)
##########################################################
@Haim Nachmias @Nital Ruzin
##########################################################>

### functions
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

#funtion that writes to file gets 3 params (path = folder , file = file name , str string to write in the file)
function writeToFile {
    param (
        $path, $file, $str
    )
    if (!(Test-Path "$path\$file"))
    {
        New-Item -path $path -name $file -type "file" -value $str | Out-Null
        writeToFile -path $path -file $file -str""
    }
    else
    {
        Add-Content -path "$path\$file" -value $str -
    } 
}
#function that writes the log file
function writeToLog {
    param (
        [string]$str
    )
    $stemp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $logMassage = "$stemp $str"
    writeToFile -path $hostname -file "Log_$hostname.txt" -str $logMassage
}

function getNameForFile{
    param(
        $name,
        $extention
    )
    if($null -eq $extention){
        $extention = ".txt"
    }
    return ($name + "_" + $hostname+$extention)
}
# get current user privileges
function dataWhoAmI {
    param (
        $name 
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Running whoami..." -ForegroundColor Yellow
    writeToLog -str "running DataWhoAmI function"
    writeToFile -file $outputFile -path $folderLocation -str "`Output of `"whoami /all`" command:`r`n"
    # when running whoami /all and not connected to the domain, claims information cannot be fetched and an error occurs. Temporarily silencing errors to avoid this.
    #$PrevErrorActionPreference = $ErrorActionPreference
    #$ErrorActionPreference = "SilentlyContinue"
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (!(Test-ComputerSecureChannel)))
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
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Running ipconfig..." -ForegroundColor Yellow
    writeToLog -str "running DataIpSettings function"
    writeToFile -file $outputFile -path $folderLocation -str "`Output of `"ipconfig /all`" command:`r`n" 
    writeToFile -file $outputFile -path $folderLocation -str (ipconfig /all) 
}

# test for internet connectivity
function checkInternetAccess{
    param (
        $name 
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkInternetAccess function"
    writeToScreen -str "Trying to ping the internet..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= ping -n 2 8.8.8.8 =============" 
    writeToFile -file $outputFile -path $folderLocation -str (ping -n 2 8.8.8.8)
    # more detailed test for newer PowerShell versions - takes a lot of time and not very important
    #try {
        # "============= Test-NetConnection -InformationLevel Detailed =============" | Out-File $outputFileName -Append
        # Test-NetConnection -InformationLevel Detailed | Out-File $outputFileName -Append
        #"============= Test-NetConnection -ComputerName www.google.com -Port 443 -InformationLevel Detailed =============" | Out-File $outputFileName -Append
        #Test-NetConnection -ComputerName www.google.com -Port 443 -InformationLevel Detailed | Out-File $outputFileName -Append
    #}
    #catch {"Test-NetConnection command doesn't exists, old powershell version." | Out-File $outputFileName -Append}
}

# get network connections (run-as admin is required for -b associated application switch)
function getNetCon {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running getNetCon function"
    writeToScreen -str "Running netstat..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= netstat -nao ============="
    writeToFile -file $outputFile -path $folderLocation -str (netstat -nao)
    writeToFile -file $outputFile -path $folderLocation -str "============= netstat -naob (includes process name, elevated admin permission is required ============="
    writeToFile -file $outputFile -path $folderLocation -str (netstat -naob)
# "============= netstat -ao  =============" | Out-File $outputFileName  -Append
# netstat -ao | Out-File $outputFileName -Append  # shows server names, but takes a lot of time and not very important
}

#get gpo
function dataGPO {
    param (
        $name
    )
    writeToLog -str "running dataGPO function"
    # check if the computer is in a domain
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        # check if we have connectivity to the domain, or if is a DC
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            $gpoPath = $folderLocation+"\"+(getNameForFile -name $name -extention ".html")
            writeToScreen -str "Running GPResult to get GPOs..." -ForegroundColor Yellow
            gpresult /f /h $gpoPath
            # /h doesn't exists on Windows 2003, so we run without /h into txt file
            if (!(Test-Path $gpoPath)) {
                writeToLog -str "Function dataGPO: gpresult faild to export to HTML exporting in txt format"
                $gpoPath = $folderLocation+"\"+(getNameForFile -name $name -extention ".txt")
                gpresult $gpoPath
            }
            else{
                writeToLog -str "Function dataGPO: gpresult exported successfully "
            }
        }
        else
        {
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
    $sPPath = $hostname+"\"+(getNameForFile -name $name -extention ".inf")
    if ($runningAsAdmin)
    {
        writeToScreen -str "Getting security policy settings..." -ForegroundColor Yellow
        secedit /export /CFG $sPPath | Out-Null
        if(!(Test-Path $sPPath)){
            writeToLog -str "Function dataSecurityPolicy: failed to export security policy unknown resone"
        }
    }
    else
    {
        writeToScreen -str "Unable to get security policy settings... elevated admin permissions are required" -ForegroundColor Red
        writeToLog -str "Function dataSecurityPolicy: Unable to get security policy settings... elevated admin permissions are required"
    }
}

# get windows features (Windows vista/2008 or above is required)
function dataWinFeatures {
    param (
        $name
    )
    writeToLog -str "running dataWinFeatures function"
    $outputFile = getNameForFile -name $name -extention ".txt"

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
                writeToFile -file $outputFile -path $folderLocation -str "============= Output of: Get-WindowsFeature =============" 
                $temp = Get-WindowsFeature | Format-Table -AutoSize | Out-String
                writeToFile -file $outputFile -path $folderLocation -str $temp
            }
        }
        else{
            writeToLog -str "Function dataWinFeatures: unable to run Get-WindowsFeature - requare wubdiws server 2008R2 and above and powershell version 4"
        }
        # get features with Get-WindowsOptionalFeature. Requires Windows 8/2012 or above and run-as-admin
        if ($psVer -ge 4 -and (($winVersion.Major -ge 7) -or ($winVersion.Minor -ge 2))) # version should be 7+ or 6.2+
        {
            writeToFile -file $outputFile -path $folderLocation -str "============= Output of: Get-WindowsOptionalFeature -Online ============="
            if ($runningAsAdmin)
                {
                    $temp = Get-WindowsOptionalFeature -Online | Sort-Object FeatureName | Format-Table | Out-String
                    writeToFile -file $outputFile -path $folderLocation -str $temp
                }
            else
                {writeToFile -file $outputFile -path $folderLocation -str "Unable to run Get-WindowsOptionalFeature without running as admin. Consider running again with elevated admin permissions."}
        }
        else {
            writeToLog -str "Function dataWinFeatures: unable to run Get-WindowsOptionalFeature - requare wubdiws server 8/2008R2 and above and powershell version 4"
        }
        # get features with dism. Requires run-as-admin
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

# get installed hotfixes (/format:htable doesn't always work)
function dataInstalledHotfixes {
    param (
        $name
    )
    writeToLog -str "running dataInstalledHotfixes function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Getting installed hotfixes..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str ("The OS version is: " + [System.Environment]::OSVersion + ". See if this version is supported according to the following pages:")
    writeToFile -file $outputFile -path $folderLocation -str "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" 
    writeToFile -file $outputFile -path $folderLocation -str "https://en.wikipedia.org/wiki/Windows_10_version_history" 
    writeToFile -file $outputFile -path $folderLocation -str "https://support.microsoft.com/he-il/help/13853/windows-lifecycle-fact-sheet" 
    writeToFile -file $outputFile -path $folderLocation -str "Output of `"Get-HotFix`" PowerShell command, sorted by installation date:`r`n" 
    writeToFile -file $outputFile -path $folderLocation -str (Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue )
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
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Getting processes..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str  "Output of `"Get-Process`" PowerShell command:`r`n"
    try {
        writeToFile -file $outputFile -path $folderLocation -str (Get-Process -IncludeUserName | Format-Table -AutoSize ProcessName, id, company, ProductVersion, username, cpu, WorkingSet | Out-String -Width 180 | Out-String) 
    }
    # run without IncludeUserName if the script doesn't have elevated permissions or for old powershell versions
    catch {
        writeToFile -file $outputFile -path $folderLocation -str (Get-Process | Format-Table -AutoSize ProcessName, id, company, ProductVersion, cpu, WorkingSet | Out-String -Width 180 | Out-String)
    }
        
}

# get services
function dataServices {
    param (
        $name
    )
    writeToLog -str "running dataServices function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Getting services..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "Output of `"Get-WmiObject win32_service`" PowerShell command:`r`n"
    writeToFile -file $outputFile -path $folderLocation -str (Get-WmiObject win32_service  | Sort-Object displayname | Format-Table -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-String)
}

# get installed software
function dataInstalledSoftware{
    param(
        $name
    )
    writeToLog -str "running dataInstalledSoftware function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Getting installed software..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Out-String -Width 180 | Out-String)
}

# get shared folders (Share permissions are missing for older PowerShell versions)
function dataSharedFolders{
    param(
        $name
    )
    writeToLog -str "running dataSharedFolders function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Getting shared folders..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= Shared Folders ============="
    $shares = Get-WmiObject -Class Win32_Share
    writeToFile -file $outputFile -path $folderLocation -str $shares
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
    $outputFile = getNameForFile -name $name -extention ".txt"
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
    $outputFile = getNameForFile -name $name -extention ".txt"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2)
    {
        writeToScreen -str "Getting local users + administrators..." -ForegroundColor Yellow
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
                writeToLog -str "Function dataLocalUsers: unsupported powershell version to run Get-CimInstance skiping..."
            }
        }
    }
    
}

# check SMB protocol hardening
function checkSMBHardening {
    param (
        $name
    )
    writeToLog -str "running checkSMBHardening function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Getting SMB hardening configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= SMB versions Support (Server Settings) =============" 
    # Check if Windows Vista/2008 or above and powershell version 4 and up 
    if ($winVersion.Major -ge 6)
    {
        
        $SMB1 = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters SMB1 -ErrorAction SilentlyContinue
        $SMB2 = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters SMB2 -ErrorAction SilentlyContinue
        if ($SMB1.SMB1 -eq 0)
            {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is not supported (based on registry values). Which is nice." }
        else
            {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is supported (based on registry values). Which is pretty bad and a finding." }
        # unknown var will all return false always
        <#
        if (!$smbConfig.EnableSMB1Protocol) 
            {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is not supported (based on Get-SmbServerConfiguration). Which is nice."}
        else
            {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Server is supported (based on Get-SmbServerConfiguration). Which is pretty bad and a finding."}
            writeToFile -file $outputFile -path $folderLocation -str "---------------------------------------" 
        #>
        if ($SMB2.SMB2 -eq 0)
            {writeToFile -file $outputFile -path $folderLocation -str "SMB2 and SMB3 Server are not supported (based on registry values). Which is weird, but not a finding." }
        else
            {writeToFile -file $outputFile -path $folderLocation -str "SMB2 and SMB3 Server are supported (based on registry values). Which is OK." }
        if($psVer -ge 4){
            $smbServerConfig = Get-SmbServerConfiguration
            $smbClientConfig = Get-SmbClientConfiguration
            if (!$smbServerConfig.EnableSMB2Protocol)
                {writeToFile -file $outputFile -path $folderLocation -str "SMB2 Server is not supported (based on Get-SmbServerConfiguration). Which is weird, but not a finding." }
            else
                {writeToFile -file $outputFile -path $folderLocation -str "SMB2 Server is supported (based on Get-SmbServerConfiguration). Which is OK." }
        }
        
    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "Old Windows versions (XP or 2003) support only SMB1." 
        writeToLog -str "Function checkSMBHardening: unable to run windows too old"
    }
    writeToFile -file $outputFile -path $folderLocation -str "============= SMB versions Support (Client Settings) ============="
    # Check if Windows Vista/2008 or above
    if ($winVersion.Major -ge 6)
    {
        $SMB1Client = (sc.exe qc lanmanworkstation | Where-Object {$_ -like "*START_TYPE*"}).split(":")[1][1]
        Switch ($SMB1Client)
        {
            "0" {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." }
            "1" {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'System'. Which is not weird. although disabled is better."}
            "2" {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must."}
            "3" {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better."}
            "4" {writeToFile -file $outputFile -path $folderLocation -str "SMB1 Client is set to 'Disabled'. Which is nice."}
        }
    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "Old Windows versions (XP or 2003) support only SMB1."
    }
    writeToFile -file $outputFile -path $folderLocation -str "============= SMB Signing (Server Settings) ============="
    $SmbServerRequireSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters RequireSecuritySignature
    $SmbServerSupportSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters EnableSecuritySignature
    if ($SmbServerRequireSigning.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (always) = Enabled"
        writeToFile -file $outputFile -path $folderLocation -str "SMB signing is required by the server, Which is good." 
    }
    else
    {
        if ($SmbServerSupportSigning.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (always) = Disabled" 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding."
        }
        else
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (always) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." 
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
    $SmbClientRequireSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters RequireSecuritySignature
    $SmbClientSupportSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters EnableSecuritySignature
    if ($SmbClientRequireSigning.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (always) = Enabled"
        writeToFile -file $outputFile -path $folderLocation -str "SMB signing is required by the client, Which is good." 
    }
    else
    {
        if ($SmbClientSupportSigning.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (always) = Disabled" 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding."
        }
        else
        {
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (always) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $outputFile -path $folderLocation -str "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding."
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
function dataRDPSecuirty {
    param (
        $name
    )
    writeToLog -str "running dataRDPSecuirty function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToScreen -str "Getting RDP security settings..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= Raw RDP Settings (from WMI) ============="
    $WMIFilter = "TerminalName='RDP-tcp'" # there might be issues with the quotation marks - to debug
    $RDP = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter $WMIFilter
    writeToFile -file $outputFile -path $folderLocation -str ($RDP | Format-List Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-String )
    writeToFile -file $outputFile -path $folderLocation -str "============= NLA (Network Level Authentication) ============="
    if ($RDP.UserAuthenticationRequired -eq 1)
        {writeToFile -file $outputFile -path $folderLocation -str "NLA is required, which is fine."}
    if ($RDP.UserAuthenticationRequired -eq 0)
        {writeToFile -file $outputFile -path $folderLocation -str "NLA is not required, which is bad. A possible finding."}
        writeToFile -file $outputFile -path $folderLocation -str "============= Security Layer (SSL/TLS) ============="
    if ($RDP.SecurityLayer -eq 0)
        {writeToFile -file $outputFile -path $folderLocation -str "Native RDP encryption is used instead of SSL/TLS, which is bad. A possible finding." }
    if ($RDP.SecurityLayer -eq 1)
        {writeToFile -file $outputFile -path $folderLocation -str "SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding."}
    if ($RDP.SecurityLayer -eq 2)
        {writeToFile -file $outputFile -path $folderLocation -str "SSL/TLS is required for connecting. Which is good."}
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw RDP Timeout Settings (from Registry) ============="
    $RDPTimeout = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" 
    if ($RDPTimeout.ValueCount -eq 0)
        {writeToFile -file $outputFile -path $folderLocation -str "RDP timeout is not configured. A possible finding."}
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
    } 
}

# getting credential guard settings (for Windows 10/2016 and above only)
function dataCredentialGuard {
    param (
        $name
    )
    writeToLog -str "running dataCredentialGuard function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    if ($winVersion.Major -ge 10)
    {
        writeToScreen -str "Getting credential guard settings..." -ForegroundColor Yellow
        $DevGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        writeToFile -file $outputFile -path $folderLocation -str "============= Credential Guard Settings from WMI ============="
        if ($null -eq $DevGuard.SecurityServicesConfigured)
            {writeToFile -file $outputFile -path $folderLocation -str "The WMI query for Device Guard settings has failed. Status unknown."}
        else {
            if (($DevGuard.SecurityServicesConfigured -contains 1) -and ($DevGuard.SecurityServicesRunning -contains 1))
            {writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is configured and running. Which is good."}
        else
            {writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is turned off. A possible finding."}    
        }
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw Device Guard Settings from WMI (Including Credential Guard) ============="
        writeToFile -file $outputFile -path $folderLocation -str ($DevGuard | Out-String)
        $DevGuardPS = Get-ComputerInfo dev*
        writeToFile -file $outputFile -path $folderLocation -str "============= Credential Guard Settings from Get-ComputerInfo ============="
        if ($null -eq $DevGuardPS.DeviceGuardSecurityServicesRunning)
            {writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is turned off. A possible finding."}
        else
        {
            if ($null -ne ($DevGuardPS.DeviceGuardSecurityServicesRunning | Where-Object {$_.tostring() -eq "CredentialGuard"}))
                {writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is configured and running. Which is good."}
            else
                {writeToFile -file $outputFile -path $folderLocation -str "Credential Guard is turned off. A possible finding."}
        }
        writeToFile -file $outputFile -path $folderLocation -str "============= Raw Device Guard Settings from Get-ComputerInfo ============="
        writeToFile -file $outputFile -path $folderLocation -str ($DevGuardPS | Out-String)
    }
    else{
        writeToLog -str "Function dataCredentialGuard: not supported OS no check is needed..."
    }
    
}

# getting LSA protection configuration (for Windows 8.1 and above only)
function dataLSAProtectionConf {
    param (
        $name
    )
    writeToLog -str "running dataLSAProtectionConf function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    if (($winVersion.Major -ge 10) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -eq 3)))
    {
        writeToScreen -str "Getting LSA protection settings..." -ForegroundColor Yellow
        $RunAsPPL = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL -ErrorAction SilentlyContinue
        if ($null -eq $RunAsPPL)
            {writeToFile -file $outputFile -path $folderLocation -str "RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding."}
        else
        {
            writeToFile -file $outputFile -path $folderLocation -str ("RunAsPPL registry value is: " +$RunAsPPL.RunAsPPL )
            if ($RunAsPPL.RunAsPPL -eq 1)
                {writeToFile -file $outputFile -path $folderLocation -str "LSA protection is on. Which is good."}
            else
                {writeToFile -file $outputFile -path $folderLocation -str "LSA protection is off. Which is bad and a possible finding."}
        }
    }
    else{
        writeToLog -str "Function dataLSAProtectionConf: not supported OS no check is needed"
    }
    
}

# search for sensitive information (i.e. cleartext passwords) if the flag exists
function checkSensitiveInfo {
    param (
        $name
    )   
    $outputFile = getNameForFile -name $name -extention ".txt"
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
            writeToFile -file $outputFile -path $folderLocation -str (Get-ChildItem -Path $path -Include $includeFileTypes -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$hostname.txt"} | Select-String -Pattern password | Out-String)
            # find files with the name pass\cred\config\vnc\p12\pfx and dump the whole file, unless it is too big
            # ignore the files outputted during the assessment...
            $includeFilePatterns = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
            $files = Get-ChildItem -Path $path -Include $includeFilePatterns -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$hostname.txt"}
            foreach ($file in $files)
            {
                writeToFile -file $outputFile -path $folderLocation -str "------------- $file -------------"
                $fileSize = (Get-Item $file.FullName).Length
                if ($fileSize -gt 300kb) {writeToFile -file $outputFile -path $folderLocation -str ("The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB).") }
                else {writeToFile -file $outputFile -path $folderLocation -str (Get-Content $file.FullName)}
            }
        }
    }
    
}

# get anti-virus status
function checkAntiVirusStatus {
    param (
        $name
    )
    writeToLog -str "running checkAntiVirusStatus function"
    $outputFile = getNameForFile -name $name -extention ".txt"
    # works only on Windows Clients, Not on Servers (2008, 2012, etc.). Maybe the "Get-MpPreference" could work on servers - wasn't tested.
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
    {
        writeToScreen -str "Getting Anti-Virus status..." -ForegroundColor Yellow
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
            {writeToFile -file $outputFile -path $folderLocation -str "No Anti Virus products were found."}
            writeToFile -file $outputFile -path $folderLocation -str "============= Anti-Virus Products Status ============="
        foreach ($av in $AntiVirusProducts)
        {    
            writeToFile -file $outputFile -path $folderLocation -str ("Product Display name: " + $av.displayname )
            writeToFile -file $outputFile -path $folderLocation -str ("Product Executable: " + $av.pathToSignedProductExe )
            writeToFile -file $outputFile -path $folderLocation -str ("Time Stamp: " + $av.timestamp)
            writeToFile -file $outputFile -path $folderLocation -str ("Product (raw) state: " + $av.productState)
            # check the product state
            $hx = '0x{0:x}' -f $av.productState
            if ($hx.Substring(3,2) -match "00|01")
                {writeToFile -file $outputFile -path $folderLocation -str "AntiVirus is NOT enabled" }
            else
                {writeToFile -file $outputFile -path $folderLocation -str "AntiVirus is enabled"}
            if ($hx.Substring(5) -eq "00")
                {writeToFile -file $outputFile -path $folderLocation -str "Virus definitions are up to date"}
            else
                {writeToFile -file $outputFile -path $folderLocation -str "Virus definitions are NOT up to date"}
        }
        writeToFile -file $outputFile -path $folderLocation -str "============= Anti-Virus Products Status (Raw Data) ============="
        writeToFile -file $outputFile -path $folderLocation -str ($AntiVirusProducts |Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "============= Firewall Products Status (Raw Data) =============" 
        writeToFile -file $outputFile -path $folderLocation -str ($FirewallProducts | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "============= Anti-Spyware Products Status (Raw Data) =============" 
        writeToFile -file $outputFile -path $folderLocation -str ($AntiSpywareProducts | Out-String)
        # check Windows Defender settings
        writeToFile -file $outputFile -path $folderLocation -str "============= Windows Defender Settings Status =============`r`n"
        $WinDefenderSettings = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        switch ($WinDefenderSettings.AllowRealtimeMonitoring)
        {
            $null {writeToFile -file $outputFile -path $folderLocation -str "AllowRealtimeMonitoring registry value was not found." }
            0 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Real Time Monitoring is off."}
            1 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Real Time Monitoring is on."}
        }
        switch ($WinDefenderSettings.EnableNetworkProtection)
        {
            $null {writeToFile -file $outputFile -path $folderLocation -str "EnableNetworkProtection registry value was not found." }
            0 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Network Protection is off." }
            1 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Network Protection is on."}
            2 {writeToFile -file $outputFile -path $folderLocation -str "Windows Defender Network Protection is set to audit mode."}
        }
        writeToFile -file $outputFile -path $folderLocation -str "---------------------------------"
        writeToFile -file $outputFile -path $folderLocation -str "Values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:"
        writeToFile -file $outputFile -path $folderLocation -str ($WinDefenderSettings | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "---------------------------------" 
        writeToFile -file $outputFile -path $folderLocation -str "Raw output of Get-MpPreference (Defender settings):"
        $MpPreference = Get-MpPreference
        writeToFile -file $outputFile -path $folderLocation -str ($MpPreference | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "---------------------------------" 
        $MpComputerStatus = Get-MpComputerStatus
        writeToFile -file $outputFile -path $folderLocation -str "Enabled Defender features:" 
        writeToFile -file $outputFile -path $folderLocation -str ($MpComputerStatus | Format-List *enabled* | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "Defender Tamper Protection:"
        writeToFile -file $outputFile -path $folderLocation -str ($MpComputerStatus | Format-List *tamper* | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "Raw output of Get-MpComputerStatus:"
        writeToFile -file $outputFile -path $folderLocation -str ($MpComputerStatus | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "---------------------------------" 
        writeToFile -file $outputFile -path $folderLocation -str "Attack Surface Reduction Rules Ids:"
        writeToFile -file $outputFile -path $folderLocation -str ($MpPreference.AttackSurfaceReductionRules_Ids | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "Attack Surface Reduction Rules Actions:"
        writeToFile -file $outputFile -path $folderLocation -str ($MpPreference.AttackSurfaceReductionRules_Actions | Out-String)
        writeToFile -file $outputFile -path $folderLocation -str "Attack Surface Reduction Only Exclusions:" 
        writeToFile -file $outputFile -path $folderLocation -str $MpPreference.AttackSurfaceReductionOnlyExclusions
    }
}

# get Windows Firewall configuration
function dataWinFirewall {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
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
            $temp = $folderLocation + "\" + (getNameForFile -name $name -extention ".csv")
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
            writeToLog -str "Function dataWinFirewall: unable to run NetFirewall commands - skiping (old OS \ powershell is below 4)"
        }
        if ($runningAsAdmin)
        {
            writeToFile -file $outputFile -path $folderLocation -str "----------------------------------`r`n"
            writeToLog -str "Function dataWinFirewall: Exporting to wfw" 
            $temp = $folderLocation + "\" + (getNameForFile -name $name -extention ".wfw")
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

# check if LLMNR and NETBIOS-NS are enabled
function checkLLMNRAndNetBIOS {
    param (
        $name
    )
    # LLMNR and NETBIOS-NS are insecure legacy protocols for local multicast DNS queries that can be abused by Responder/Inveigh
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkLLMNRAndNetBIOS function"
    writeToScreen -str "Getting LLMNR and NETBIOS-NS configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= LLMNR Configuration ============="
    writeToFile -file $outputFile -path $folderLocation -str "GPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution"
    $LLMNR = Get-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" EnableMulticast -ErrorAction SilentlyContinue
    $LLMNR_Enabled = $LLMNR.EnableMulticast
    writeToFile -file $outputFile -path $folderLocation -str "Registry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $LLMNR_Enabled"
    if ($LLMNR_Enabled -eq 0)
        {writeToFile -file $outputFile -path $folderLocation -str "LLMNR is disabled, which is secure."}
    else
        {writeToFile -file $outputFile -path $folderLocation -str "LLMNR is enabled, which is a finding, especially for workstations."}
        writeToFile -file $outputFile -path $folderLocation -str "============= NETBIOS Name Service Configuration ============="
        writeToFile -file $outputFile -path $folderLocation -str "Checking the NETBIOS Node Type configuration - see 'https://getadmx.com/?Category=KB160177#' for details...`r`n"
    $NodeType = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" NodeType -ErrorAction SilentlyContinue).NodeType
    if ($NodeType -eq 2)
        {writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to P-node (only point-to-point name queries to a WINS name server), which is secure."}
    else
    {
        switch ($NodeType)
        {
            $null {writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to the default setting (broadcast queries), which is not secure and a finding."}
            1 {writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to B-node (broadcast queries), which is not secure and a finding."}
            4 {writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server), which is not secure and a finding."}
            8 {writeToFile -file $outputFile -path $folderLocation -str "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts), which is not secure and a finding."}        
        }

        writeToFile -file $outputFile -path $folderLocation -str "Checking the NETBIOS over TCP/IP configuration for each network interface."
        writeToFile -file $outputFile -path $folderLocation -str "Network interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting"
        writeToFile -file $outputFile -path $folderLocation -str "`r`nNetbiosOptions=0 is default, and usually means enabled, which is not secure and a possible finding."
        writeToFile -file $outputFile -path $folderLocation -str "NetbiosOptions=1 is enabled, which is not secure and a possible finding."
        writeToFile -file $outputFile -path $folderLocation -str "NetbiosOptions=2 is disabled, which is secure."
        writeToFile -file $outputFile -path $folderLocation -str "If NetbiosOptions is set to 2 for the main interface, NetBIOS Name Service is protected against poisoning attacks even though the NodeType is not set to P-node, and this is not a finding."
        $interfaces = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" NetbiosOptions -ErrorAction SilentlyContinue
        writeToFile -file $outputFile -path $folderLocation -str ($interfaces | Select-Object PSChildName,NetbiosOptions | Out-String)
    }
    
}

# check if cleartext credentials are saved in lsass memory for WDigest
function checkWDigest {
    param (
        $name
    )
    # turned on by default for Win7/2008/8/2012, to fix it you must install kb2871997 and than fix the registry value below
    # turned off by default for Win8.1/2012R2 and above
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkWDigest function"
    writeToScreen -str "Getting WDigest credentials configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= WDigest Configuration ============="
    $WDigest = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential -ErrorAction SilentlyContinue
    if ($null -eq $WDigest)
    {
        writeToFile -file $outputFile -path $folderLocation -str "WDigest UseLogonCredential registry value wasn't found."
        # check if running on Windows 6.3 or above
        if (($winVersion.Major -ge 10) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -eq 3)))
            {writeToFile -file $outputFile -path $folderLocation -str  "The WDigest protocol is turned off by default for Win8.1/2012R2 and above. So it is OK, but still recommended to set the UseLogonCredential registry value to 0, to revert malicious attempts of enabling WDigest."}
        else
        {
            # check if running on Windows 6.1/6.2, which can be hardened, or on older version
            if (($winVersion.Major -eq 6) -and ($winVersion.Minor -ge 1))    
                {writeToFile -file $outputFile -path $folderLocation -str "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding."}
            else
            {
                writeToFile -file $outputFile -path $folderLocation -str "The operating system version is not supported. You have worse problems than WDigest configuration."
                writeToFile -file $outputFile -path $folderLocation -str "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS."
            }
        }
    }
    else
    {    
        if ($WDigest.UseLogonCredential -eq 0)
        {
            writeToFile -file $outputFile -path $folderLocation -str "WDigest UseLogonCredential registry key set to 0."
            writeToFile -file $outputFile -path $folderLocation -str "WDigest doesn't store cleartext user credentials in memory, which is good. The setting was intentionally hardened."
        }
        if ($WDigest.UseLogonCredential -eq 1)
        {
            writeToFile -file $outputFile -path $folderLocation -str "WDigest UseLogonCredential registry key set to 1."
            writeToFile -file $outputFile -path $folderLocation -str "WDigest stores cleartext user credentials in memory, which is bad and a finding. The configuration was either intentionally configured by an admin for some reason, or was set by a threat actor to fetch clear-text credentials."
        }
    }
    
}

# check for Net Session enumeration permissions
function checkNetSessionEnum {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
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
    $SessionRegValue = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity SrvsvcSessionInfo).SrvsvcSessionInfo
    $SecurityDesc = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($true,$false,$SessionRegValue,0)
    writeToFile -file $outputFile -path $folderLocation -str ($SecurityDesc.DiscretionaryAcl | ForEach-Object {$_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru} | Out-String)
    writeToFile -file $outputFile -path $folderLocation -str "--------- Raw Registry Value Check ---------" 
    writeToFile -file $outputFile -path $folderLocation -str "For comparison, below are the beggining of example values of the SrvsvcSessionInfo registry key, which holds the ACL for NetSessionEnum:"
    writeToFile -file $outputFile -path $folderLocation -str "Default value for Windows 2019 and newer builds of Windows 10 (hardened): 1,0,4,128,160,0,0,0,172"
    writeToFile -file $outputFile -path $folderLocation -str "Default value for Windows 2016, older builds of Windows 10 and older OS versions (not secure - finding): 1,0,4,128,120,0,0,0,132"
    writeToFile -file $outputFile -path $folderLocation -str "Value after running NetCease (hardened): 1,0,4,128,20,0,0,0,32"
    writeToFile -file $outputFile -path $folderLocation -str "`r`nThe SrvsvcSessionInfo registry value under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity is set to:"
    writeToFile -file $outputFile -path $folderLocation -str ($SessionRegValue | Out-String)
}

# check for SAM enumeration permissions
function checkSAMEnum{
    param(
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkSAMEnum function"
    writeToScreen -str "Getting SAM enumeration configuration..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= Remote SAM (SAMR) Configuration ============="
    writeToFile -file $outputFile -path $folderLocation -str "`r`nBy default, in Windows 2016 (and above) and Windows 10 build 1607 (and above), only Administrators are allowed to make remote calls to SAM with the SAMRPC protocols, and (among other things) enumerate the members of the local groups."
    writeToFile -file $outputFile -path $folderLocation -str "However, in older OS versions, low privileged domain users can also query the SAM with SAMRPC, which is a major vulnerability mainly on non-Domain Contollers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $outputFile -path $folderLocation -str "These old OS versions (Windows 7/2008R2 and above) can be hardened by installing a KB and configuring only the Local Administrators group in the following GPO policy: 'Network access: Restrict clients allowed to make remote calls to SAM'."
    writeToFile -file $outputFile -path $folderLocation -str "The newer OS versions are also recommended to be configured with the policy, though it is not essential."
    writeToFile -file $outputFile -path $folderLocation -str "`r`nSee more details here:"
    writeToFile -file $outputFile -path $folderLocation -str "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    writeToFile -file $outputFile -path $folderLocation -str "https://blog.stealthbits.com/making-internal-reconnaissance-harder-using-netcease-and-samri1o"
    writeToFile -file $outputFile -path $folderLocation -str "`r`n----------------------------------------------------"

    $RestrictRemoteSAM = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa RestrictRemoteSAM -ErrorAction SilentlyContinue
    if ($null -eq $RestrictRemoteSAM)
    {
        writeToFile -file $outputFile -path $folderLocation -str "The 'RestrictRemoteSAM' registry value was not found. SAM enumeration permissions are configured as the default for the OS version, which is $winVersion."
        if (($winVersion.Major -ge 10) -and ($winVersion.Build -ge 14393))
            {writeToFile -file $outputFile -path $folderLocation -str "This OS version is hardened by default."}
        else
            {writeToFile -file $outputFile -path $folderLocation -str "This OS version is not hardened by default and this issue can be seen as a finding."}
    }
    else
    {
        $RestrictRemoteSAMValue = $RestrictRemoteSAM.RestrictRemoteSAM
        writeToFile -file $outputFile -path $folderLocation -str "The 'RestrictRemoteSAM' registry value is set to: $RestrictRemoteSAMValue"
        $RestrictRemoteSAMPermissions = ConvertFrom-SDDLString -Sddl $RestrictRemoteSAMValue
        writeToFile -file $outputFile -path $folderLocation -str "Below are the permissions for SAM enumeration. Make sure that only Administrators are granted Read permissions."
        writeToFile -file $outputFile -path $folderLocation -str ($RestrictRemoteSAMPermissions | Out-String)
    }
}

# check for PowerShell v2 installation, which lacks security features (logging, AMSI)
function checkPowershellVer {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
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
    }
    catch
    {
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell version 2 was not able to run. This is secure."
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
        writeToLog -str "Function checkPowershellVer: unable to run Get-WindowsFeature - requare wubdiws server 2008R2 and above and powershell version 4"
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
        writeToLog -str "Function checkPowershellVer: unable to run Get-WindowsOptionalFeature - requare wubdiws server 8/2012R2 and above and powershell version 4"
    }
    # run registry check
    writeToFile -file $outputFile -path $folderLocation -str "============= Registry Check =============" 
    writeToFile -file $outputFile -path $folderLocation -str "Based on the registry value described in the following article:"
    writeToFile -file $outputFile -path $folderLocation -str "https://devblogs.microsoft.com/powershell/detection-logic-for-powershell-installation"
    $LegacyPowerShell = Get-ItemProperty "HKLM:\Software\Microsoft\PowerShell\1\PowerShellEngine" PowerShellVersion -ErrorAction SilentlyContinue
    if (($LegacyPowerShell.PowerShellVersion -eq "2.0") -or ($LegacyPowerShell.PowerShellVersion -eq "1.0"))
    {
        writeToFile -file $outputFile -path $folderLocation -str ("PowerShell version " + $LegacyPowerShell.PowerShellVersion + " is installed, based on the registry value mentioned above.")
    }
    else
    {
        writeToFile -file $outputFile -path $folderLocation -str "PowerShell version 1/2 is not installed." 
    }
    
}

# NTLMv2 enforcement check - check if there is a GPO that enforce the use of NTLMv2 (checking registry)
function checkNTLMv2 {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkNTLMv2 function"
    writeToScreen -str "Getting NTLM version enforcment..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "============= NTLM Check ============="
    writeToFile -file $outputFile -path $folderLocation -str "NTLMv1 & LM are  legacy authentication protocols that are reversible"
    writeToFile -file $outputFile -path $folderLocation -str "If there are legacy systems in the network configure Level 3 NTLM hardning on the domain (that way only the lagacy system will use the legacy authentication) otherwise select Level 5"
    writeToFile -file $outputFile -path $folderLocation -str "For more information go to: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication `r`n"
    $temp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -ErrorAction SilentlyContinue # registry key that contains the NTLM restrications
    if($null -eq $temp){
        writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default`r`n" #using system default depends on OS version
    }
    switch ($temp.lmcompatibilitylevel) {
        (0) { writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level 0) Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n" }
        (1) { writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level 1) Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n" }
        (2) { writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level 2) Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n" }
        (3) { writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level 3) Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - Not a finding if all servers are with the same configuration`r`n"}
        (4) { writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level 4) Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2) - Not a finding if all servers are with the same configuration`r`n"}
        (5) { writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level 5) Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2 - A good thing!)`r`n"}
        Default {writeToFile -file $outputFile -path $folderLocation -str " > NTLM Authntication setting: (Level Unknown) - " + $temp.lmcompatibilitylevel + "`r`n"}
    }
}

# GPO reprocess check
function checkGPOReprocess {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkGPOReprocess function"
    writeToScreen -str "Getting GPO enforcment..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= GPO Reprocess Check ============="
    writeToFile -file $outputFile -path $folderLocation -str "If GPO reprocess is not enforced once the GPO received is the first and lest time the gpo is enforced (until next change)"
    writeToFile -file $outputFile -path $folderLocation -str "GPO can be overridden with administrator premission - it is recommended that all security settings will be repossessed every time the system checks for GPO change`r`n"
    $temp = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoGPOListChanges -ErrorAction SilentlyContinue # registry that contains registry polciy reprocess settings 
    if($null -eq $temp){
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO regirstry policy reprocess is not configured "processed even if not changed"' 
    }
    elseif ($temp.NoGPOListChanges -ne 0) {
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO regirstry policy reprocess is not configured currectly "processed even if not changed"' 
    }
    $temp = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" -Name NoGPOListChanges -ErrorAction SilentlyContinue # registry that contains script policy reprocess settings 
    if($null -eq $temp){
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO script policy reprocess is not configured "processed even if not changed"' 
    }
    elseif ($temp.NoGPOListChanges -ne 0) {
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO script policy reprocess is not configured currectly "processed even if not changed"' 
    }
    $temp = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name NoGPOListChanges -ErrorAction SilentlyContinue # registry that contains security policy reprocess settings 
    if($null -eq $temp){
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO security policy reprocess is not configured "processed even if not changed"'
    }
    elseif ($temp.NoGPOListChanges -ne 0) {
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO security policy reprocess is not configured currectly "processed even if not changed"'
    }
    
}

# Check always install elevated setting
function checkInstallElevated {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkInstallElevated function"
    writeToScreen -str "Getting Always install with elevation setting..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Always install elevated Check ============="
    writeToFile -file $outputFile -path $folderLocation -str "checking if GPO is configured to force installation as administrator - can be used by an attacker`r`n"
    $temp = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    if($null -eq $temp){
        writeToFile -file $outputFile -path $folderLocation -str ' > No GPO for for "Always install with elevation"'
    }
    elseif ($temp.AlwaysInstallElevated -eq 1) {
        writeToFile -file $outputFile -path $folderLocation -str ' > Always install with elevated is enabled - this is a finding!'
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str ' > GPO for "Always install with elevated" is existing but not forceing installing with elevation'
    }
    
}

# Powershell Audit settings check
function checkPowrshellAudit {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkPowrshellAudit function"
    writeToScreen -str "Getting Powershell audit policy..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= PowerShell Audit ============="
    writeToFile -file $outputFile -path $folderLocation -str " Powershell Audit is configured by three main settings modules, script block and transcript:"
    writeToFile -file $outputFile -path $folderLocation -str "  - Model logging - audits the modules used in powershell commands\scripts"
    writeToFile -file $outputFile -path $folderLocation -str "  - Script block - audits the use of script block in powershell commands\scripts"
    writeToFile -file $outputFile -path $folderLocation -str "  - Transcript - audits the commands running in powershell"
    writeToFile -file $outputFile -path $folderLocation -str " For comprehensive audit trail all of those need to be configured and each of them has a special setting that need to be configured to work properly (for example in module audit you need to specify witch modules to audit)`r`n"
    # --- Start Of Module Logging ---
    writeToFile -file $outputFile -path $folderLocation -str "--- PowerShell Module audit: "
    $temp = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -ErrorAction SilentlyContinue # registry that checks Module Logging in Computer-Space
    if($null -eq $temp){
        $temp = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -ErrorAction SilentlyContinue # registry that checks Module Logging in User-Space 
        if($null -ne $temp -and $temp.EnableModuleLogging -eq 1){
            $booltest = $false
            $temp2 = Get-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
            foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $booltest = $True
                }
            }
            if(!$booltest){
                writeToFile -file $outputFile -path $folderLocation -str  " > PowerShell - Module logging is enforced on all modules but only on the user"
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module logging is enforced only on the user and not on all modules" 
                writeToFile -file $outputFile -path $folderLocation -str ($temp2 | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
            } 
        }
        else {
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module logging is not enforced"
        }
    }
    elseif($temp.EnableModuleLogging -eq 1){
        $booltest = $false
        $temp2 = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue # registry that contains which Module are logged in Computer-Space
        foreach ($item in ($temp2 | Select-Object -ExpandProperty Property)){
            if($item -eq "*"){
                $booltest = $True
            }
        }
        if(!$booltest){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module logging is not enforced on all modules:" 
            writeToFile -file $outputFile -path $folderLocation -str ($temp2 | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module logging is enforced on all modules"
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Module logging is Not enforced!"
    }

    # --- End Of Module Logging ---
    # --- Start of ScriptBlock logging
    writeToFile -file $outputFile -path $folderLocation -str "--- PowerShell Script block logging: "
    $temp = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue # registry containing script-block logging setting - in computer-space
    if($null -eq $temp -or $temp.EnableScriptBlockLogging -ne 1){
        $temp = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue # registry containing script-block logging setting - in user-space
        if($null -ne $temp -and $temp.EnableScriptBlockLogging -eq 1){
            $temp2 = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockInvocationLogging -ErrorAction SilentlyContinue # registry containing script-block Invocation logging setting - in user-space
            if($null -eq $temp2 -or $temp2.EnableScriptBlockInvocationLogging -ne 1){
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block logging is enabled but Invocation logging is not enforced - only on user" 
            }
            else{
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block logging is enforced - only on user"
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block logging is not enforced"
        }
    }
    else{
        $temp2 = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockInvocationLogging -ErrorAction SilentlyContinue # registry containing script-block Invocation logging setting - in computer-space
        if($null -eq $temp2 -or $temp2.EnableScriptBlockInvocationLogging -ne 1){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block logging is enabled but Invocation logging is not enforced"
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Script Block logging is enabled"
        }
    }
    # --- End of ScriptBlock logging
    # --- Start Transcription logging 
    writeToFile -file $outputFile -path $folderLocation -str "--- PowerShell Transcripting logging: "
    $temp = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableTranscripting -ErrorAction SilentlyContinue # registry containing transcripting logging setting - computer-space
    $bollCheck = $false
    if($null -eq $temp -or $temp.EnableTranscripting -ne 1){
        $temp = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableTranscripting -ErrorAction SilentlyContinue # registry containing transcripting logging setting - user-space
        if($null -ne $temp -and $temp.EnableTranscripting -eq 1){
            $temp2 = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableInvocationHeader -ErrorAction SilentlyContinue # registry containing transcripting Invocation-Header logging setting - user-space
            if($null -eq $temp2 -or $temp2.EnableInvocationHeader -ne 1){
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced"
                $bollCheck = $True
            }
            $temp2 = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name OutputDirectory -ErrorAction SilentlyContinue # registry containing transcripting output directory logging setting - user-space
            if($null -eq $temp2 -or $temp2.OutputDirectory -eq ""){
                writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enforced but no folder is set to save the log"
                $bollCheck = $True
            }
            if(!$bollCheck){
                writeToFile -file $outputFile -path $folderLocation -str " > Powershell - Transcription logging is enforced currectly but only on the user"
                $bollCheck = $True
            }
        }
        else{
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is not enforced (logging input and outpot of powershell command)"
            $bollCheck = $True
        }
    }
    else{
        $temp2 = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableInvocationHeader -ErrorAction SilentlyContinue # registry containing transcripting Invocation-Header logging setting - computer-space
        if($null -eq $temp2 -or $temp2.EnableInvocationHeader -ne 1){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced" 
            $bollCheck = $True
        }
        $temp2 = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name OutputDirectory -ErrorAction SilentlyContinue # registry containing transcripting output directory logging setting - computer-space
        if($null -eq $temp2 -or $temp2.OutputDirectory -eq ""){
            writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled but no folder is set to save the log" 
            $bollCheck = $True
        }
    }
    if(!$bollCheck){
        writeToFile -file $outputFile -path $folderLocation -str " > PowerShell - Transcription logging is enabled and configured currectly" 
    }
    
}

# get various system info (can take a few seconds)
function dataSystemInfo {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
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
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running dataAuditSettings function"
    writeToScreen -str "getting audit policy settings..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Audit Policy Configuration ============="
    if ($winVersion.Major -ge 6)
    {
        if($runningAsAdmin)
        {writeToFile -file $outputFile -path $folderLocation -str (auditpol /get /category:* | Format-Table | Out-String)}
        else{
            writeToLog -str "Function dataAuditSettings: unable to get auditpol data not running as admin"
        }
    }
}

#check if command line audit is enabled
function checkCommandLineAudit {
    param (
        $name
    )
    $outputFile = getNameForFile -name $name -extention ".txt"
    writeToLog -str "running checkCommandLineAudit function"
    writeToScreen -str "checking command line audit..." -ForegroundColor Yellow
    writeToFile -file $outputFile -path $folderLocation -str "`r`n============= Command line Audit ============="
    writeToFile -file $outputFile -path $folderLocation -str "Command line Audit tracks all commands running in the CLI"
    writeToFile -file $outputFile -path $folderLocation -str "Supported windows is 8/2012R2 and above"

    $reg = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue # registry key that contains the NTLM restrications
    if ((($winVersion.Major -ge 7) -or ($winVersion.Minor -ge 2))){
        if($null -eq $reg){
            writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is not configured - this is bad" #using system default depends on OS version
        }
        elseif($reg.ProcessCreationIncludeCmdLine_Enabled -ne 1){
            writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is not configured currectly - this is bad" #using system default depends on OS version
        }
        else{
            if($runningAsAdmin)
            {
                $test = auditpol /get /category:*
                foreach ($item in $test){
                    if($item -like "*Process Creation*No Auditing"){
                        writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is not configured currectly (Advance audit>Detailed Tracking>Process Creation is not configured)  - this is bad" 
                    }
                    elseif ($item -like "*Process Creation*") {
                        writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is configured currectly - this is good" 
                    }
                }
            }
            else{
                writeToLog -str "Function checkCommandLineAudit: unable to get auditpol data not running as admin cannot check setting"
            }
        }
    }
    else{
        writeToFile -file $outputFile -path $folderLocation -str " > Command line audit policy is not supported in this OS (legacy) - this is bad" 
    }
}

###Genral Vals
# get hostname to use as the folder name and file names
$hostname = hostname
$folderLocation = $hostname
# get the windows version for later use
$winVersion = [System.Environment]::OSVersion.Version
# powershell version 
$psVer = Get-Host | Select-Object Version
$psVer = $psVer.Version.Major
### start of script ###
$startTime = Get-Date
writeToScreen -str "Hello dear user!" -ForegroundColor "Green"
writeToScreen -str "This script will output the results to a folder or a zip file with the computer name." -ForegroundColor "Green"
#check if running as an elevated admin
$runningAsAdmin = $null -ne (whoami /groups | select-string S-1-16-12288)
if (!$runningAsAdmin)
    {writeToScreen -str "Please run the script as an elevated admin, or else some output will be missing! :-(" -ForegroundColor Red}

# remove old folder and create new one
Remove-Item $hostname -Recurse -ErrorAction SilentlyContinue
New-Item $folderLocation -type directory -ErrorAction SilentlyContinue | Out-Null

# output log
writeToLog -str "Computer Name: $hostname"
writeToLog -str ("Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption)
$partOfDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
writeToLog -str  "Part of Domain: $partOfDomain" 
if ($partOfDomain)
{
    writeToLog -str  ("Domain Name: " + (Get-WmiObject -class Win32_ComputerSystem).Domain)
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2)
        {writeToLog -str  "Domain Controller: True" }
    else
        {writeToLog -str  "Domain Controller: False"}    
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
dataIpSettings -name "ipconfig"

# test for internet connectivity
checkInternetAccess -name "Internet-Connectivity"

# get network connections (run-as admin is required for -b associated application switch)
getNetCon -name "Netstat"

# get GPOs
dataGPO -name "gpresult"

# get security policy settings (secpol.msc), run as admin is required
dataSecurityPolicy -name "Security-Policy"

# get windows features (Windows vista/2008 or above is required)
dataWinFeatures -name "Windows-Features"

# get installed hotfixes (/format:htable doesn't always work)
dataInstalledHotfixes -name "Hotfixes"

# get processes (new powershell version and run-as admin are required for IncludeUserName)
dataRunningProcess -name "Process-list"

# get services
dataServices -name "Services"

# get installed software
dataInstalledSoftware -name "Software"

# get shared folders (Share permissions are missing for older PowerShell versions)
dataSharedFolders -name "Shares"

# get local+domain account policy
dataAccountPolicy -name "AccountPolicy"

# get local users + admins
dataLocalUsers -name "Local-Users"
	
# check SMB protocol hardening
checkSMBHardening -name "SMB"

# Getting RDP security settings
dataRDPSecuirty -name "RDP"

# getting credential guard settings (for Windows 10/2016 and above only)
dataCredentialGuard -name "Credential-Guard"

# getting LSA protection configuration (for Windows 8.1 and above only)
dataLSAProtectionConf -name "LSA-Protection"

# search for sensitive information (i.e. cleartext passwords) if the flag exists
checkSensitiveInfo -name "Sensitive-Info"

# get anti-virus status
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

# NTLMv2 enforcement check - check if there is a GPO that enforce the use of NTLMv2 (checking registry)
checkNTLMv2 -name "Domain-Hardning"

# GPO reprocess check
checkGPOReprocess -name "Domain-Hardning"

# Powershell Audit settings check
checkCommandLineAudit -name "Audit-Policy"

# Powershell Audit settings check
checkPowrshellAudit -name "Audit-Policy"

# Powershell Audit settings check
dataAuditPolicy -name "Audit-Policy"

# Check always install elevated setting
checkInstallElevated -name "Domain-Hardning"

# get various system info (can take a few seconds)
dataSystemInfo -name "Systeminfo"

#########################################################

$currTime = Get-Date
writeToLog -str ("Script End Time (before zipping): " + $currTime.ToString("dd/MM/yyyy HH:mm:ss"))
writeToLog -str ("Total Running Time (before zipping): " + [int]($currTime - $startTime).TotalSeconds + " seconds")  

# compress the files to a zip. works for PowerShell 5.0 (Windows 10/2016) only. sometimes the compress fails because the file is still in use.
if($psVer -ge 5){
    Compress-Archive -Path $folderLocation\* -DestinationPath $folderLocation -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -Path $hostname -ErrorAction SilentlyContinue
    writeToScreen -str "All Done! Please send the output ZIP file." -ForegroundColor Green
}
elseif ($psVer -eq 4 ) {
        $fullPath = Get-Location
        $fullPath = $fullPath.path
        $fullPath += "\"+$folderLocation
        $zipLocation = $fullPath+".zip"
        if(Test-Path $zipLocation){
            Remove-Item -Force -Path $zipLocation
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($fullPath,$zipLocation)
        Remove-Item -Recurse -Force -Path $hostname -ErrorAction SilentlyContinue
        writeToScreen -str "All Done! Please send the output ZIP file." -ForegroundColor Green
}
else{
    writeToScreen -str "All Done! Please ZIP all the files and send it back." -ForegroundColor Green
    writeToLog -str "powershell running the script is below 4 script is not supporting ziping below that"
}

$endTime = Get-Date
$elapsed = $endTime - $startTime
writeToScreen -str ("The script took "+([int]$elapsed.TotalSeconds) +" seconds. Thank you.") -ForegroundColor Green
Start-Sleep -Seconds 2
