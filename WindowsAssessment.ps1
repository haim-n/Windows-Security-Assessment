$Version = "0.72"
# v0.71 update: minor fixes
# v0.72 update: added TODO
##########################################################
# TODO:
## Find misconfigured services which allow elevation of privileges
## Test the SMB1 registry check
## Add explanations to output files to help the auditor and allow screenshots from the output (SMB, WDigest, Sensitive Info, RDP, LSA, Cred Guard)
## Check again on Win2008 + Win2003
## check if Internet sites are accessible (ports 80/443 test, curl/wget, etc.)
## Check for Lock with screen saver after time-out (User Configuration\Policies\Administrative Templates\Control Panel\Personalization\...)
## Check for Windows Update / WSUS settings
## Check for Device Control (GPO or dedicated software)
## Get IIS information
## Add More settings from hardening docs or PT mitigations
## Run the script from remote location to a list of servers - psexec, remote ps, etc.
## Change script formation to functions
## Find and filter the actual security issues in the results
## Zip files without the need for PowerShell 5.0
##########################################################
# @Haim Nachmias
##########################################################

$startTime = Get-Date
write-host Hello dear user! -ForegroundColor Green
Write-Host This script will output the results to a folder or a zip file with the server name. -ForegroundColor Green
#check if running as an elevated admin
$runningAsAdmin = (whoami /all | select-string S-1-16-12288) -ne $null
if (!$runningAsAdmin)
    {Write-host "Please run the script as an elevated admin, or else some output will be missing! :-(" -ForegroundColor Red}

# get hostname to use as the folder name and file names
$hostname = hostname
# get the windows version for later use
$winVersion = [System.Environment]::OSVersion.Version

# remove old folder and create new one
Remove-Item $hostname -Recurse -ErrorAction SilentlyContinue
New-Item $hostname -type directory | Out-Null

#########################################################

# get current user privileges
write-host Running whoami... -ForegroundColor Yellow
"`nOutput of `"whoami /all`" command:`n" | Out-File $hostname\whoami-all_$hostname.txt -Append
whoami /all | Out-File $hostname\whoami-all_$hostname.txt -Append

# get IP settings
write-host Running ipconfig... -ForegroundColor Yellow
"`nOutput of `"ipconfig /all`" command:`n" | Out-File $hostname\ipconfig_$hostname.txt -Append
ipconfig /all | Out-File $hostname\ipconfig_$hostname.txt -Append

# test for internet connectivity
write-host Trying to ping the internet... -ForegroundColor Yellow
"============= ping -n 2 8.8.8.8 =============" | Out-File $hostname\Internet-Connectivity_$hostname.txt
ping -n 2 8.8.8.8 | Out-File $hostname\Internet-Connectivity_$hostname.txt -Append
# more detailed test for newer PowerShell versions - takes a lot of time and not very important
#try {
    # "============= Test-NetConnection -InformationLevel Detailed =============" | Out-File $hostname\Internet-Connectivity_$hostname.txt -Append
    # Test-NetConnection -InformationLevel Detailed | Out-File $hostname\Internet-Connectivity_$hostname.txt -Append
    #"============= Test-NetConnection -ComputerName www.google.com -Port 443 -InformationLevel Detailed =============" | Out-File $hostname\Internet-Connectivity_$hostname.txt -Append
    #Test-NetConnection -ComputerName www.google.com -Port 443 -InformationLevel Detailed | Out-File $hostname\Internet-Connectivity_$hostname.txt -Append
#}
#catch {"Test-NetConnection command doesn't exists, old powershell version." | Out-File $hostname\Internet-Connectivity_$hostname.txt -Append}

# get GPOs
# check if the computer is in a domain
if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
{
    # check if we have connectivity to the domain, or if is a DC
    if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
    {
        write-host Checking GPOs... -ForegroundColor Yellow
        gpresult /h $hostname\gpresult_$hostname.html
        # /h doesn't exists on Windows 2003
        if (!(Test-Path $hostname\gpresult_$hostname.html)) {gpresult $hostname\gpresult_$hostname.txt}
    }
}

# get security policy settings (secpol.msc), run as admin is required
# to open the *.inf output file, open MMC, add snap-in "Security Templates", right click and choose new path, choose the *.inf file path, and open it
if ($runningAsAdmin)
{
    write-host Getting security policy settings... -ForegroundColor Yellow
    secedit /export /CFG $hostname\Security-Policy_$hostname.inf | Out-Null
}
else
{
    write-host Unable to get security policy settings... elevated admin permissions are required -ForegroundColor Red
}

# get windows features (Windows vista/2008 & run-as admin are required)
if ($winVersion.Major -ge 6)
{
    if ($runningAsAdmin)
    {
        write-host Checking windows features... -ForegroundColor Yellow
        "`nOutput of `"dism /online /get-features /format:table`" command:`n" | Out-File $hostname\Windows-Features_$hostname.txt -Append
        dism /online /get-features /format:table | Out-File $hostname\Windows-Features_$hostname.txt -Append
    }
    else
    {
        write-host Unable to get windows features... elevated admin permissions are required -ForegroundColor Red
        "Unable to get windows features without running as admin. Consider running again with elevated admin permissions." | Out-File $hostname\Windows-Features_$hostname.txt -Append
    }
}

# get audit policy (Windows vista/2008 & run-as admin are required)
if ($winVersion.Major -ge 6)
{
    if ($runningAsAdmin)
    {
        write-host Checking audit policy... -ForegroundColor Yellow
        "`nOutput of `"auditpol /get /category:*`" command:`n" | Out-File $hostname\Audit-Policy_$hostname.txt -Append
        auditpol /get /category:* | Out-File $hostname\Audit-Policy_$hostname.txt -Append
    }
    else
    {
        write-host Unable to get audit policy... elevated admin permissions are required -ForegroundColor Red
        "Unable to get audit policy without running as admin. Consider running again with elevated admin permissions."  > $hostname\Audit-Policy_$hostname.txt
    }
}

# get installed hotfixes (/format:htable doesn't always work)
write-host Checking for installed hotfixes... -ForegroundColor Yellow
"`nOutput of `"Get-HotFix`" PowerShell command, sorted by installation date:`n" | Out-File $hostname\hotfixes_$hostname.txt -Append
Get-HotFix | sort InstalledOn -Descending | Out-File $hostname\hotfixes_$hostname.txt -Append
#wmic qfe list full /format:$htable > $hostname\hotfixes_$hostname.html
#if ((Get-Content $hostname\hotfixes_$hostname.html) -eq $null)
#{
#    write-host "Checking for installed hotfixes again... htable format didn't work" -ForegroundColor Yellow
#    Remove-Item $hostname\hotfixes_$hostname.html
#    wmic qfe list > $hostname\hotfixes_$hostname.txt
#}

# get processes (new powershell version and run-as admin are required for IncludeUserName)
write-host Getting processes... -ForegroundColor Yellow
"`nOutput of `"Get-Process`" PowerShell command:`n" | Out-File $hostname\Process-list_$hostname.txt -Append
try {Get-Process -IncludeUserName | ft -AutoSize ProcessName, id, company, ProductVersion, username, cpu, WorkingSet | Out-String -Width 180 | Out-File $hostname\Process-list_$hostname.txt -Append}
# run without IncludeUserName if the script doesn't have elevated permissions or for old powershell versions
catch {Get-Process | ft -AutoSize ProcessName, id, company, ProductVersion, cpu, WorkingSet | Out-String -Width 180 | Out-File $hostname\Process-list_$hostname.txt -Append}

# get services
write-host Getting services... -ForegroundColor Yellow
"`nOutput of `"Get-WmiObject win32_service`" PowerShell command:`n" | Out-File $hostname\Services_$hostname.txt -Append
Get-WmiObject win32_service  | Sort displayname | ft -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-File $hostname\Services_$hostname.txt -Append

# get installed softwares
write-host Getting installed softwares... -ForegroundColor Yellow
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | sort DisplayName | Out-String -Width 180 | Out-File $hostname\Softwares_$hostname.txt

# get shared folders (Share permissions are missing for older PowerShell versions)
write-host Getting shared folders... -ForegroundColor Yellow
"============= Shared Folders =============" | Out-File $hostname\Shares_$hostname.txt
$shares = Get-WmiObject -Class Win32_Share
$shares | Out-File $hostname\Shares_$hostname.txt -Append
# get shared folders + share permissions + NTFS permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
foreach ($share in $shares)
{
    $sharePath = $share.Path
    $shareName = $share.Name
    "`n============= Share Name: $shareName | Share Path: $sharePath =============" | Out-File $hostname\Shares_$hostname.txt -Append
    "Share Permissions:" | Out-File $hostname\Shares_$hostname.txt -Append
    # Get share permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
    try
    {
        import-module smbshare -ErrorAction SilentlyContinue
        $share | Get-SmbShareAccess | Out-String -Width 180 | Out-File $hostname\Shares_$hostname.txt -Append
    }
    catch
    {
        $shareSecSettings = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'"
        if ($shareSecSettings -eq $null)
            {
            # Unfortunately, some of the shares security settings are missing from the WMI. Complicated stuff. Google "Count of shares != Count of share security"
            "Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting.`n" | Out-File $hostname\Shares_$hostname.txt -Append}
        else
        {
            $DACLs = (Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'" -ErrorAction SilentlyContinue).GetSecurityDescriptor().Descriptor.DACL
            foreach ($DACL in $DACLs)
            {
                if ($DACL.Trustee.Domain) {$Trustee = $DACL.Trustee.Domain + "\" + $DACL.Trustee.Name}
                else {$Trustee = $DACL.Trustee.Name}
                $AccessType = [Security.AccessControl.AceType]$DACL.AceType
                $FileSystemRights = $DACL.AccessMask -as [Security.AccessControl.FileSystemRights]
                "Trustee: $Trustee | Type: $AccessType | Permission: $FileSystemRights" | Out-File $hostname\Shares_$hostname.txt -Append
            }
        }    
    }
    "NTFS Permissions:" | Out-File $hostname\Shares_$hostname.txt -Append
    try {(Get-Acl $sharePath).Access | ft | Out-File $hostname\Shares_$hostname.txt -Append}
    catch {"No NTFS permissions were found." | Out-File $hostname\Shares_$hostname.txt -Append}
}

# get local+domain account policy
write-host Getting local and domain account policy... -ForegroundColor Yellow
"============= Local Account Policy =============" | Out-File $hostname\AccountPolicy_$hostname.txt -Append
"`nOutput of `"NET ACCOUNTS`" command:`n" | Out-File $hostname\AccountPolicy_$hostname.txt -Append
NET ACCOUNTS | Out-File $hostname\AccountPolicy_$hostname.txt -Append
# check if the computer is in a domain
"`n============= Domain Account Policy =============" | Out-File $hostname\AccountPolicy_$hostname.txt -Append
if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
{
    if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
    {
        "`nOutput of `"NET ACCOUNTS /domain`" command:`n" | Out-File $hostname\AccountPolicy_$hostname.txt -Append
        NET ACCOUNTS /domain | Out-File $hostname\AccountPolicy_$hostname.txt -Append
    }    
    else
        {"Error: No connection to the domain." | Out-File $hostname\AccountPolicy_$hostname.txt -Append}
}
else
    {"Error: The computer is not part of a domain." | Out-File $hostname\AccountPolicy_$hostname.txt -Append}

# get local users + admins
write-host Getting local users + administrators... -ForegroundColor Yellow
"============= Local Administrators =============" | Out-File $hostname\Local-Users_$hostname.txt -Append
"`nOutput of `"NET LOCALGROUP administrators`" command:`n" | Out-File $hostname\Local-Users_$hostname.txt -Append
NET LOCALGROUP administrators | Out-File $hostname\Local-Users_$hostname.txt -Append
"`n============= Local Users =============" | Out-File $hostname\Local-Users_$hostname.txt -Append
# Get-LocalUser exists only in Windows 10 / 2016
try
{
    "`nOutput of `"Get-LocalUser`" PowerShell command:`n" | Out-File $hostname\Local-Users_$hostname.txt -Append
    Get-LocalUser | ft name, enabled, AccountExpires, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon, description, SID | Out-String -Width 180 | Out-File $hostname\Local-Users_$hostname.txt -Append
}
catch
{
    "`nGetting information regarding local users from WMI.`n" | Out-File $hostname\Local-Users_$hostname.txt -Append
    "Output of `"Get-CimInstance win32_useraccount -Namespace `"root\cimv2`" -Filter `"LocalAccount=`'$True`'`"`" PowerShell command:`n" | Out-File $hostname\Local-Users_$hostname.txt -Append
    Get-CimInstance win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" | Select Caption,Disabled,Lockout,PasswordExpires,PasswordRequired,Description,SID | format-table -autosize | Out-String -Width 180 | Out-File $hostname\Local-Users_$hostname.txt -Append
}
	
# get network connections (run-as admin is required for -b associated application switch)
write-host Running netstat... -ForegroundColor Yellow
"`n============= netstat -nao =============" | Out-File $hostname\netstat_$hostname.txt -Append
netstat -nao | Out-File $hostname\netstat_$hostname.txt -Append
"`n============= netstat -naob (includes process name, elevated admin permission is required =============" | Out-File $hostname\netstat_$hostname.txt -Append
netstat -naob | Out-File $hostname\netstat_$hostname.txt -Append
# "============= netstat -ao  =============" | Out-File $hostname\netstat_$hostname.txt  -Append
# netstat -ao | Out-File $hostname\netstat_$hostname.txt -Append  # shows server names, but takes a lot of time and not very important

# check SMB protocol hardening
Write-Host Checking SMB hardening... -ForegroundColor Yellow
"`n============= SMB versions Support (Server Settings) =============" | Out-File $hostname\SMB_$hostname.txt
# Check if Windows Vista/2008 or above
if ($winVersion.Major -ge 6)
{
    $SMB1 = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters SMB1 -ErrorAction SilentlyContinue
    $SMB2 = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters SMB2 -ErrorAction SilentlyContinue
    if ($SMB1.SMB1 -eq 0)
        {"SMB1 Server is not supported. Which is nice." | Out-File $hostname\SMB_$hostname.txt -Append}
    else
        {"SMB1 Server is supported. Which is pretty bad and certainly a finding." | Out-File $hostname\SMB_$hostname.txt -Append}
    if ($SMB2.SMB2 -eq 0)
        {"SMB2 and SMB3 Server are not supported. Which is weird, but not a finding." | Out-File $hostname\SMB_$hostname.txt -Append}
    else
        {"SMB2 and SMB3 Server are supported. Which is OK." | Out-File $hostname\SMB_$hostname.txt -Append}
}
else
{
    "Old Windows versions (XP or 2003) support only SMB1." | Out-File $hostname\SMB_$hostname.txt -Append
}
"`n============= SMB versions Support (Client Settings) =============" | Out-File $hostname\SMB_$hostname.txt -Append
# Check if Windows Vista/2008 or above
if ($winVersion.Major -ge 6)
{
    $SMB1Client = (sc.exe qc lanmanworkstation | ? {$_ -like "*START_TYPE*"}).split(":")[1][1]
    Switch ($SMB1Client)
    {
        "0" {"SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." | Out-File $hostname\SMB_$hostname.txt -Append}
        "1" {"SMB1 Client is set to 'System'. Which is not weird. although disabled is better." | Out-File $hostname\SMB_$hostname.txt -Append}
        "2" {"SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must." | Out-File $hostname\SMB_$hostname.txt -Append}
        "3" {"SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better." | Out-File $hostname\SMB_$hostname.txt -Append}
        "4" {"SMB1 Client is set to 'Disabled'. Which is nice." | Out-File $hostname\SMB_$hostname.txt -Append}
    }
}
else
{
    "Old Windows versions (XP or 2003) support only SMB1." | Out-File $hostname\SMB_$hostname.txt -Append
}
"`n============= SMB Signing (Server Settings) =============" | Out-File $hostname\SMB_$hostname.txt -Append
$SmbServerRequireSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters RequireSecuritySignature
$SmbServerSupportSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters EnableSecuritySignature
if ($SmbServerRequireSigning.RequireSecuritySignature -eq 1)
{
    "Microsoft network server: Digitally sign communications (always) = Enabled" | Out-File $hostname\SMB_$hostname.txt -Append
    "SMB signing is required by the server, Which is good." | Out-File $hostname\SMB_$hostname.txt -Append
}
else
{
    if ($SmbServerSupportSigning.EnableSecuritySignature -eq 1)
    {
        "Microsoft network server: Digitally sign communications (always) = Disabled" | Out-File $hostname\SMB_$hostname.txt -Append
        "Microsoft network server: Digitally sign communications (if client agrees) = Enabled" | Out-File $hostname\SMB_$hostname.txt -Append
        "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding." | Out-File $hostname\SMB_$hostname.txt -Append
    }
    else
    {
        "Microsoft network server: Digitally sign communications (always) = Disabled." | Out-File $hostname\SMB_$hostname.txt -Append
        "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." | Out-File $hostname\SMB_$hostname.txt -Append
        "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." | Out-File $hostname\SMB_$hostname.txt -Append
    }
}
"`n============= SMB Signing (Client Settings) =============" | Out-File $hostname\SMB_$hostname.txt -Append
$SmbClientRequireSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters RequireSecuritySignature
$SmbClientSupportSigning = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters EnableSecuritySignature
if ($SmbClientRequireSigning.RequireSecuritySignature -eq 1)
{
    "Microsoft network client: Digitally sign communications (always) = Enabled" | Out-File $hostname\SMB_$hostname.txt -Append
    "SMB signing is required by the client, Which is good." | Out-File $hostname\SMB_$hostname.txt -Append
}
else
{
    if ($SmbClientSupportSigning.EnableSecuritySignature -eq 1)
    {
        "Microsoft network client: Digitally sign communications (always) = Disabled" | Out-File $hostname\SMB_$hostname.txt -Append
        "Microsoft network client: Digitally sign communications (if client agrees) = Enabled" | Out-File $hostname\SMB_$hostname.txt -Append
        "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding." | Out-File $hostname\SMB_$hostname.txt -Append
    }
    else
    {
        "Microsoft network client: Digitally sign communications (always) = Disabled." | Out-File $hostname\SMB_$hostname.txt -Append
        "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." | Out-File $hostname\SMB_$hostname.txt -Append
        "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding." | Out-File $hostname\SMB_$hostname.txt -Append
    }
}


# Getting RDP security settings
Write-Host Checking RDP security settings... -ForegroundColor Yellow
"============= Raw RDP Settings =============" | Out-File $hostname\RDP_$hostname.txt -Append
$RDP = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter “TerminalName='RDP-tcp'” 
$RDP | fl Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-File $hostname\RDP_$hostname.txt -Append
"`n============= NLA (Network Level Authentication) =============" | Out-File $hostname\RDP_$hostname.txt -Append
if ($RDP.UserAuthenticationRequired -eq 1)
    {"NLA is required, which is fine." | Out-File $hostname\RDP_$hostname.txt -Append}
if ($RDP.UserAuthenticationRequired -eq 0)
    {"NLA is not required, which is bad. A finding." | Out-File $hostname\RDP_$hostname.txt -Append}
"`n============= Security Layer (SSL/TLS) =============" | Out-File $hostname\RDP_$hostname.txt -Append
if ($RDP.SecurityLayer -eq 0)
    {"Native RDP encryption is used instead of SSL/TLS. Which is bad. A finding." | Out-File $hostname\RDP_$hostname.txt -Append}
if ($RDP.SecurityLayer -eq 1)
    {"SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding." | Out-File $hostname\RDP_$hostname.txt -Append}
if ($RDP.SecurityLayer -eq 2)
    {"SSL/TLS is required for connecting. Which is good." | Out-File $hostname\RDP_$hostname.txt -Append}
"`n============= Raw RDP Timeout Settings =============" | Out-File $hostname\RDP_$hostname.txt -Append
$RDPTimeout = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" 
if ($RDPTimeout.ValueCount -eq 0)
    {"RDP timeout is not configured. A possible finding." | Out-File $hostname\RDP_$hostname.txt -Append}
else
{
    "The following RDP timeout properties were configured:" | Out-File $hostname\RDP_$hostname.txt -Append
    $RDPTimeout | Out-File $hostname\RDP_$hostname.txt -Append
    "`nMaxConnectionTime = Time limit for active RDP sessions" | Out-File $hostname\RDP_$hostname.txt -Append
    "MaxIdleTime = Time limit for active but idle RDP sessions" | Out-File $hostname\RDP_$hostname.txt -Append
    "MaxConnectionTime = Time limit for disconnected RDP sessions" | Out-File $hostname\RDP_$hostname.txt -Append
    "fResetBroken = Log off session (instead of disconnect) when time limits are reached" | Out-File $hostname\RDP_$hostname.txt -Append
    "60000 = 1 minute, 3600000 = 1 hour, etc." | Out-File $hostname\RDP_$hostname.txt -Append
    "`nFor further information, see the GPO settings at: Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session\Session Time Limits" | Out-File $hostname\RDP_$hostname.txt -Append
}

# getting credential guard settings (for Windows 10 only)
if ($winVersion.Major -ge 10)
{
    Write-Host Checking credential guard settings... -ForegroundColor Yellow
    $DevGuard = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    "============= Credential Guard Settings =============" | Out-File $hostname\Credential-Guard_$hostname.txt -Append
    if (($DevGuard.SecurityServicesConfigured -contains 1) -and ($DevGuard.SecurityServicesRunning -contains 1))
        {"Credential Guard is configured and running. Which is good." | Out-File $hostname\Credential-Guard_$hostname.txt -Append}
    else
        {"Credential Guard is turned off. A possible finding." | Out-File $hostname\Credential-Guard_$hostname.txt -Append}
    "`n============= Raw Device Guard Settings (Including Credential Guard) =============" | Out-File $hostname\Credential-Guard_$hostname.txt
    $DevGuard | Out-File $hostname\Credential-Guard_$hostname.txt -Append
}

# getting LSA protection configuration (for Windows 8.1 and above only)
if (($winVersion.Major -ge 10) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -eq 3)))
{
    Write-Host Checking LSA protection settings... -ForegroundColor Yellow
    $RunAsPPL = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL -ErrorAction SilentlyContinue
    if ($RunAsPPL -eq $null)
        {"RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding." | Out-File $hostname\LSA-Protection_$hostname.txt}
    else
    {
        "RunAsPPL registry value is: " +$RunAsPPL.RunAsPPL | Out-File $hostname\LSA-Protection_$hostname.txt
        if ($RunAsPPL.RunAsPPL -eq 1)
            {"LSA protection is on . Which is good." | Out-File $hostname\LSA-Protection_$hostname.txt -Append}
        else
            {"LSA protection is off . Which is bad and a possible finding." | Out-File $hostname\LSA-Protection_$hostname.txt -Append}
    }
}

# search for sensitive information (i.e. cleartext passwords)
write-host Searching for sensitive information... -ForegroundColor Yellow
"============= Looking for clear-text passwords =============" | Out-File $hostname\Sensitive-Info_$hostname.txt -Append
# recursive searches in c:\temp, current user desktop, default IIS website root folder
# add any other directory that you want. searching in C:\ may take a while.
$paths = "C:\Temp",[Environment]::GetFolderPath("Desktop"),"c:\Inetpub\wwwroot"
foreach ($path in $paths)
{
    "`n============= recursive search in $path =============" | Out-File $hostname\Sensitive-Info_$hostname.txt -Append
    # find txt\ini\config\xml\vnc files with the word password in it, and dump the line
    # ignore the files outputted during the assessment...
    $includeFileTypes = @("*.txt","*.ini","*.config","*.xml","*vnc*")
    Get-ChildItem -Path $path -Include $includeFileTypes -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | ? {$_.Name -notlike "*_$hostname.txt"} | Select-String -Pattern password | Out-File $hostname\Sensitive-Info_$hostname.txt -Append
    # find files with the name pass\cred\config\vnc\p12\pfx and dump the whole file, unless it is too big
    # ignore the files outputted during the assessment...
    $includeFilePatterns = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
    $files = Get-ChildItem -Path $path -Include $includeFilePatterns -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | ? {$_.Name -notlike "*_$hostname.txt"}
    foreach ($file in $files)
    {
        "------------- $file -------------" | Out-File $hostname\Sensitive-Info_$hostname.txt -Append
        $fileSize = (Get-Item $file.FullName).Length
        if ($fileSize -gt 300kb) {"The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB)." | Out-File $hostname\Sensitive-Info_$hostname.txt -Append}
        else {cat $file.FullName | Out-File $hostname\Sensitive-Info_$hostname.txt -Append}
    }
}

# get anti-virus status
# works only on Windows Clients, Not on Servers (2008, 2012, etc.)
if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
{
    write-host Getting Anti-Virus status... -ForegroundColor Yellow
    if ($winVersion.Major -ge 6)
    {
        $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
        $FirewallProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct
        $AntiSpywareProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiSpywareProduct
        "`nSecurity products status was taken from WMI values on WMI namespace `"root\SecurityCenter2`".`n" | Out-File $hostname\AntiVirus_$hostname.txt -Append
    }
    else
    {
        $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct
        $FirewallProducts = Get-WmiObject -Namespace root\SecurityCenter -Class FirewallProduct
        $AntiSpywareProducts = Get-WmiObject -Namespace root\SecurityCenter -Class AntiSpywareProduct
        "`nSecurity products status was taken from WMI values on WMI namespace `"root\SecurityCenter`".`n" | Out-File $hostname\AntiVirus_$hostname.txt -Append
    }
    if ($AntiVirusProducts -eq $null)
        {"No Anti Virus products were found." | Out-File $hostname\AntiVirus_$hostname.txt -Append}
    "`n============= Anti-Virus Products Status =============" | Out-File $hostname\AntiVirus_$hostname.txt -Append
    foreach ($av in $AntiVirusProducts)
    {
    
        "`nProduct Display name: " + $av.displayname | Out-File $hostname\AntiVirus_$hostname.txt -Append
        "Product Executable: " + $av.pathToSignedProductExe | Out-File $hostname\AntiVirus_$hostname.txt -Append
        "Time Stamp: " + $av.timestamp | Out-File $hostname\AntiVirus_$hostname.txt -Append
        "Product (raw) state: " + $av.productState | Out-File $hostname\AntiVirus_$hostname.txt -Append
        # check the product state
        $hx = '0x{0:x}' -f $av.productState
        if ($hx.Substring(3,2) -match "00|01")
            {"AntiVirus is NOT enabled" | Out-File $hostname\AntiVirus_$hostname.txt -Append}
        else
            {"AntiVirus is enabled" | Out-File $hostname\AntiVirus_$hostname.txt -Append}
        if ($hx.Substring(5) -eq "00")
            {"Virus definitions are up to date" | Out-File $hostname\AntiVirus_$hostname.txt -Append}
        else
            {"Virus definitions are NOT up to date" | Out-File $hostname\AntiVirus_$hostname.txt -Append}
    }
    "`n============= Anti-Virus Products Status (Raw Data) =============" | Out-File $hostname\AntiVirus_$hostname.txt -Append
    $AntiVirusProducts | Out-File $hostname\AntiVirus_$hostname.txt -Append
    "`n============= Firewall Products Status (Raw Data) =============" | Out-File $hostname\AntiVirus_$hostname.txt -Append
    $FirewallProducts | Out-File $hostname\AntiVirus_$hostname.txt -Append
    "`n============= Anti-Spyware Products Status (Raw Data) =============" | Out-File $hostname\AntiVirus_$hostname.txt -Append
    $AntiSpywareProducts | Out-File $hostname\AntiVirus_$hostname.txt -Append
}

# check if LLMNR and NETBIOS-NS are enabled
# LLMNR and NETBIOS-NS are insecure legacy protocols for local multicast DNS queries that can be abused by Responder
write-host Getting LLMNR and NETBIOS configuration... -ForegroundColor Yellow
"============= LLMNR Configuration =============" | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
"`nGPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution" | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
$LLMNR = Get-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" EnableMulticast -ErrorAction SilentlyContinue
$LLMNR_Enabled = $LLMNR.EnableMulticast
"`nRegistry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $LLMNR_Enabled" | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
if ($LLMNR_Enabled -eq 0)
    {"`nLLMNR is disabled, which is good." | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append}
else
    {"`nLLMNR is enabled, which is a possible finding, especially for workstations." | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append}
"`n============= NETBIOS Configuration =============" | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
"`nChecking the NETBIOS over TCP/IP configuration for each network interface." | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
"`nNetwork interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting" | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
"`nNetbiosOptions=0 is default, and usually means enabled, which is bad and a possible finding." | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
"NetbiosOptions=1 is enabled, which is bad and a possible finding." | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
"NetbiosOptions=2 is disabled, which is good." | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append
$interfaces = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" NetbiosOptions
$interfaces | select PSChildName,NetbiosOptions | Out-File $hostname\LLMNR_and_NETBIOS_$hostname.txt -Append

# check if cleartext credentials are saved in lsass memory for WDigest
# turned on by default for Win7/2008/8/2012, to fix it you must install kb2871997 and than fix the registry value below
# turned off by default for Win8.1/2012R2 and above
write-host Getting WDigest credentials configuration... -ForegroundColor Yellow
"============= WDigest Configuration =============" | Out-File $hostname\WDigest_$hostname.txt
$WDigest = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential -ErrorAction SilentlyContinue
if ($WDigest -eq $null)
{
    "`nWDigest UseLogonCredential registry key wasn't found." | Out-File $hostname\WDigest_$hostname.txt -Append
    if (($winVersion.Major -ge 10) -or (($winVersion.Major -eq 6) -and ($winVersion.Minor -eq 3)))
        {"`nThe WDigest UseLogonCredential is turned off by default for Win8.1/2012R2 and above. It's OK." | Out-File $hostname\WDigest_$hostname.txt -Append}
    else
    {
        if (($winVersion.Major -eq 6) -and ($winVersion.Minor -ge 1))    
        {"`nWDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding." | Out-File $hostname\WDigest_$hostname.txt -Append}
        else
        {"`nThe operating system version is not supported. You have worse problems than WDigest configuration." | Out-File $hostname\WDigest_$hostname.txt -Append}
    }
}
else
{
    if ($WDigest -eq 0)
    {"`nWDigest doesn't store cleartext user credentials in memory, which is good." | Out-File $hostname\WDigest_$hostname.txt -Append}
    if ($WDigest -eq 1)
    {"`nWDigest stores cleartext user credentials in memory, which is bad and a possible finding." | Out-File $hostname\WDigest_$hostname.txt -Append}
}

# get various system info (takes a lot of time)
write-host Running systeminfo... -ForegroundColor Yellow
systeminfo > $hostname\systeminfo_$hostname.txt

#########################################################

# output log
"Script Version: $Version" | Out-File $hostname\Log_$hostname.txt
"Computer Name: $hostname" | Out-File $hostname\Log_$hostname.txt -Append
"Running As Admin: $runningAsAdmin" | Out-File $hostname\Log_$hostname.txt -Append
$user = whoami
"Running User: $user" | Out-File $hostname\Log_$hostname.txt -Append
"Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption | Out-File $hostname\Log_$hostname.txt -Append
$uptimeDate = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
"System Uptime: Since " + $uptimeDate.ToString("dd/MM/yyyy HH:mm:ss") | Out-File $hostname\Log_$hostname.txt -Append
"Part of Domain: " + (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain | Out-File $hostname\Log_$hostname.txt -Append
$currTime = Get-Date
"`nStart Time: " + $startTime.ToString("dd/MM/yyyy HH:mm:ss") | Out-File $hostname\Log_$hostname.txt -Append
"End Time (before zipping): " + $currTime.ToString("dd/MM/yyyy HH:mm:ss")  | Out-File $hostname\Log_$hostname.txt -Append
"Running Time (before zipping): " + [int]($currTime - $startTime).TotalSeconds + " seconds"  | Out-File $hostname\Log_$hostname.txt -Append

# compress the files to a zip. works for PowerShell 5.0 (Windows 10/2016) only. sometimes the compress fails because the file is still in use.
try
{
    Compress-Archive -Path $hostname\* -DestinationPath $hostname -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -Path $hostname -ErrorAction SilentlyContinue
    Write-Host All Done! Please send the output ZIP file to the auditor. -ForegroundColor Green
}
catch
{
    Write-Host All Done! Please ZIP all the files and send them to the auditor. -ForegroundColor Green
}

$endTime = Get-Date
$elapsed = $endTime - $startTime
Write-Host The script took ([int]$elapsed.TotalSeconds) seconds. Thank you. -ForegroundColor Green
Start-Sleep -Seconds 2