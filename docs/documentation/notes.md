---
layout: default
title: Notes
parent: Documentation
nav_order: 1
---

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## System:

```
# Get the system disk space
Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'" | Select-Object -Property DeviceID, DriveType, VolumeName, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}}
# Get the system disk space alternative
Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'" | Select-Object -Property @{L='FreeSpace';E={"{0:N2} GB" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2} GB" -f ($_.Size/1GB)}}

# Clear credential manager, ran as user
cmdkey /list | ForEach-Object{if($_ -like "*Target:*" -and $_ -like "*"){cmdkey /del:($_ -replace " ","" -replace "Target:","")}}

# Access user certificates
rundll32.exe cryptui.dll,CryptUIStartCertMgr

# Temporarily disable Symantec Antivirus
start smc -stop

# App-V
Get-AppvStatus
Enable-Appv

# Start disk check from remote session
echo y | chkdsk C: /F /R

# Check System Boot Time
(gcim Win32_OperatingSystem).LastBootUpTime
(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime

# ARP
* List entries
arp -a
* Reset cache
arp -d
* Manual entries
- netsh interface ipv4 add neighbors "Local Area Connection" 10.170.52.5 70-10-6f-ae-48-fa
* Remove manual entries
- netsh interface ipv4 reset

# Disable Hyper-V 
- Check if enabled:
bcdedit
msinfo32 - Field: Device Guard Virtualization based security
* If Hyper-V is disabled, you’ll just see a list of technologies that are required for Hyper-V to run and whether they are present on the system.
- To disable virtualization:
dism.exe /Online /Disable-Feature:Microsoft-Hyper-V-All
bcdedit /set hypervisorlaunchtype off

# Change system language
GET-WinSystemLocale
SET-WinSystemLocale

# OLEDB Provider list
(New-Object system.data.oledb.oledbenumerator).GetElements() | select SOURCES_NAME, SOURCES_DESCRIPTION

# Locked Files - Process Explorer from Sysinternals
- Open the Process Explorer Search via Find > Find Handle or DLL (or press Ctrl + F), enter the file name, and wait for the list of processes accessing your file.
- Taskkill /PID XXXX /F
- https://download.sysinternals.com/files/ProcessExplorer.zip

# Missing switch user windows 10 - 1 disabled, 0 on POLICY: Hide entry points for Fast User Switching - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsLogon::HideFastUserSwitching
reg add "HKEY_USERS\S-1-5-21-xxxxxxxx\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v HideFastUserSwitching /t REG_DWORD /d 0 /f
reg delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v HideFastUserSwitching /f
```

## Powershell:

```
# Clone group membership from 1 AD group to another
Add-ADGroupMember -Identity 'newgroup' -Members (Get-ADGroupMember -Identity 'oldgroup' -Recursive)

# Check if special password policy is applied on a account # If no result then the default domain policy applies: Get-ADDefaultDomainPasswordPolicy
Get-ADUserResultantPasswordPolicy $user

# Change domain computername
Rename-Computer –computername OldName –newname NewName –domaincredential Domain\Admin_User –force –restart

# "During a logon attempt, the user’s security context accumulated too many security IDs."
*The security token of a Windows Client can hold up to 1024 SIDs. If a user object is member of more groups than allowed, the logon fails.*
($token=(get-aduser (get-aduser admin_userid) -Properties tokengroups).tokengroups).count

# Filesystem search
Get-ChildItem 'C:\' -recurse | where {$_.name -like '*lmi_rescue.exe*'}

# Registry search:
$path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\'
Get-ChildItem $path -recurse | Get-ItemProperty | Where-Object { $_ -match 'autodesk'}
$path2 = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
Get-ChildItem $path2 -recurse | Get-ItemProperty | Where-Object { $_ -match 'autodesk'}

# User Registry Search:
New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
$path = 'hku:\S-1-5-21-2763872571-2999947588-3099097816-000000\'
Get-ChildItem $path -recurse | Get-ItemProperty | Where-Object { $_ -match 'bbc' -and $_ -match 'player'}

# Get UNC path from DFS shares
- Works on root share:
Get-DfsnFolderTarget -Path "\\dc.domain.com\uk\Sites\Contract"
- Works on sub folders
dfsutil client property state "\\dc.domain.com\uk\Sites\Contract"

# RoboCopy - bad network file transfer (retries if loosing connection)
robocopy $SourceDIR $DestDIR $File /z /w:1 /r:0 /tee /XO /v | Where-Object {$data = $_.Split([char]9); if("$($data[4])" -ne "") {$file = "$($data[4])"} ;Write-Progress "Percentage $($data[0])" -Activity "Robocopy" -CurrentOperation "$($file)" -ErrorAction SilentlyContinue;}
```

## Registry:

```
# For entering a hex value, the /d flag requires that you preface the 8-character hex value with 0x. E.g: /d 0x00000015

# This registry key when set gives a CLI prompt for credentials instead of a pop-up box!
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name ConsolePrompting -Value $true

# Get Windows 10 OS version
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

# Disable flash EOL notification message in Internet Explorer, plugin will be removed at the end of next year.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main" /v DisableFlashNotificationPolicy /t REG_DWORD /d 1 /f

# Interactive logon: Don't display last signed-in
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f

# Disable local admin auto login
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

# Allow for FilePaths above 260 characters, useful for certain scripts that deals with shares that have paths longer than the limit.
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -value 1
# GPEdit location:  Configuration > Administrative Templates > System > FileSystem
```

## Event Logs:

```
# Get event log report after: chkdsk
$FilterXPath = "*[System[Provider[@Name='Microsoft-Windows-Wininit'] and (EventID=1001)]]"
Get-WinEvent -LogName 'Application' -FilterXPath $FilterXPath -MaxEvents 1 | Select-Object -ExpandProperty Message

# Device manager logs
Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration"
Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration" | Select TimeCreated,LevelDisplayName,ID,ProcessId,Message,MachineName
```

## Installs:

```
# WMIC
wmic product where "name='Tachomaster' and version='02.007.0053'" call uninstall
wmic product where "Vendor like '%Autodesk%'" get Name
wmic product where "Caption like '%Adobe%Flash%'" get Name
```

```
# Get SID's on computer
Reg Query 'HKEY_USERS'

# Get reg detals for apps installed in users profile
Reg Query "HKEY_USERS\S-1-5-21-X-X-X-X\software\microsoft\windows\currentversion\uninstall\"
```

```
# Check who installed software
Get-EventLog -LogName Application -InstanceId 1033 -Message *Adobe* | Format-Table TimeGenerated, UserName, Message -AutoSize -Wrap

# Install report from Event Logs
Get-EventLog -LogName Application -InstanceId 1033 -Newest 1 | Select-Object -ExpandProperty message
Get-WinEvent -FilterHashtable @{logname = ‘setup’} | Format-Table timecreated, message -AutoSize -Wrap
# Other options
Get-WinEvent -FilterHashtable @{logname = ‘Application’; ProviderName='Windows Error Reporting';} | Format-Table timecreated, message -AutoSize -Wrap

# Remote software removal - test
Start-Process  -Wait  -FilePath  "wmic"  -ArgumentList  "product where `"name like '%Adobe Reader%'`" call uninstall" -Hidden

# Remote patch install/removal - test
* How to do .msu's?
wusa.exe C:\Packages\windows10.0-kb4577586-x64_ec16e118cd8b99df185402c7a0c65a31e031a6f0.msu /quiet /norestart
wusa.exe /uninstall /kb:123456 /quiet /norestart
* How to do .cab's?
- NO (wusa.exe C:\Packages\spd-x-none_7c1009a5a70cac8d7012a44d2710faf79d7d7fb5.cab /quiet /norestart)
dism.exe /online /add-package /PackagePath:C:\Packages\PatchTemp\Windows10.0-KB4577586-x64.cab

# Remote install of HP Drivers
cmd /c 'c:\packages\sp107705.exe' -e -s
cmd /c 'C:\SWSetup\SP107705\setup.exe' -s
```

```
# To Test: Silent install of SSDT
cmd /c 'SSDT-Setup-ENU15.9.8.exe /install installvssql:ssdt /passive /NORESTART /LOG  c:\packages\ssdt2017-instance-creation.log'
cmd /c 'SSDT-Setup-ENU15.9.8.exe /install installall /passive /NORESTART /LOG  c:\packages\ssdt2017-features-install.log'
```

```
# Silent install of MSODBCSQL
msiexec /i C:\Packages\msodbcsql_17.5.2.1_x64.msi /qn ADDLOCAL=ALL IACCEPTMSODBCSQLLICENSETERMS=YES

# Silent install of SQLNC
msiexec /i C:\Packages\sqlncli.msi /qn ADDLOCAL=ALL IACCEPTSQLNCLILICENSETERMS=YES

# Silent install of VNC Server
cmd /c 'c:\packages\VNC-Server-6.7.2-Windows.exe' /qn REBOOT=ReallySuppress LICENSEKEY=X-X-X-X-X ENABLEAUTOUPDATECHECKS=0 ENABLEANALYTICS=0
** License confirmation: cmd /c 'C:\Program Files\RealVNC\VNC Server\vnclicense.exe' -add X-X-X-X-X
# Silent install of VNC Viewer
cmd /c 'c:\packages\VNC-Viewer-6.20.529-Windows.exe' /qn

# Silent install of Access Runtime 2016
Set-Content 'C:\Packages\office.xml' -value "<Configuration Product=""AccessRT"">`r`n<Display Level=""none"" CompletionNotice=""No"" SuppressModal=""Yes"" NoCancel=""Yes"" AcceptEula=""Yes"" />`r`n<Setting Id=""SETUP_REBOOT"" Value=""Never"" />`r`n</Configuration>"
C:\Packages\AccessRuntime2016_x64_en-us.exe /extract:C:\Packages\AccessRuntime2016_x64_en-us\ /q
C:\Packages\AccessRuntime2016_x64_en-us\setup.exe /config "C:\Packages\office.xml"
Remove-Item "C:\packages\AccessRuntime2016_x64_en-us\" -Recurse -Confirm:$false

# Silent install of NiceLabel-2019
cmd /c 'C:\Packages\NiceLabel2019-BlueYonderVersionONLY.exe' /s LICENSECODE=1234567890 AUTOMATION=FALSE DESIGNER=TRUE RUNTIME=TRUE

# Silent install of Minitab Companion - demo version
cmd /c 'c:\packages\companion5.5.1.0setup.exe' /exenoui /qn ACCEPT_EULA=1 DISABLE_UPDATES=1
- https://www.minitab.com/content/dam/www/en/uploadedfiles/documents/install-guides/MinitabDeploymentGuide_en.pdf

# Silent install of Plantronics Manager
cmd /c 'C:\Packages\PlantronicsHubInstaller.exe' /install /quiet

# Silent install of Jabra Direct
cmd /c 'C:\Packages\JabraDirectSetup5.2.20825.exe' /install /quiet /norestart

# Silent install of Logitech Unifying Software
cmd /c 'C:\Packages\unifying250.exe /S'
- Installs under: C:\Program Files\Common Files\LogiShrd\Unifying\
- Reg: HKEY_LOCAL_MACHINE\SOFTWARE\Logitech\Unifying
* Uninstall: cmd /c 'C:\Program Files\Common Files\LogiShrd\Unifying\UnifyingUnInstaller.exe' /S

# Silent install of Adobe Creative Cloud
Expand-Archive "C:\Packages\Windows 10_en_US_WIN_64.zip" "C:\Packages"
cmd /c "C:\Packages\windows 10\build\setup.exe" --silent

# Silent install of Crystal Reports Developer Edition v10
Set-Content 'C:\Packages\Response.ini' -value "### Product keycode`r`nproductkey=""XXXXX-XXXXXXX-XXXXXX-XXXXXXX-XX"""
cmd /c 'setup.exe -r C:\Packages\Response.ini'
- https://help.sap.com/viewer/9fe2522cc23841d389160e24e801186f/2016.4/en-US/476017e16e041014910aba7db0e91070.html

# Silent install of QZ Tray
- First install Java if it is not already installed on the machine
cmd /c 'start /wait "" C:\Packages\qz-tray-2.1.3+1.exe /S'

# Silent install of Bartender
- https://www.seagullscientific.com/media/1677/bartender-silent-install-201908.pdf
- Apparently some issue wit SQL install - https://support.seagullscientific.com/hc/en-us/community/posts/360031105814-2019-Silent-Install
cmd /c 'C:\Packages\BT2019_R9_156128_Full_x64.exe FEATURE=BarTender PKC=xxxx-xxxx-xxxx-xxxx'
- Works, will run from remote PS as a separate window in admin context
Start-Process -FilePath "C:\Packages\BT2019_R9_156128_Full_x64.exe" -ArgumentList 'FEATURE=BarTender PKC=xxxx-xxxx-xxxx-xxxx' -Wait -Verb RunAs -WindowStyle hidden
- Removal
cmd /c 'C:\Packages\BT2019_R9_156128_Full_x64.exe REMOVE=ALL'

# Silent install of DYMO LabelWriter
- Needs to be ran as administrator after install to add printer
- If printer drivers only is needed then use: cmd /c 'C:\Packages\DLS8Setup.8.5.4.exe' /S /p
cmd /c 'C:\Packages\DLS8Setup.8.5.4.exe' /S
cmd /c 'C:\Program Files (x86)\DYMO\DYMO Label Software\Uninstall DYMO Label.exe' /S

# Silent install of Amazon Workspaces
cmd /c 'C:\Packages\Amazon+WorkSpaces.msi' ALLUSERS=1 /qn
```

## UnInstalls:

```
# CCleaner
cmd /c '"C:\Program Files\CCleaner\uninst.exe" /S'

# AutoCAD:
wmic product where "vendor like '%autodesk%'" call uninstall
cmd /c 'TASKKILL /F /IM "AdAppMgr.exe" & TASKKILL /F /IM "AdAppMgrUpdater.exe" & TASKKILL /F /IM "AutodeskDesktopApp.exe"'
cmd /c "C:\Program Files (x86)\Autodesk\Autodesk Desktop App\removeAdAppMgr.exe" --mode unattended
- Optional
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AutodeskDesktopApp.exe" /f
remove-item "C:\Programdata\Autodesk" -recurse -force
remove-item "C:\Users\*\AppData\Roaming\Autodesk\Autodesk Desktop App\" -recurse -force
remove-item "C:\Users\*\AppData\Local\Autodesk\Web Services\" -recurse -force
```

## Active Directory:

```
# LogonWorkstations Attribute - Service account security restriction
- Attribute works differently than you would expect, the option says "LOG ON TO" but means "LOG ON FROM". So the HOST and not the TARGET needs to be added to the list.
- In the case of scan to folder accounts: The printer hostname needs to be added to the attribute! Not the target server it is scanning to.

* This wont work well for AD integrated applications!
- For this feature a policy can be set up to apply for these accounts to restrict login to domain computers.
- Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Deny log on locally
```

## GPO Policy:

```
# User Configuration\Administrative Templates\Windows Components\File Explorer\Remove "Map Network Drive" and "Disconnect Network Drive"
- HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoNetConnectDisconnect
- Workaround to use command to map the share: net use Z: \\server\share /PERSISTENT:YES
```



