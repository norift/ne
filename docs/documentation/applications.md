---
layout: default
title: Applications
parent: Documentation
nav_order: 3
---

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Browsers
### Internet Explorer: This website wants to install the following add-on "crystal report activex viewer control"

> The: ActiveXViewer.cab file needs to be downloaded from the source
> http://yourwebsitewherecrystalisinstalled/crystalreportviewers11/ActiveXControls/ActiveXViewer.cab

Extract ActiveXViewer.cab to a folder on the machine, then manually register the .DLL's, restart browser and access the page again.

```
REGSVR32 /S CRVIEWER.DLL
REGSVR32 /S REPORTPARAMETERDIALOG.DLL
REGSVR32 /S SVIEWHLP.DLL
REGSVR32 /S SWEBRS.DLL
```


### Internet Explorer: DLG_FLAGS_INVALID_CA "Your PC doesn’t trust this website’s security certificate."

*Because this site uses HTTP Strict Transport Security, you can’t continue to this site at this time.*

This error is due to issues regarding Zscaler's root CA certificate, this needs to be downloaded and installed again.

- [Zscaler root CA Certificate](http://keyserver.xxx.com/pki/X3/ZscalerRootCertificate-2048-SHA256.crt)

Download the certificate. Double click it and install for user, then do the same and install for machine, and lastly restart Internet Explorer.

### Internet Explorer: Not prompting to download .csv files

This issue can be resolved by creating some registry values to recognize the filetypes and the app to open these in.

```
REG ADD "HKEY_CLASSES_ROOT\MIME\Database\Content Type\application/csv" /v CLSID /t REG_SZ /d "{00020812-0000-0000-C000-000000000046}" /f
REG ADD "HKEY_CLASSES_ROOT\MIME\Database\Content Type\application/csv" /v Encoding /t REG_BINARY /d 08000000 /f
REG ADD "HKEY_CLASSES_ROOT\MIME\Database\Content Type\application/csv" /v Extension /t REG_SZ /d ".csv" /f

REG ADD "HKEY_CLASSES_ROOT\MIME\Database\Content Type\text/csv" /v CLSID /t REG_SZ /d "{00020812-0000-0000-C000-000000000046}" /f
REG ADD "HKEY_CLASSES_ROOT\MIME\Database\Content Type\text/csv" /v Encoding /t REG_BINARY /d 08000000 /f
REG ADD "HKEY_CLASSES_ROOT\MIME\Database\Content Type\text/csv" /v Extension /t REG_SZ /d ".csv" /f

# {00020812-0000-0000-C000-000000000046} is the CLSID for Excel 2016
# {25336920-03F9-11cf-8FD0-00AA00686F13} is the CLSID for the "Browse in place", for filetypes you would want to force open in the browser.
```

### Internet Explorer: There was a temporary DNS error. Error Code:  INET_E_RESOURCE_NOT_FOUND

*This error may occur after installing Microsoft Windows Creators update*

```
REG COPY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ConnectionsX" /f
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /f
```

### Microsoft EDGE: Plugins

- [Reference article](https://docs.microsoft.com/en-us/deployedge/faqs-edge-in-the-enterprise)

Does Microsoft Edge (Chromium-based) support ActiveX controls or BHOs like Silverlight or Java?

No. Microsoft Edge doesn't support ActiveX controls or Browser Help Objects (BHOs) like Silverlight or Java. However, if you're running web apps that use ActiveX controls, BHOs, or legacy document modes on Internet Explorer 11, you can configure them to run in IE mode on the new Microsoft Edge. For more information, see Configure IE mode on Microsoft Edge.


### Google Chrome: "The application has failed to start because its side-by-side configuration is incorrect."

This error is generally resolved by quickly re-installing google chrome, in our environment there are cases where removing/upgrading chrome fails because the old installation reference is still in the registry. So instead of installing as it should the package delivery system asks for the old installer to remove the old app. In the registry location below there should be a google chrome reference, if it is deleted then the software can be pushed.



```

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\KeyID
```

### Google Chrome/Firefox: To export a list you must have a Microsoft SharePoint Foundation compatible application

This is an error message you will receive if you are trying to export sharepoint lists in firefox/chrome, this is due that both these browsers doesn't support ActiveX controls which is used in sharepoint 2013 to validate if you have excel installed, this controller is called SpreadSheetLauncher. For this feature use Internet Explorer.

### Google Chrome: corrupt user profile

```
Rename-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default.old" -confirm:$false
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default.old\bookmarks" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\" -confirm:$false
```

### Google Chrome: displays window in all white or black

Open run and paste in the command below, if it runs sucessfully update the graphics driver on the computer

```
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --disable-gpu
```

### Google Chrome: Not saving bookmarks, not properly closing app, etc

This specific machine was for some reason being pushed an AppV version of both Chrome and FireFox, both these versions of the browsers are normally intended for VDE/VDL's in the citrix environment. This is why the browser was glitchy and not working properly, citrix is more restricted. Quick fix here was to just remove the shortcuts to the AppV launchers. 

```
C:\Users\UserID\AppData\Local\Microsoft\AppV\Client\Integration\
```

### Update for Removal of Adobe Flash Player for Windows

*Applying this update will remove Adobe Flash Player from your Windows device. After this update has been applied, this update cannot be uninstalled.*

This patch is designed to remove the adobe flash player that is built in to Microsoft Edge and Internet Explorer, the patch will only remove the built in version and wont affect any other standalone installations.

- [Windows 10 v1909 KB4577586 Download](http://download.windowsupdate.com/c/msdownload/update/software/updt/2020/10/windows10.0-kb4577586-x64_ec16e118cd8b99df185402c7a0c65a31e031a6f0.msu)

## Oracle
### Run time error '3706': Provider cannot be found

This error will be due to the OraOLEDB.Oracle provider not beeing loaded on the machine. In our case unsure about root cause, but we had to add user rights to the binary folder before we were able to proceed with force loading the .dll file manually.

*Oracle 12c 12.2.0.1*

```
(New-Object system.data.oledb.oledbenumerator).GetElements() | select SOURCES_NAME, SOURCES_DESCRIPTION
# OraOLEDB.Oracle | Oracle Provider for OLE DB

cd C:\app\client\Admin\product\12.2.0\client_1\bin
C:\Windows\System32\regsvr32.exe OraOLEDB12.dll


For x64 System32: C:\Windows\System32\regsvr32.exe
For x86 SysWOW64: C:\Windows\SysWOW64\regsvr32.exe
```

## Java
### The following resource is signed with a weak signature algorithm MD5withRSA and is treated as unsigned.

As of java 8u131 applications signed with MD5withRSA/DSA algorithms are treated as unsigned. To bypass this modify the java.security file in the program files folder to still allow the algorithm.

```
((Get-Content -path "C:\Program Files (x86)\Java\jre1.8.*\lib\security\java.security") -replace 'jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024','#jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024') | Set-Content -Path "C:\Program Files (x86)\Java\jre1.8.*\lib\security\java.security"
```

### Can not verify Deployment Rule Set jar due to certificate expiration

```powershell
remove-item 'C:\Windows\Sun\Java\Deployment\DeploymentRuleSet.jar' -confirm:$false -force
```

### Disable java update prompt



```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy" /v NotifyDownload /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy" /v EnableJavaUpdate /t REG_DWORD /d 0 /f
```

### Viewing oracle app and getting: java.lang.ClassNotFoundException: oracle.forms.engine.Main

The issue in our case affected the certificate store, which then errored out the java applet. Quickly solved by removing the cacerts file.

```
Remove-Item "C:\Program Files (x86)\Java\jre*\lib\security\cacerts" -confirm:$false -force
```

## Cisco AnyConnect
### Unable to change domain password in windows 10

```
Logon Denied
Only one user session is allowed.
%user% is already logged onto this machine.

This user must log off of this machine before you can log on.
```

Issue is resolved by changing a registry key, unable to determine why this was and issue for just a few clients.

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{B12744B8-5BB7-463a-B85E-BB7627E73002}" /v EnforceSingleLogon /t REG_DWORD /d 0 /f
```

## Citrix Reciever/WorkSpaceApp
### The remote session was disconnected because there are no Terminal Service License Servers available to provide a license. Please contact your server administrator

```
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSLicensing" /f
```

### WorkSpaceApp v1904: Unable to connect to the server. Contact your system administrator with the following error: SSL Error 47: The server sent an SSL alert: sslv3 alert handshake failure (alert number unavailable)

*Note: Citrix has deprecated weak cryptography across the board. If the configurations on the backend is not updated to support one of the 3 supported strong cipher suites, you will not be able to connect.*

- [Overview of the Crypto Kit updates in Citrix Workspace for Windows and Mac](https://support.citrix.com/article/CTX250104)

```
# At least one of these is required:  
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)  
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)  
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
```

## Applications
### Notepad++ "When starting app it is not responding"

This issue was resolved by removing the session.xml from the users profile, then it should work once you open the app again.

```
Remove-Item "C:\Users\$env:username\AppData\Roaming\Notepad++\session.xml" -confirm:$false
```

### Anixis PPE - Password Policy Enforcer - Unable to change password while on VPN

*The server SERVERXX.domain.com did not respond (10060). Make sure this server is running PPE V9.0 or later and UDP Port 1333 is not blocked by a firewall.*

> Vendor confirmed that the Anixis tool requires a open port to a DC, either there is none set up or there is some issue with connectivity towards the DC.

### SQLTools - "OCI8: Cannot allocate OCI handle" / "The program can't start because OCI.dll is missing"

Application is installed in the users profile, the application as well have a dependency of the 32 bit Oracle Instant Client. The 2 errors in this case related to the user first of all copied the app files from a different computer, and second he did not have the dependency installed.

- [SQLTools Downloads](http://www.sqltools.net/downloads.html)
- [Oracle Clinet Downloads](https://www.oracle.com/database/technologies/instant-client/microsoft-windows-32-downloads.html)

### Windows Media Player - "Server execution failed"

Generally some issue with the system files, issue should be resolved by doing a system scan.

```
Start-Process -FilePath "${env:Windir}\System32\SFC.EXE" -ArgumentList '/scannow' -Wait -Verb RunAs -WindowStyle hidden
```

### Power BI - "An error happened while reading data from the provider: 'Object reference not set to an instance of an object.'"

```
Locate and copy the oraons.dll file in ‘<>product\12.2.0\client_1’ on your oracle install path
Paste the file into the ‘<>product\12.2.0\client_1\bin directory
```

### mRemoteNG - "Object reference not set to an instance of an object."

Issue seems to be related to a corrupt configuration file, not sure exactly which but issue was resolved by re-installing the app after clearing cached files and folders in the user profile.

```
Uninstall App
Clear mRemoteNG related folders under C:\Users\<username>\AppData\Roaming
Install App
```



