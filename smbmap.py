import sys
import signal
import string
import time
import logging
from impacket import smb, version, smb3, nt_errors
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import *
import argparse
import ntpath
import cmd
import os


class SMBMap():

    def __init__(self):
        self.username = None
        self.password = None
        self.domain = None
        self.rpcconn = None
        self.smbconn = None 
        self.port = 445
        self.isLoggedIn = False

    def login(self, username, password, domain, host):
        self.username = username
        self.password = password
        self.domain = domain
        
        try:
            self.smbconn = SMBConnection(host, host, sess_port=self.port)
            self.smbconn.login(username, password, domain=self.domain)
            
            if self.smbconn.isGuestSession() > 0:
                print '[+] Guest SMB session established...'
            else:
                print '[+] User SMB session establishd...'

        except Exception as e:
            print '[!] Authentication error occured'
            sys.exit()
 
    def logout(self):
        self.smbconn.logoff()

    def logout_rpc(self):
        self.rpcconn.logoff() 
                   
    def login_rpc_hash(self, username, ntlmhash, domain, host):
        self.username = username
        self.password = ntlmhash
        self.domain = domain
        
        lmhash, nthash = ntlmhash.split(':')    
    
        try:
            self.rpcconn = SMBConnection('*SMBSERVER', host, sess_port=139)
            self.rpcconn.login(username, '', domain, lmhash=lmhash, nthash=nthash)
            
            if self.rpcconn.isGuestSession() > 0:
                print '[+] Guest RCP session established...'
            else:
                print '[+] User RCP session establishd...'

        except Exception as e:
            print '[!] RPC Authentication error occured'
            sys.exit()
     
    def login_rpc(self, usenrame, password, domain, host):
        self.username = username
        self.password = password
        self.domain = domain
    
        try:
            self.rpcconn = SMBConnection('*SMBSERVER', host, sess_port=139)
            self.rpcconn.login(username, password, domain)
            
            if self.rpcconn.isGuestSession() > 0:
                print '[+] Guest RCP session established...'
            else:
                print '[+] User RCP session establishd...'

        except Exception as e:
            print '[!] RPC Authentication error occured'
            sys.exit()
 
    def login_hash(self, username, ntlmhash, domain, host):
        self.username = username
        self.password = ntlmhash
        self.domain = domain
        
        lmhash, nthash = ntlmhash.split(':')    
    
        try:
            self.smbconn = SMBConnection(host, host, sess_port=self.port)
            self.smbconn.login(username, '', domain, lmhash=lmhash, nthash=nthash)
            
            if self.smbconn.isGuestSession() > 0:
                print '[+] Guest session established...'
            else:
                print '[+] User session establishd...'

        except Exception as e:
            print '[!] Authentication error occured'
            sys.exit()   
 
    def find_open_ports(self, port, protocol):    
        result = 1 
        try:
            if protocol == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(.3)
                result = sock.connect_ex((address,port))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(.3)
                result = sock.connect_ex((address, port))
            if result == 0:
                sock.close()
                return True
        except:
            return False

    def get_shares(self):
        return self.smbconn.listShares()

    def list_shares(self, display=False):
        shareList = self.smbconn.listShares()
        shares = []
        for item in range(len(shareList)):
            if display:
                print shareList[item]['shi1_netname'][:-1]
            shares.append(shareList[item]['shi1_netname'][:-1])
        return shares 

    def list_path_recursive(self, share, pwd, wildcard, pathList):
        root = self.pathify(pwd)
        width = 16
        try:
            pathList[root] = self.smbconn.listPath(share, root)
            print '\t.%s' % (pwd.replace('//','/'))
            if len(pathList[root]) > 2:
                    for smbItem in pathList[root]:
                        try:
                            filename = smbItem.get_longname()
                            isDir = 'd' if smbItem.is_directory() > 0 else '-' 
                            filesize = smbItem.get_filesize() 
                            readonly = 'w' if smbItem.is_readonly() > 0 else 'r'
                            date = time.ctime(float(smbItem.get_mtime_epoch()))
                            if smbItem.is_directory() <= 0:
                                if '-F' in sys.argv:
                                    if smbItem.get_filesize() < 5000000:
                                        fileobj = file('/tmp/temp', 'w+')
                                        remoteFile = conn.retrieveFile(share, '%s/%s' % (root, filename), fileobj)
                                        fileobj.close()
                                        fileobj = open('/tmp/temp', 'r')
                                        data = mmap.mmap(fileobj.fileno(), smbItem.file_size, access=mmap.ACCESS_READ)
                                        match = re.search(resultFilter, data) 
                                        if match:
                                            print '\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(width), date, filename)
                                else:
                                    print '\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(width), date, filename)
                        except SessionError as e:
                            continue
                        except Exception as e:
                            print e

                    for smbItem in pathList[root]: 
                        try:
                            filename = smbItem.get_longname()
                            if smbItem.is_directory() > 0 and filename != '.' and filename != '..':
                                subPath = '%s/%s' % (pwd, filename)
                                subPath = self.pathify(subPath)
                                pathList[subPath] = self.smbconn.listPath(share, subPath)
                                if len(pathList[subPath]) > 2:
                                    self.list_path_recursive(share, '%s/%s' % (pwd, filename), wildcard, pathList)

                        except SessionError as e:
                            continue
        except:
            pass

    def pathify(self, path):
        root = ntpath.join(path,'*')
        root = string.replace(root,'/','\\')
        root = ntpath.normpath(root)
        return root

    def list_path(self, share, path, display=False):
        pwd = self.pathify(path)
        width = 16
        try: 
            pathList = self.smbconn.listPath(share, pwd)
            if display:
                print '\t.%s' % (path.ljust(50))
            for item in pathList:
                filesize = item.get_filesize() 
                readonly = 'w' if item.is_readonly() > 0 else 'r'
                date = time.ctime(float(item.get_mtime_epoch()))
                isDir = 'd' if item.is_directory() > 0 else 'f'
                filename = item.get_longname()
                if display:
                    print '\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(width), date, filename)
            return True
        except Exception as e:
            return False     
 
    def create_dir(self, share, path):
        #path = self.pathify(path)
        self.smbconn.createDirectory(share, path)

    def remove_dir(self, share, path):
        #path = self.pathify(path)
        self.smbconn.deleteDirectory(share, path)
    
    def valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def filter_results(self, pattern):
        pass
    
    def download_file(self,  path):
        path = string.replace(path,'/','\\')
        path = ntpath.normpath(path)
        filename = path.split('\\')[-1]   
        share = path.split('\\')[0]
        path = path.replace(share, '')
        out = open(ntpath.basename('%s/%s' % (os.getcwd(), filename)),'wb')
        try:
            dlFile = self.smbconn.listPath(share, path)
            print '[+] Starting download: %s (%s bytes)' % ('\%s%s' % (share, path), dlFile[0].get_filesize())
            self.smbconn.getFile(share, path, out.write)
            print '[+] File output to: %s/%s' % (os.getcwd(), filename)
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print '[!] Error retrieving file, access denied'
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                print '[!] Error retrieving file, invalid path'
        except Exception as e:
            print '[!] Error retrieving file, unkown error'
            os.remove(filename)
        out.close()
    
    def exec_command(self, command):
        pass
    
    def delete_file(self, path):
        path = string.replace(path,'/','\\')
        path = ntpath.normpath(path)
        filename = path.split('\\')[-1]   
        share = path.split('\\')[0]
        path = path.replace(share, '')
        path = path.replace(filename, '')
        try:
            self.smbconn.deleteFile(share, path + filename)
            print '[+] File successfully deleted: %s%s%s' % (share, path, filename)
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print '[!] Error deleting file, access denied'
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                print '[!] Error deleting file, invalid path'
        except Exception as e:
            print '[!] Error deleting file, unkown error'
            print e
         
    def upload_file(self, src, dst): 
        dst = string.replace(dst,'/','\\')
        dst = ntpath.normpath(dst)
        dst = dst.split('\\')
        share = dst[0]
        dst = '\\'.join(dst[1:])
        print share, dst
        if os.path.exists(src):
            print '[+] Starting upload: %s (%s bytes)' % (src, os.path.getsize(src))
            upFile = open(src, 'rb')
            try:
                self.smbconn.putFile(share, dst, upFile.read)
                print '[+] Upload complete' 
            except:
                print '[!] Error uploading file....zero clues...we\'ll just assume it was you'
            upFile.close() 
        else:
            print '[!] Invalid source. File does not exist'
            sys.exit()

    def is_ntlm(self, password):
       if len(password.split(':')) == 2:
            lm, ntlm = password.split(':')
            if len(lm) == 32 and len(ntlm) == 32:
                return True
            else: 
                return False

    def get_version(self):
        try:
            rpctransport = transport.SMBTransport(self.rpcconn.getServerName(), self.rpcconn.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.rpcconn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrServerGetInfo(dce, 102)

            print "Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major']
            print "Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor']
            print "Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name']
            print "Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment']
            print "Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath']
            print "Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users']
        except:
            print '[!] RPC Access denied...oh well'
            sys.exit()

def signal_handler(signal, frame):
    print 'You pressed Ctrl+C!'
    sys.exit(1)

def usage():
    print 'SMBMap - Samba Share Enumerator'
    print 'Shawn Evans - Shawn.Evans@knowledgeCG.com'
    print ''
    print '$ python %s -u jsmith -p password1 -d workgroup -h 192.168.0.1' % (sys.argv[0])
    print '$ python %s -u jsmith -p \'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d\' -h 172.16.0.20' % (sys.argv[0]) 
    print '$ cat smb_ip_list.txt | python %s -u jsmith -p password1 -d workgroup' % (sys.argv[0])
    print ''
    print '-h\t\tHostname or IP'
    print '-u\t\tUsername, if omitted null session assumed'
    print '-p\t\t\'Password\' (or NTLM hash)' 
    print '-d\t\tDomain name'
    print '-R\t\t\'C$\\finance\' (Recursively list dirs, and files, no share\path lists ALL shares)'
    print '-r\t\tList contents of root only'
    print '-f\t\tFile name filter, -f "password"'
    print '-F\t\tFile content filter, -f "password"'
    print '-D\t\t\'C$\\temp\\passwords.txt\' (download path)'
    print '--upload-src\t\t/temp/payload.exe  (note that this requires --upload-dst for a destiation share)'
    print '--upload-dst\t\tC$\\temp\\payload.exe (destination upload path)'
    print '--del\t\tC$\\temp\\msf.exe (delete a file)'
    print '--skip\t\tSkip delete confirmation prompt'
    print ''
    sys.exit()
     
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    if len(sys.argv) < 3:
        usage()

    mysmb = SMBMap()
    ipArg = ''
    ip = ''
    counter = 0
    isFile = False
    host = {}
    canWrite = 0
    dlPath = False
    src = False
    dst = False
    delFile = False
    lsshare = False 
    lspath = False
    skip = None
    user = ''
    passwd = ''
 
    for val in sys.argv:
        if val == '-?' or val == '--help':
            usage()
        if val == '-R':
            try:
                lspath = sys.argv[counter+1].replace('/','\\').split('\\')
                lsshare = lspath[0]
                lspath = '\\'.join(lspath[1:])
            except:
                continue
        if val == '-u':
            user = sys.argv[counter+1]
        if val == '-p':
            passwd = sys.argv[counter+1]
        if val == '-d':
            domain = sys.argv[counter+1]
        if val == '-h':
            ipArg = sys.argv[counter+1]
        if val == '-D':
            try:
                dlPath = sys.argv[counter+1]
            except:
                print '[!] Missing download source'
                sys.exit()
        if val == '--upload-dst':
            try:
                dst = sys.argv[counter+1]
            except:
                print '[!] Missing destination upload path (-T)'
                sys.exit()
        if val == '--upload-src':
            try:
                src = sys.argv[counter+1]
            except:
                print '[!] Missing upload source'
                sys.exit()
        if val == '--del':
            delFile = sys.argv[counter+1]
        if val == '--skip':
           skip = True 
        counter+=1

    choice = ''  
  
    if delFile and skip == None: 
        valid = ['Y','y','N','n'] 
        while choice not in valid:
            sys.stdout.write('[?] Confirm deletetion of file: %s [Y/n]? ' % (delFile))
            choice = raw_input()
            if choice == 'n' or choice == 'N':
                print '[!] File deletion aborted...'
                sys.exit()
            elif choice == 'Y' or choice == 'y' or choice == '':
                break
            else:
                print '[!] Invalid input'

    if (not src and dst): 
        print '[!] Upload destination defined, but missing source (--upload-src)'
        sys.exit()
    elif (not dst and src):
        print '[!] Upload source defined, but missing destination (--upload-dst)'
        sys.exit()
 
    if '-p' not in sys.argv:
        passwd = raw_input('%s\'s Password: ' % (user))    
 
    if len(set(sys.argv).intersection(['-d'])) == 0: 
        print '[+] Missing domain...defaulting to WORKGROUP'
        domain = 'WORKGROUP'

    if not (sys.stdin.isatty()):
        ip = sys.stdin.readlines()
        isFile = True
    else:
        if mysmb.valid_ip(ipArg):
            ip = ipArg
        else:
            sys.exit()

    print '[+] Finding open SMB ports....'
    if isFile:
        for i in ip:
            try:
                port = 445 
                if port:
                    try:
                        host[i.strip()] = { 'name': socket.gethostbyaddr(i.strip())[0] , 'port' : port }
                    except:
                        host[i.strip()] = { 'name': 'unkown' , 'port' : port }
            except:
                continue
    else:
        port = 445 
        if port:
            try:
                host[ip.strip()] = { 'name' : socket.gethostbyaddr(ip)[0], 'port' : port }
            except:
                host[ip.strip()] = { 'name' : 'unkown' , 'port' : port }

    for key in host.keys():
        if mysmb.is_ntlm(passwd):
            print '[+] Hash detected, using pass-the-hash to authentiate' 
            mysmb.login_hash(user, passwd, domain, key)
        else:
            mysmb.login(user, passwd, domain, key)
        
        print '[+] IP: %s:%d\tName: %s' % (key, host[key]['port'], host[key]['name'].ljust(50))
        if not dlPath and not src and not delFile:        
            print '\tDisk%s\tPermissions' % (' '.ljust(50))
            print '\t----%s\t-----------' % (' '.ljust(50))

        try:
            error = 0
            if dlPath:
                mysmb.download_file(dlPath)
                sys.exit()

            if src and dst:
                mysmb.upload_file(src, dst)
                sys.exit()

            if delFile:
                mysmb.delete_file(delFile)
                sys.exit()

            shareList = [lsshare] if lsshare else mysmb.list_shares(False)
            for share in shareList:
                pathList = {}
                canWrite = False
                try:
                    root = string.replace('/asdf','/','\\')
                    root = ntpath.normpath(root)
                    mysmb.create_dir(share, root)
                    print '\t%s\tREAD, WRITE' % (share.ljust(50))
                    canWrite = True
                    mysmb.remove_dir(share, root)
                except Exception as e:
                    canWrite = False

                if canWrite == False:
                    readable = mysmb.list_path(share, '', False)
                    if readable:
                        print '\t%s\tREAD ONLY' % (share.ljust(50))
                    else:
                        error += 1

                if error == 0 and (len(set(sys.argv).intersection(['-r','-R'])) == 1):
                    path = '/'
                    if '-f' in sys.argv:
                        resultFilter = sys.argv[sys.argv.index('-f') + 1]
                    elif '-F' in sys.argv:
                        resultFilter = sys.argv[sys.argv.index('-F') + 1]
                    else:
                        resultFilter = ''

                    if '-r' in sys.argv:
                        dirList = mysmb.list_path(share, path, True)
                    elif '-R' in sys.argv:
                        if lsshare and lspath:
                            dirList = mysmb.list_path_recursive(lsshare, lspath, '*', pathList)
                            sys.exit()
                        else:
                            dirList = mysmb.list_path_recursive(share, path, '*', pathList)
                    print ''

                if error > 0:
                    print '\t%s\tNO ACCESS' % (share.ljust(50))
                    error = 0
            mysmb.logout() 

        except Exception as e:
            print e
            sys.exit() 
