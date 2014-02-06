#!/usr/bin/python

from smb.SMBConnection import SMBConnection
from nmb.NetBIOS import NetBIOS
import sys
import socket
import os
import signal
import mmap
import re

def signal_handler(signal, frame):
    print 'You pressed Ctrl+C!'
    sys.exit(1)

def get_dir_list(conn, share, root, resultFilter, recursive, pathList = {}, currentRootIndex=0):
    try:
        if recursive:
            pathList[root] = conn.listPath(share, root, search=55)
            rootLength = len(pathList[root])
            print '\t|.%s' % (root) 
            if len(pathList[root]) > 2:
                for smbItem in pathList[root]:
                    filename = smbItem.filename
                    if not (smbItem.isDirectory):
                        if '-F' in sys.argv:
                            if smbItem.file_size < 1000000:
                                fileobj = file('/tmp/temp', 'w+')
                                remoteFile = conn.retrieveFile(share, '%s/%s' % (root, filename), fileobj)
                                fileobj.close()
                                fileobj = open('/tmp/temp', 'r')
                                data = mmap.mmap(fileobj.fileno(), smbItem.file_size, access=mmap.ACCESS_READ)
                                match = re.search(resultFilter, data) 
                                if match:
                                    print '\t\t|%s%s' % ('_'*47, filename)
                        else:
                            if len(resultFilter) > 0 and resultFilter.lower() in filename.lower():
                                print '\t\t|%s%s' % ('_'*47, filename)
                            elif len(resultFilter) == 0:
                                print '\t\t|%s%s' % ('_'*47, filename)
                for smbItem in pathList[root]: 
                    filename = smbItem.filename
                    if smbItem.isDirectory and filename != '.' and filename != '..':
                        if root == '/':
                            subPath = '%s%s' % (root, filename)
                        else:
                            subPath = '%s/%s' % (root, filename)
                        pathList[subPath] = conn.listPath(share, subPath ,search=55)
                        if len(pathList[subPath]) > 2:
                            get_dir_list(conn, share, subPath, resultFilter, True, pathList, currentRootIndex)
                        else:
                            currentRootIndex += 1
            else:
                currntRootIndex = 0
        else:
            print '\t%s.%s' % ('|', root.ljust(50))
            pathList[root] = conn.listPath(share, root , search=55)
            for smbItem in pathList[root]:
                filename = smbItem.filename
                print '\t|%s%s' % ('_'*55, filename) 
    
    except Exception as e:
        pass
        err, name, obj = sys.exc_info()
        print err, name, obj       
        print sys.exc_traceback.tb_lineno 
        print e

def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

def smb_port(address):
    if port_open(address, 445, 'tcp'): return 445
    else: return False

def port_open(address, port, protocol):
    result = 1
    try:
        if protocol == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(.3)
            result = sock.connect_ex((address,port))
        elif prtocol == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(.3)
            result = sock.connect_ex((address, port))
        if result == 0:
            sock.close()
            return True
    except:
        return False

def usage():
    print 'SMBMap - Samba Share Enumerator'
    print 'Shawn Evans - Shawn.Evans@knowledgeCG.com'
    print ''
    print '$ python %s -u jsmith -p password1 -d workgroup 192.168.0.1' % (sys.argv[0])
    print '$ cat smb_ip_list.txt | python %s -u jsmith -p password1 -d workgroup' % (sys.argv[0])
    print ''
    print '-h\t\tHostname or IP'
    print '-u\t\tUsername'
    print '-p\t\tPassword'
    print '-d\t\tDomain name'
    print '-R\t\tRecursively list all dirs, and files'
    print '-r\t\tList contents of root only'
    print '-f\t\tFile name filter, -f "password"'
    print '-F\t\tFile content filter, -f "password"'
    print ''
    sys.exit()

signal.signal(signal.SIGINT, signal_handler)
counter =  0
isFile = False

if len(sys.argv) < 3:
    usage()

ipArg = ''
for val in sys.argv:
    if val == '-u':
        user = sys.argv[counter+1]
    if val == '-p':
        passwd = sys.argv[counter+1]
    if val == '-d':
        domain = sys.argv[counter+1]
    if val == '-h':
        ipArg = sys.argv[counter+1]
    counter+=1

ip = ''
if not (sys.stdin.isatty()):
    ip = sys.stdin.readlines()
    isFile = True
else:
    if valid_ip(ipArg):
        ip = ipArg 
    else:
        sys.exit()

host = {}

print 'Finding open SMB ports....'
if isFile:
    for i in ip:
        try:
            port = smb_port(i.strip()) 
            if port:
                try:
                    host[i.strip()] = { 'name': socket.gethostbyaddr(i.strip())[0] , 'port' : port }
                except:
                    host[i.strip()] = { 'name': 'unkown' , 'port' : port }
        except:
            continue
else:
    port = smb_port(ip.strip())
    if port:
        try:
            host[ip.strip()] = { 'name' : socket.gethostbyaddr(ip)[0], 'port' : port }
        except:
            host[ip.strip()] = { 'name' : 'unkown' , 'port' : port }

canWrite = 0

for key in host.keys():
    print ''
    print 'IP: %s:%d\tName: %s' % (key, host[key]['port'], host[key]['name'].ljust(50)) 
    print '\tDisk%s\tPermissions' % (' '.ljust(50))
    print '\t----%s\t-----------' % (' '.ljust(50))
    conn = SMBConnection(user,passwd,'somedude',host[key]['name'],domain=domain,is_direct_tcp=True)
    try:
        error = 0
        conn.connect(key, host[key]['port'], timeout=1)
        shareList = conn.listShares()
        for share in shareList:
            canWrite = False
            try: 
                conn.createDirectory(share.name,'hacked')
                print '\t%s\tREAD, WRITE' % (share.name.ljust(50))
                canWrite = True 
                conn.deleteDirectory(share.name,'hacked')
            except:
                canWrite = False
    
            try:
                if canWrite == False:
                    conn.listPath(share.name,'/')
                    print '\t%s\tREAD ONLY' % (share.name.ljust(50))
            except:
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
                    dirList = get_dir_list(conn, share.name, path, resultFilter, False)
                elif '-R' in sys.argv:
                    dirList = get_dir_list(conn, share.name, path, resultFilter, True)
                print ''
                    
            if error > 0:
                print '\t%s\tNO ACCESS' % (share.name.ljust(50))
                error = 0
            conn.close()
                   
    except Exception as e:
        print '[ERROR]\tUnable to bind to RPC endpoint'
        conn.close() 
