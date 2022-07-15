#This Script is used to Upgrade the CWS (Software/Firmware)
#Usage: python CWSUpgrade.py
#More Info: @ https://wiki.parallelwireless.net/display/ENG/CWS+Upgrade+TOOL
#
#Authors: Rajesh Kotoju (rkotoju@parallelwireless.com) , Chakradhar Sarvana (<csarvana@parallelwireless.com>)
Version="2.0 (05/06/2020)"

#Check if all these packages are installed
try:
    import paramiko
    import sys
    import threading
    import os
    import time
    import commands
    import logging
    import collections
    import json
    import argparse
    import re
    import signal
    import tarfile 
    import datetime 
    import socket
except Exception as e:
    sys.stderr.write("Exception while importing the packages %s , Exiting \n" %str(e))
    exit(1)

install_status  = []
cwsSession      = {}
threads_cws     = []
install_all_threads  = []

parser = argparse.ArgumentParser(description='Script to Upgrade the CWS')
parser.add_argument('-v', '--version', action='store_true', 
    help="shows version")
args = parser.parse_args()

if args.version:
    print ("Version is %s" %Version)
    sys.exit(1)

#Default values, user can change if required
LOGGING_LEVEL = logging.INFO
SCRIPT_LOGGING = "" 

def signal_handler(number, frame):
    logging.info("Received Signal %s" %number)
    print 'Received signal %s' % (threading.currentThread())
    if number == signal.SIGINT:
        pass  
    elif number == signal.SIGTERM:
        for i, t in enumerate(install_all_threads):
            if (t.is_alive() is True): 
                print t._Thread__name 
                t.join()
        sys.exit(1)

#Function to Log
def logger(cws_ip = "", log_str= "" , level = False, console = True, date = "" ):
    if date :
        date = commands.getoutput('date +%D-%T-%3N ')
    if level:
        logging.error(date+" "+cws_ip+" "+ log_str)
    else:
        logging.info(date+" "+cws_ip+" "+ log_str)
    if console: 
        print (date+" "+cws_ip+" "+ log_str)

class CWS(threading.Thread):
    def __init__ (self, parent, paramsList):
        threading.Thread.__init__(self)
        self.automation      =    parent
        self.CwsIpAddr        =    paramsList[0].strip()
        self.M_VLAN          =    paramsList[1]
        self.S_VLAN          =    paramsList[2]
        self.UNIRANID        =    paramsList[3]
        self.HWCLASSID       =    paramsList[4]
        self.CLOUDSERVERADDR =    paramsList[5]
        self.SEC_GW_ADDR     =    paramsList[6]
        self.UNIRANADDR      =    paramsList[7]
        self.IPSEC           =    paramsList[8]
        self.network_ipaddr  =    paramsList[9]
        self.network_netmask =    paramsList[10]
        self.network_gw      =    paramsList[11]
        self.install_configure  =    paramsList[12]

        self.CWS_MASTER_IP    = "169.254.1.3"
        self.CWS_SLAVE_IP     = "169.254.1.4"
        self.user             = 'root'
        self.passwd           = parent.CWS_ROOT_PWD
        self.slave_passwd     = parent.CWS_SLAVE_ROOT_PWD
        self.fw_force_install = parent.FW_FORCE_INSTALL
        self.sw_force_install = parent.SW_FORCE_INSTALL
        self.RETRY_COUNT      = 0
        self.MAX_RETRIES      = 2
        self.UPGRADE_SCRIPT   = "cwsUpgrade.sh" 
        self.start_time       = time.time()
        self.rrhsystem_info   = "" 
        self.disk_info        = "" 
        self.hardware_info    = {}
        self.FIRMWARE_VERSION = ""
        self.UPGRADE_RETRY    = 0
        self.MVLAN_CONFIGURED = False
        self.SVLAN_CONFIGURED = False
 
        self.cws_master       = None
        self.cws_master_ssh   = None
        self.cws_slave       = None
        self.cws_slave_ssh   = None
        self.CWS_STATE        = None
        self.UPGRADE_SCRIPT_CMD = None 
        self.CWS_INSTALL_STATUS = ["UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"]

        self.MASTER_SLAVE       = self.automation.MASTER_SLAVE 
        self.CWS_FIRMWARE_PKG   = self.automation.FIRMWARE_PKG
        self.CWS_SOFTWARE_PKG   = self.automation.CWS_SOFTWARE

        self.slave_Networkfile_NAME = "slave_network_"+self.CwsIpAddr
        self.slave_Unifile_NAME = "slave_uniRanConfig.ini.sample_"+self.CwsIpAddr

        #CHAKRI, Comment the below 3 & Uncomment the further 3 rows for local testing
        self.slave_Tgt_Ini= "uniRanConfig.ini"
        self.slave_Tgt_Nw = "network"
        self.master_UniranConfig = "/staging/etc/uniRanConfig.ini"

#        self.master_UniranConfig = "/staging/etc/uniRanConfig.ini.sample"
#        self.slave_Tgt_Ini= self.slave_Unifile_NAME
#        self.slave_Tgt_Nw = self.slave_Networkfile_NAME

        self.slave_Networkfile_PATH = self.automation.BUILD_PATH + "/TEMPLATES/"+self.slave_Networkfile_NAME
        self.slave_Uniranfile_PATH = self.automation.BUILD_PATH+"/TEMPLATES/"+self.slave_Unifile_NAME

        self.MD5SUM_SLAVE_CWS_NW_File  = "" 
        self.MD5SUM_SLAVE_CWS_INI_File  = "" 
     
        self.CWS_EXPECTED_RESULT = ["UNKNOWN", "UNKNOWN", "UNKNOWN" ]
        if self.automation.FIRMWARE_PKG:
            self.CWS_EXPECTED_RESULT[0] = "SUCCESS"
        if self.automation.CWS_SOFTWARE:
            if self.automation.SLAVE_ONLY_INSTALL:
                self.CWS_EXPECTED_RESULT[1] = "SUCCESS"
            elif self.automation.MASTER_SLAVE and self.automation.MASTER_SLAVE == "MASTER":
                self.CWS_EXPECTED_RESULT[1] = "SUCCESS"
            elif self.automation.MASTER_SLAVE and self.automation.MASTER_SLAVE == "SLAVE":
                self.CWS_EXPECTED_RESULT[2] = "SUCCESS"
            else: 
                self.CWS_EXPECTED_RESULT[1] = "SUCCESS"
                self.CWS_EXPECTED_RESULT[2] = "SUCCESS"

        self.rsync = self.automation.BUILD_PATH+"PACKAGES/rsync"
        self.sshpass = self.automation.BUILD_PATH+"PACKAGES/sshpass"
        self.file_transfer = self.automation.FILE_TRANSFER

        if self.passwd:
            self.SSH_CMD_MASTER  = "sshpass -p "+self.passwd+" ssh -b "+self.automation.HOST_IP_ADDR+" -oStrictHostKeyChecking=no -oConnectTimeout=30 "+self.user+"@"
            if "scp" in self.file_transfer:
                self.SCP_CMD = "sshpass -p "+self.passwd+" scp -o StrictHostKeyChecking=no -o ConnectTimeout=60 -o BindAddress="+self.automation.HOST_IP_ADDR+" "
            else:  
                self.SCP_CMD = "sshpass -p "+self.passwd+" "+self.rsync+"  -e \"ssh -o StrictHostKeyChecking=no -o BindAddress="+self.automation.HOST_IP_ADDR+"\" --timeout=30 "
        else:
            self.SSH_CMD_MASTER  = "ssh -b "+self.automation.HOST_IP_ADDR+" -oStrictHostKeyChecking=no -oConnectTimeout=30 "+self.user+"@"
            if "scp" in self.file_transfer:
                self.SCP_CMD = "scp -o StrictHostKeyChecking=no -o ConnectTimeout=60 -o BindAddress="+self.automation.HOST_IP_ADDR+" "
            else:
                self.SCP_CMD = self.rsync+" -e \"ssh -o StrictHostKeyChecking=no -o BindAddress="+self.automation.HOST_IP_ADDR+"\" --timeout=30 "

        if self.slave_passwd:
            if "scp" in self.file_transfer:
                self.SCP_SLAVE_CMD = "sshpass -p "+self.slave_passwd+" scp -o StrictHostKeyChecking=no -oConnectTimeout=30 -o BindAddress="+self.automation.HOST_IP_ADDR+" "
            else:
                self.SCP_SLAVE_CMD = "sshpass -p "+self.slave_passwd+" "+self.rsync+" -e \"ssh -o StrictHostKeyChecking=no -o BindAddress="+self.automation.HOST_IP_ADDR+"\" --timeout=30 "
            self.SSH_SLAVE  = "/tmp/sshpass -p "+self.slave_passwd+" ssh -b "+self.automation.HOST_IP_ADDR+" -oStrictHostKeyChecking=no -oConnectTimeout=30 "+self.user+"@"+self.UNIRANADDR
        else:
            if "scp" in self.file_transfer:
                self.SCP_SLAVE_CMD = " scp -o StrictHostKeyChecking=no -oConnectTimeout=30 -o BindAddress="+self.automation.HOST_IP_ADDR+" "
            else:
                self.SCP_SLAVE_CMD = self.rsync+" -e \"ssh -o StrictHostKeyChecking=no -o BindAddress="+self.automation.HOST_IP_ADDR+"\" --timeout=30 "
            self.SSH_SLAVE  = " ssh -b "+self.automation.HOST_IP_ADDR+" -oStrictHostKeyChecking=no -oConnectTimeout=30 -o BindAddress="+self.automation.HOST_IP_ADDR+" "+self.user+"@"+self.UNIRANADDR

        self.SSH_CMD_SLAVE = "ssh -oStrictHostKeyChecking=no -oConnectTimeout=30 root@"+self.CWS_SLAVE_IP
        #self.SSH_CMD_SLAVE = self.SSH_CMD_MASTER+ self.CwsIpAddr+ " \" ssh -oStrictHostKeyChecking=no -oConnectTimeout=30 root@"+self.CWS_SLAVE_IP
        self.SSH_SLAVE_LOCALIP = "ssh -oStrictHostKeyChecking=no -oConnectTimeout=30 root@"+ self.CWS_SLAVE_IP

        date = (commands.getoutput('date +%D_%T').replace("/", "_")).replace(":", "_")

        if self.automation.INDIVIDUAL_CWS_LOG:
            filename = self.automation.DEBUG_LOG_PATH +"/log_collected_on_HNG_"+self.CwsIpAddr+"_"+date+".log"
            self.logger = logging.getLogger(self.CwsIpAddr)
            self.logger.addHandler(logging.FileHandler(filename ))
        self.shutdown_flag = threading.Event()

    def run(self):
        while not self.shutdown_flag.is_set():
            time.sleep(0.5)

    def getDate(self):
        date = commands.getoutput('date +%D_%T')
        date = date.replace("/", "_")
        date = date.replace(":", "_")
        return date 
        
    def updateCwsLog(self, cws_ip = "", log_str= "" , level = False, console = True, date = ""):      
        cws_ip = self.CwsIpAddr
        if self.automation.INDIVIDUAL_CWS_LOG:
            if date :
                date = self.getDate()
            if level:
                self.logger.error(date+" "+cws_ip+" "+ log_str)
            else:
                self.logger.info(date+" "+cws_ip+" "+ log_str)
        self.automation.logger(log_str=log_str, cws_ip = cws_ip, level = level, console = console )

   #Generate Upgrade Script command
    def generateUpgradeScript(self):
        #"Usage: ./cwsUpgrade.sh <masterIP> <slaveIP> <hngIP> <master,slave> <cwsBuild> <firmware> <path>"
        logging.info(commands.getoutput('date +%D-%T-%3N')+"Generating  Upgrade command for CWS: "+str(self.CwsIpAddr))

        self.UPGRADE_SCRIPT_CMD = "./"+self.UPGRADE_SCRIPT+ " "+ self.CwsIpAddr +" "+ self.CWS_SLAVE_IP+ " "+ self.automation.HOST_IP_ADDR+ " " 

        if self.automation.SLAVE_ONLY_INSTALL:
            self.UPGRADE_SCRIPT_CMD += " True,False "    
        elif not self.CWS_SOFTWARE:
            self.UPGRADE_SCRIPT_CMD += " False,False " 
        else:
            if self.automation.MASTER_SLAVE: 
                if self.automation.MASTER_SLAVE == "MASTER":
                    self.UPGRADE_SCRIPT_CMD += " True,False "
                elif self.automation.MASTER_SLAVE == "SLAVE":
                    self.UPGRADE_SCRIPT_CMD += " False,True "
                else:
                    self.updateCwsLog(self.CwsIpAddr, "INVALID ARGUMENT PROVIDED for UPGRADE SCRIPT") 
                    return False
            else:
                self.UPGRADE_SCRIPT_CMD += " True,True " 

        if not self.CWS_FIRMWARE_PKG:
            self.UPGRADE_SCRIPT_CMD += self.CWS_SOFTWARE+ " False"
        elif not self.CWS_SOFTWARE:
            self.UPGRADE_SCRIPT_CMD += "False " + self.CWS_FIRMWARE_PKG
        else:
            self.UPGRADE_SCRIPT_CMD += self.CWS_SOFTWARE+ " "+ self.CWS_FIRMWARE_PKG

        self.UPGRADE_SCRIPT_CMD += " "+ self.automation.REMOTE_PKG_PATH 
        logging.info(commands.getoutput('date +%D-%T-%3N')+" Upgrade command for CWS: "+str(self.CwsIpAddr))


    #Function to Login To Master CWS
    def loginToMainCws(self):
        NODE = "MASTER"
        if self.automation.SLAVE_ONLY_INSTALL:
            NODE = "SLAVE"
        if self.cws_master_ssh is not None and self.cws_master_ssh.get_transport() and self.cws_master_ssh.get_transport().is_active():
            return True

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.automation.HOST_IP_ADDR, 0))           
        sock.connect((self.CwsIpAddr, 22))       

        self.cws_master_ssh= paramiko.SSHClient()
        self.cws_master_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.cws_master_ssh.connect(self.CwsIpAddr,username=self.user,password=self.passwd, sock = sock, allow_agent=False)
            self.cws_master = self.cws_master_ssh.invoke_shell() 
            logging.info(commands.getoutput('date +%D-%T-%3N')+" Created SSH Connection to "+str(self.CwsIpAddr))
            self.updateCwsLog(self.CwsIpAddr, " LOGIN TO "+str(NODE)+" CWS SUCCESSFUL")
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES): 
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! while connecting to "+str(self.CwsIpAddr)+ "Error: "+str(e))
                self.updateCwsLog(self.CwsIpAddr, "  LOGIN TO "+str(NODE)+" CWS FAILURE ERROR: "+str(e), "error")
                self.CWS_INSTALL_STATUS[0] = "LOGIN FAILED"
                return False
            else: 
                self.updateCwsLog(self.CwsIpAddr, "  LOGIN TO "+str(NODE)+" CWS FAILED, RETRYING: "+str(e), "error")
                time.sleep(30)     
                self.RETRY_COUNT += 1             
                self.loginToMainCws()

    #Function to Copy a File from HOST to Slave Mgmt IP
    def scpBuildToSlave(self, build):
        try:
            cmd = self.SCP_SLAVE_CMD + self.automation.RATE_LIMIT+ " " + build +" "+self.user+"@"+self.UNIRANADDR+":/tmp/"
            logging.info(commands.getoutput('date +%D-%T-%3N')+" COPYING SSHPASS TO SLAVE "+cmd+" on CWS "+ str(self.UNIRANADDR))
            result = commands.getoutput(cmd)
            logging.info(commands.getoutput('date +%D-%T-%3N')+" SSHPASS COPIED TO SLAVE " + str(self.UNIRANADDR)+str(result))

            """cmd = "/tmp/"+self.SSH_CMD_MASTER+self.CWS_MASTER_IP+ " md5sum /tmp/"+build.split("/")[-1]
            logging.info(commands.getoutput('date +%D-%T-%3N')+" VALIDATING MD5SUM OF SSHPASS"+cmd+" on CWS "+ str(self.UNIRANADDR))
            result = commands.getoutput(cmd)
            logging.info(commands.getoutput('date +%D-%T-%3N')+" MD5SUM OUTPUT OF SSHPASS "+str(cmd) + str(self.UNIRANADDR)+str(result))
            if "a7a0916e322ebaa3b3d9ca24efa26f8e" not in result:
                logging.error(self.getDate()+" UNABLE TO VALIDATE MD5SUM ON SLAVE "+result+ "  CWS : "+ str(self.UNIRANADDR))
                return False
            """
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
               logging.info(commands.getoutput('date +%D-%T-%3N')+" Exception while doing SCP on CWS:"+str(self.UNIRANADDR)+" Error: "+str(e)+"\n")
               return False
            else:
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" SCP OF BUILD "+ build+ " ON CWS: "+str(self.UNIRANADDR)+ " FAILED, RETRYING"+ " Error: "+str(e))
                time.sleep(5)
                self.RETRY_COUNT += 1
                self.scpBuildToSlave(build)
        return True

        
    #Function to Copy a File from HOST to Master
    def scpBuild(self, build, pkg_type = "sw"):
        self.updateCwsLog(log_str =" COPYING THE PACKAGE "+str(pkg_type).upper()+" TO CWS ") 
        try:
            cmd = self.SCP_CMD + self.automation.RATE_LIMIT+ " " + build +" "+self.user+"@"+self.CwsIpAddr+":"+self.automation.REMOTE_PKG_PATH
            logging.info(commands.getoutput('date +%D-%T-%3N')+" EXECUTING COMMAND "+cmd+" on CWS "+ str(self.CwsIpAddr))
            result = commands.getoutput(cmd)
            logging.info(commands.getoutput('date +%D-%T-%3N')+" File Copied to Master" + str(self.CwsIpAddr)+str(result))

            if not self.validateMd5Sum (self.cws_master , pkg_type):
                logging.error(self.getDate()+" UNABLE TO VALIDATE MD5SUM ON MASTER "+build+ "  CWS : "+ str(self.CwsIpAddr))
                return False

            return True

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
               logging.info(commands.getoutput('date +%D-%T-%3N')+" Exception while doing SCP on CWS:"+str(self.CwsIpAddr)+" Error: "+str(e)+"\n")
               self.CWS_INSTALL_STATUS[0] = "BUILD SCP FAILED"
               return False
            else: 
                self.updateCwsLog(log_str =commands.getoutput('date +%D-%T-%3N')+" SCP OF BUILD "+ build+ " ON CWS: "+str(self.CwsIpAddr)+ " FAILED, RETRYING"+ " Error: "+str(e))
                time.sleep(5)     
                self.RETRY_COUNT += 1             
                self.scpBuild(build, pkg_type)    


    def copyFileToSlave(self, build, pkg_type = "ini"):
        try:
            build = build.split("/")[-1:][0]
            if pkg_type == "uniran":
                cmds_list = ["scp -o StrictHostKeyChecking=no -oConnectTimeout=30 /tmp/"+build+" root@"+self.CWS_SLAVE_IP+":/staging/etc/"+self.slave_Tgt_Ini]
            else:
                cmds_list = ["scp -o StrictHostKeyChecking=no -oConnectTimeout=30 /tmp/"+build+" root@"+self.CWS_SLAVE_IP+":/etc/config/"+self.slave_Tgt_Nw]
            if not self.runCommandsOnMaster(cmds_list):
                self.updateCwsLog( log_str = package+ " File copy to Slave CWS Failed", cws_ip = self.CwsIpAddr, level = "error")
                return False

            if not self.validateMd5SumOnSlave(pkg_type):
                logging.error(self.getDate()+" UNABLE TO VALIDATE MD5SUM ON SLAVE "+build+ "  CWS : "+ str(self.CwsIpAddr))
                return False
            time.sleep(1)

            return True

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
               logging.info(commands.getoutput('date +%D-%T-%3N')+" Exception while doing SCP on CWS:"+str(self.CwsIpAddr)+" Error: "+str(e)+"\n")
               self.CWS_INSTALL_STATUS[0] = "BUILD SCP FAILED"
               return False
            else: 
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" SCP OF BUILD "+ build+ " ON CWS: "+str(self.CwsIpAddr)+ " FAILED, RETRYING"+ " Error: "+str(e))
                time.sleep(5)     
                self.RETRY_COUNT += 1             
                self.copyFileToSlave(build, pkg_type)    


    #Function to run commands on Master CWS
    def runCommandsOnMaster(self, cmds_list, slave_check = False):
        try:
            if (self.cws_master_ssh is not None) and self.cws_master_ssh.get_transport() and (not self.cws_master_ssh.get_transport().is_active()):
                logging.info(commands.getoutput('date +%D-%T-%3N')+" SSH Connection to master is down, reinitiating")
                if not self.pollCws():
                    return False

            if slave_check: 
                if not self.pollSlaveCws():
                    return False     

            self.sendCommand("\n") 
            time.sleep(1)
            output = self.cws_master.recv(65535)
            for cmd in cmds_list:
                logging.info("\n\n"+commands.getoutput('date +%D-%T-%3N')+" EXECUTING COMMAND "+cmd+" on CWS "+ str(self.CwsIpAddr))

                self.sendCommand(cmd+"\n")     
                time.sleep(1)
                output = self.cws_master.recv(65535)
                if "main -v" in cmd:
                    self.rrhsystem_info = output.split("\n") 
                if "df -kh" in cmd:
                    output = output.split("\n")
                    self.disk_info = int(output[1].split(".")[0])
                    self.disk_info += 20
                logging.info("\n"+commands.getoutput('date +%D-%T-%3N')+" Command "+str(cmd)+" output on CWS:\n "+ str(self.CwsIpAddr)+str(output)+"\n")
                time.sleep(0.5)
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception while running commands on Master CWS: "+ str(self.CwsIpAddr)+ "Error "+ str(e))
                return False
            else:
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" EXECUTION OF CMDS ON CWS: "+str(self.CwsIpAddr)+ "FAILED, RETRYING "+ " Error: "+str(e))
                time.sleep(20)
                self.RETRY_COUNT += 1
                self.runCommandsOnMaster(cmds_list)


    #Function to Login To Master CWS
    def loginToSlaveCws(self):
        if self.cws_slave_ssh is not None and self.cws_slave_ssh.get_transport() and self.cws_slave_ssh.get_transport().is_active():
            return True

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.automation.HOST_IP_ADDR, 0))           
        sock.connect((self.UNIRANADDR, 22))       

        self.cws_slave_ssh= paramiko.SSHClient()
        self.cws_slave_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.cws_slave_ssh.connect(self.UNIRANADDR,username=self.user,password=self.slave_passwd, sock = sock, allow_agent=False)
            self.cws_slave = self.cws_slave_ssh.invoke_shell()
            logging.info(commands.getoutput('date +%D-%T-%3N')+" Created SSH Connection to "+str(self.UNIRANADDR))
            self.updateCwsLog(self.UNIRANADDR, " LOGIN TO SLAVE SUCCESSFUL")
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! while connecting to "+str(self.UNIRANADDR)+ "Error: "+str(e))
                self.updateCwsLog(self.UNIRANADDR, "  LOGIN TO SLAVE FAILURE ERROR: "+str(e), "error")
                self.CWS_INSTALL_STATUS[0] = "LOGIN FAILED"
                return False
            else:
                self.updateCwsLog(self.UNIRANADDR, "  LOGIN TO SLAVE FAILED, RETRYING: "+str(e), "error")
                time.sleep(5)
                self.RETRY_COUNT += 1
                self.loginToSlaveCws()

    #Function to enable Root Access on Slave
    def enableRootAccessOnSlave(self):
        self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = "  ENABLING ROOT ACCESS ON SLAVE CWS")
        ssh_cmd = 'ssh -oStrictHostKeyChecking=no -oConnectTimeout=30 admin@'+self.CWS_SLAVE_IP 
        #cmds_list = [ssh_cmd, 'admin', 'shell', 'Pw@dm1n', 'su', '', 'sudo sed -i \'s/PermitRootLogin.*no/PermitRootLogin yes/g\' /etc/ssh/sshd_config', 'sudo sed -i \'s/PermitEmptyPasswords.*/PermitEmptyPasswords yes/g\' /etc/ssh/sshd_config', 'sudo /etc/init\.d/sshd stop', 'sudo /etc/init\.d/sshd start', 'sync', 'exit', 'exit', 'exit']
        cmds_list = [ssh_cmd, 'admin', 'shell', 'Pw@dm1n', 'su', '', 'sudo sed -i \'s/PermitRootLogin.*no/PermitRootLogin yes/g\' /opt/pw/bbp/etc/ssh/sshd_config', 'sudo sed -i \'s/PermitEmptyPasswords.*/PermitEmptyPasswords yes/g\' /opt/pw/bbp/etc/ssh/sshd_config', 'sudo /etc/init\.d/sshd stop', 'sudo /etc/init\.d/sshd start', 'sync', 'exit', 'exit', 'exit']
        retry_count  = 0
        while (retry_count <= self.MAX_RETRIES):
            if self.runCommandsOnMaster(cmds_list, slave_check =True):
               break
            self.updateCwsLog(self.CwsIpAddr, " ENABLING ROOT ACCESS FAILED , RETRYING")
            time.sleep(5)
            retry_count += 1
        if (retry_count > self.MAX_RETRIES):
            return False
        else:
            return True
 
    #Function to backup Nw & Ini file
    def backupNwIniFile(self):
        self.updateCwsLog(self.CwsIpAddr, " BACKING UP NW/INI FILE ON SLAVE CWS "+str(self.CWS_SLAVE_IP))
        ssh_cmd = 'ssh -oStrictHostKeyChecking=no -oConnectTimeout=30 root@'+self.CWS_SLAVE_IP 
        cmds_list = [ssh_cmd, 'cp /staging/etc/uniRanConfig.ini /staging/etc/uniRanConfig.ini_backup_upg', 'cp /etc/config/network /etc/config/network_backup_upg', 'sync',  'exit']
        self.RETRY_COUNT = 0
        return self.runCommandsOnMaster(cmds_list, slave_check =True)

   
    #Function to Validate the MD5 Sum 
    def validateMd5Sum(self, cws, pkg_name = "sw"):
        self.updateCwsLog(self.CwsIpAddr, " VALIDATING MD5SUM OF THE PACKAGE "+str(pkg_name).upper())
        try:  
            if pkg_name == "sw": 
                self.sendCommand("md5sum "+self.automation.REMOTE_PKG_PATH+self.automation.CWS_SOFTWARE+"\n")
                time.sleep(10) 
                md5sum_sw_pkg = cws.recv(65535) 

                if (self.automation.MD5SUM_CWS_SW_PKG in md5sum_sw_pkg) :
                    logging.info(commands.getoutput('date +%D-%T-%3N')+" MD5Sum's of Software pkg Matching on CWS: "+str(self.CwsIpAddr))
                else: 
                    logging.error(commands.getoutput('date +%D-%T-%3N')+" MD5SUM NOT MATCHING FOR SOFTWARE PKG " +str(md5sum_sw_pkg)+ "on CWS: "+str(self.CwsIpAddr))
                    logging.error("Expected: "+self.automation.MD5SUM_CWS_SW_PKG+ " Received: "+md5sum_sw_pkg)
                    return False

            if pkg_name == "fw": 
                self.sendCommand("md5sum "+self.automation.REMOTE_PKG_PATH+self.automation.FIRMWARE_PKG+"\n")
                time.sleep(10) 
                md5sum_frw_pkg = cws.recv(65535) 
   
                if (self.automation.MD5SUM_CWS_FIRMWARE_PKG in md5sum_frw_pkg):
                    logging.info(commands.getoutput('date +%D-%T-%3N')+" MD5Sum's of Firmware pkg Matching on CWS: "+str(self.CwsIpAddr))
                else:
                    logging.error(commands.getoutput('date +%D-%T-%3N')+" MD5SUM MISMATCH FOR FIRMWARE PKG " +str(md5sum_frw_pkg)+ "on CWS: "+str(self.CwsIpAddr))
                    logging.error("Expected: "+self.automation.MD5SUM_CWS_FIRMWARE_PKG+ " Received: "+md5sum_frw_pkg)
                    return False

            if pkg_name == "script":
                self.sendCommand("md5sum "+self.automation.REMOTE_PKG_PATH+self.UPGRADE_SCRIPT+"\n")
                time.sleep(5) 
                md5sum_script_pkg = cws.recv(65535) 

                if (self.automation.MD5SUM_UPGRADE_SCRIPT in md5sum_script_pkg) :
                    logging.info(commands.getoutput('date +%D-%T-%3N')+" MD5Sum's of Upgrade Script Matching on CWS: "+str(self.CwsIpAddr))
                else: 
                    logging.error(commands.getoutput('date +%D-%T-%3N')+" MD5SUM NOT MATCHING FOR Upgrade Script " +str(md5sum_script_pkg)+ "on CWS: "+str(self.CwsIpAddr))
                    logging.error("Expected: "+self.automation.MD5SUM_UPGRADE_SCRIPT+ " Received: "+md5sum_script_pkg)
                    return False

            if pkg_name == "network":
                self.sendCommand("md5sum "+self.automation.REMOTE_PKG_PATH+self.slave_Networkfile_NAME+"\n")
                time.sleep(5) 
                md5sum_script_pkg = cws.recv(65535) 

                if (self.MD5SUM_SLAVE_CWS_NW_File in md5sum_script_pkg) :
                    logging.info(commands.getoutput('date +%D-%T-%3N')+" MD5Sum of Network File Matching on CWS: "+str(self.CwsIpAddr))
                else: 
                    logging.error(commands.getoutput('date +%D-%T-%3N')+" MD5SUM NOT MATCHING FOR Network File " +str(md5sum_script_pkg)+ "on CWS: "+str(self.CwsIpAddr))
                    logging.error("Expected: "+self.MD5SUM_SLAVE_CWS_NW_File+ " Received: "+md5sum_script_pkg)
                    return False

            if pkg_name == "uniran":
                self.sendCommand("md5sum "+self.automation.REMOTE_PKG_PATH+self.MD5SUM_SLAVE_CWS_INI_File+"\n")
                time.sleep(5) 
                md5sum_script_pkg = cws.recv(65535) 

                if (self.MD5SUM_SLAVE_CWS_INI_File in md5sum_script_pkg) :
                    logging.info(commands.getoutput('date +%D-%T-%3N')+" MD5Sum's of INI File Matching on CWS: "+str(self.CwsIpAddr))
                else: 
                    logging.error(commands.getoutput('date +%D-%T-%3N')+" MD5SUM NOT MATCHING FOR INI File " +str(md5sum_script_pkg)+ "on CWS: "+str(self.CwsIpAddr))
                    logging.error("Expected: "+self.MD5SUM_SLAVE_CWS_INI_File+ " Received: "+md5sum_script_pkg)
                    return False


            return True

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Error in validating the MD5Sum on CWS:  "+str(self.CwsIpAddr)+" Error: "+str(e))   
                return False
            else:
                self.updateCwsLog(commands.getoutput('date +%D-%T-%3N')+" MD5SUM Mismtach ON CWS: "+str(self.CwsIpAddr)+ " RETRYING"+ " Error: "+str(e))
                time.sleep(5)
                self.RETRY_COUNT += 1
                self.validateMd5Sum(self.CwsIpAddr, cws)
 
    #Function to Validate the MD5 Sum 
    def validateMd5SumOnSlave(self, pkg_name ):
        self.updateCwsLog(self.CwsIpAddr, " VALIDATING MD5SUM OF THE PACKAGE ON SLAVE CWS")
        try:  
            if pkg_name == "network":
                self.sendCommand(self.SSH_CMD_SLAVE+ " md5sum /etc/config/"+self.slave_Tgt_Nw+ "\n")
                time.sleep(5) 
                md5sum_script_pkg = self.cws_master.recv(65535) 

                if (self.MD5SUM_SLAVE_CWS_NW_File in md5sum_script_pkg) :
                    self.updateCwsLog(log_str = "MD5SUM OF NETWORK FILE MATCHING ON SLAVE")
                else: 
                    logging.error(commands.getoutput('date +%D-%T-%3N')+" MD5SUM NOT MATCHING FOR Network File On Slave " +str(md5sum_script_pkg)+ "on CWS: "+str(self.CwsIpAddr))
                    logging.error("Expected: "+self.MD5SUM_SLAVE_CWS_NW_File+ " Received: "+md5sum_script_pkg)
                    return False

            if pkg_name == "uniran":
                self.sendCommand(self.SSH_CMD_SLAVE+" md5sum /staging/etc/"+self.slave_Tgt_Ini+"\n")
                time.sleep(5) 
                md5sum_script_pkg = self.cws_master.recv(65535) 

                if (self.MD5SUM_SLAVE_CWS_INI_File in md5sum_script_pkg) :
                    self.updateCwsLog(log_str ="MD5SUM OF UNIRAN CONFIG FILE MATCHING ON SLAVE")
                else: 
                    logging.error(commands.getoutput('date +%D-%T-%3N')+" MD5SUM NOT MATCHING FOR INI File " +str(md5sum_script_pkg)+ "on Slave CWS: "+str(self.CwsIpAddr))
                    logging.error("Expected: "+self.MD5SUM_SLAVE_CWS_INI_File+ " Received: "+md5sum_script_pkg)
                    return False

            return True

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Error in validating the MD5Sum on SLAVE CWS:  "+str(self.CwsIpAddr)+" Error: "+str(e))   
                return False
            else:
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" MD5SUM Mismtach ON SLAVE CWS: "+str(self.CwsIpAddr)+ " RETRYING"+ " Error: "+str(e))
                time.sleep(5)
                self.RETRY_COUNT += 1
                self.validateMd5SumOnSlave(pkg_name)
 
    #Function to Check CWS StackMode type(T2K) & Build Version
    def checkCwsMode(self):
        self.updateCwsLog(self.CwsIpAddr, " FETCHING THE CWS STACK MODE ")
        try:
            cmd = self.SSH_CMD_MASTER + self.CwsIpAddr +" \"grep LTESTACKMODE /staging/etc/uniRanConfig.ini\" | grep \"^[^#;]\" | cut -d \"=\" -f 2"
            result = commands.getoutput(cmd)
            if "T3K" in result:
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS STACKMODE IS NOT T2K: " + str(result), level = "error")
                return False 
            elif "T2K" in result:
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS STACKMODE IS: T2K ")
            else:
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS STACKMODE IS: NOT CONFIGURED, CONSIDERING IT AS T2K")

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " Error in Fetching the LTESTACKMODE :  "+str(self.CwsIpAddr)+" Error: "+str(e), level = "error")   
                return False
            else:
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Error in Fetching the LTESTACKMODE on CWS: "+str(self.CwsIpAddr)+ " RETRYING"+ " Error: "+str(e))
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.checkCwsMode()
        return True 


    #Function to Check Software version 
    def checkSlaveCwsSwVersion(self, cws):
        self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = "  VALIDATING SLAVE CWS SW VERSION")
        try:
            cmd = self.SSH_SLAVE_LOCALIP+" cwsboot \n"
            self.sendCommand (cmd)
            time.sleep(8)
            result = cws.recv(65535)
            slave_version = re.search("  A  (.*)", result).groups(1)[0].split()[1]
                
            if slave_version == self.automation.SOFTWARE_VERSION: 
                if self.sw_force_install:
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS SLAVE VERSION: "+str(slave_version) +" UPGRADING TO: "+ str(self.automation.SOFTWARE_VERSION)+ ", AS FORCE INSTALL ENABLED")
                else:
                    if self.automation.SW_BUILD_DATE:
                        build_installed_date = re.search("  "+self.automation.SOFTWARE_VERSION+" (.*)  ", result).groups(1)[0].split()[0]
                        if self.automation.SW_BUILD_DATE in build_installed_date:
                             self.CWS_INSTALL_STATUS[2] = "SUCCESS ["+str(slave_version)+"]"
                             self.automation.updateCsvFileStatus(self.CwsIpAddr)
                             self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " SLAVE CWS ALREADY ON: "+str(slave_version) +" SW BUILD DATE MATCHED, NOT RETRYING UPGRADE")
                             return False
                        else:
                             self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " SLAVE CWS VERSION: "+str(slave_version) +" SW BUILD DATE DIDN'T MATCH, INSTALLING NEW PKG")
                    else:
                        self.CWS_INSTALL_STATUS[2] = "SUCCESS ["+str(slave_version)+"]"
                        self.automation.updateCsvFileStatus(self.CwsIpAddr)
                        self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " SLAVE CWS ALREADY ON: "+str(slave_version) +" FORCE INSTALL DISABLED, NOT RETRYING UPGRADE")
                        return False
            else:  
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS SLAVE VERSION: "+str(slave_version) +" UPGRADING TO: "+ str(self.automation.SOFTWARE_VERSION))

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " SOFTWARE VERSION ON SLAVE VALIDATION FAILED :  "+str(self.CwsIpAddr)+" Error: "+str(e), level = "error")   
                return False
            else:
                logging.error(commands.getoutput('date +%D-%T-%3N')+" SOFTWARE VERSION ON SLAVE VALIDATION FAILED on CWS: "+str(self.CwsIpAddr)+ " RETRYING"+ " Error: "+str(e))
                time.sleep(4)
                self.RETRY_COUNT += 1
                self.checkSlaveCwsSwVersion(cws)
        return True 


    #Function to Check Software version 
    def checkCwsSwVersion(self):
        NODE = "MASTER"
        if self.automation.SLAVE_ONLY_INSTALL:
            NODE = "SLAVE"
        self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = "  VALIDATING "+str(NODE)+" CWS SW VERSION ")
        try:
            #cmd = self.SSH_CMD_MASTER + self.CwsIpAddr+" \"cwsboot | grep \"  A \"\"  | awk '{print $4}'"
            cmd = self.SSH_CMD_MASTER + self.CwsIpAddr+" \"cwsboot | grep \"  A \"\" "
            result = commands.getoutput(cmd)
            logging.info("CWSBOOT output on CWS: "+self.CwsIpAddr+ str(result)) 
            master_version = re.search("  A  (.*)", result).groups(1)[0].split()[1]
            logging.info("CWS "+str(self.CwsIpAddr)+" SW Version is "+str(master_version))
 
            if self.automation.SOFTWARE_VERSION in master_version: 
                if self.sw_force_install:
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = str(NODE)+" CWS VERSION: "+str(master_version) +" UPGRADING TO: "+ str(self.automation.SOFTWARE_VERSION)+ ", AS FORCE INSTALL ENABLED")
                else:
                    if self.automation.SW_BUILD_DATE:
                        build_installed_date = re.search("  "+self.automation.SOFTWARE_VERSION+" (.*)  ", result).groups(1)[0].split()[0]
                        if self.automation.SW_BUILD_DATE in build_installed_date:
                            self.CWS_INSTALL_STATUS[1] = "SUCCESS ["+str(master_version)+"]"
                            self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = str(NODE)+" CWS ALREADY ON: "+str(master_version) +" SW BUILD DATE MATCHED, NOT RETRYING UPGRADE")
                            if self.automation.MASTER_SLAVE == "MASTER" or self.automation.SLAVE_ONLY_INSTALL:
                                self.automation.updateCsvFileStatus(self.CwsIpAddr)
                                return False
                        else:
                            self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = str(NODE)+" CWS VERSION: "+str(master_version) +" UPGRADING TO: "+ str(self.automation.SOFTWARE_VERSION)+ ", AS SW BUILD DATE DIDNT MATCH")
                    else:   
                        self.CWS_INSTALL_STATUS[1] = "SUCCESS ["+str(master_version)+"]"
                        if self.automation.MASTER_SLAVE == "MASTER" or self.automation.SLAVE_ONLY_INSTALL:
                            self.automation.updateCsvFileStatus(self.CwsIpAddr)
                            return False
 
                        self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = str(NODE)+" ALREADY ON: "+str(master_version) +" FORCE INSTALL DISABLED, NOT RETRYING UPGRADE")
                        return False  
            else:  
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = str(NODE)+" CWS VERSION: "+str(master_version) +" UPGRADING TO: "+ str(self.automation.SOFTWARE_VERSION))

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = str(NODE)+" SOFTWARE VERSION VALIDATION FAILED :  "+str(self.CwsIpAddr)+" Error: "+str(e), level = "error")   
                return False
            else:
                logging.error(commands.getoutput('date +%D-%T-%3N')+" SOFTWARE VERSION VALIDATION FAILED on CWS: "+str(self.CwsIpAddr)+ " RETRYING"+ " Error: "+str(e))
                time.sleep(4)
                self.RETRY_COUNT += 1
                self.checkCwsSwVersion()
        return True 


    #Function to Check Firmware version
    def checkCwsFwVersion(self):
        logging.info("Firmware version on CWS : "+str(self.hardware_info["Pkg_ver"]))
        if self.FIRMWARE_VERSION == self.hardware_info["Pkg_ver"]:              
            logging.info("FW MATCHED")  
            if self.fw_force_install:
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS FIRMWARE VERSION: "+str(self.hardware_info["Pkg_ver"]) +" UPGRADING TO: "+ str(self.FIRMWARE_VERSION)+ ", AS FORCE INSTALL ENABLED")
            else:
                self.CWS_INSTALL_STATUS[0] = "SUCCESS ["+str(self.hardware_info["Pkg_ver"])+"]"                   
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS FIRMWARE ALREADY ON: "+str(self.hardware_info["Pkg_ver"]) +" FORCE INSTALL DISABLED, NOT RETRYING UPGRADE")
                if not self.CWS_SOFTWARE_PKG:
                    self.automation.updateCsvFileStatus(self.CwsIpAddr)
                    time.sleep(0.2)
                    return False
        else:
            self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS FIRMWARE VERSION: "+str(self.hardware_info["Pkg_ver"]) +" UPGRADING TO: "+ str(self.FIRMWARE_VERSION))
            
        return True 

    #Function to Check Diskspace
    def checkDiskSpace(self, disksize):
        NODE = "MASTER"
        if self.automation.SLAVE_ONLY_INSTALL:
            NODE = "SLAVE"
        retry_count = 0
        self.updateCwsLog(self.CwsIpAddr, " CHECKING FOR DISK SPACE ON "+str(NODE)+" CWS")
        cmds_list = ["> /tmp/log/messages\n", "rm -rf /tmp/log/messages.*\n", "rm -rf /tmp/*.tgz\n", "df -kh | grep /tmp | awk '{print $4}'\n"]

        while (retry_count <= self.MAX_RETRIES):
            if self.runCommandsOnMaster(cmds_list):
               break
            self.updateCwsLog(self.CwsIpAddr, " UNABLE TO GET THE DISK SPACE ON "+str(NODE)+"  CWS, RETRYING")
            time.sleep(5)
            retry_count += 1
        if (retry_count > self.MAX_RETRIES):
            return False
        else:
            if self.disk_info and self.disk_info > disksize:
                self.updateCwsLog(self.CwsIpAddr, str(NODE)+" CWS HAS ENOUGH DISK SPACE "+str(self.disk_info)+" MB")
                return True
            return False


    #Function to Check the Upgrade script process on Maser CWS before starting the Upgrade
    def checkUpgradeScriptProcess(self, cws):
        logging.info(commands.getoutput('date +%D-%T-%3N')+" CHECKING Upgrade Script Process on CWS:  "+str(self.CwsIpAddr)) 
        try:
            #Check if already upgrade script running on Master CWS, if So, Abort
            cmd = "ps -aef | grep "+self.UPGRADE_SCRIPT+" | grep -v grep" 
            self.sendCommand (cmd)
            time.sleep(2)
            result = cws.recv(65535)
            if "bash.*"+self.UPGRADE_SCRIPT in result:
                self.updateCwsLog(log_str = "ALREADY UPGRADE IS RUNNING ON CWS, ABORTING THIS", cws_ip = self.CwsIpAddr, level = "error")
                return False 
        except Exception as e:
            logging.error(commands.getoutput('date +%D-%T-%3N')+" Error in Checking the Upgrade process on CWS before Start:  "+str(self.CwsIpAddr)+" Error: "+str(e)) 
            return False
        return True

    #Function to send the Command to CWS
    def sendCommand(self, command):
        #Handle the exception yet
        logging.info(commands.getoutput('date +%D-%T-%3N')+" Running Command using sendCommand "+ str(command))
        self.cws_master.send(command)

    #Function to Execute the Upgrading script 
    def executeUpgradeScript(self, cws, package = "FIRMWARE"):
        if not self.checkCwsReachability():
            self.updateCwsLog(self.CwsIpAddr, " CWS NOT REACHABLE FOR STARTING UPGRADE SCRIPT")
            return False

        self.updateCwsLog(self.CwsIpAddr, " STARTING THE INSTALLATION SCRIPT FOR "+str(package))
        try:
            #cmds_list = [ "chmod +x "+self.automation.REMOTE_PKG_PATH+self.UPGRADE_SCRIPT, "rm "+self.automation.REMOTE_PKG_PATH+"upgrade.log", "cd "+self.automation.REMOTE_PKG_PATH, self.UPGRADE_SCRIPT_CMD+" > upgrade.log &", "ls -lrt"]
            cmds_list = [ "rm "+self.automation.REMOTE_PKG_PATH+"upgrade.log", "cd "+self.automation.REMOTE_PKG_PATH, self.UPGRADE_SCRIPT_CMD+" > upgrade.log &", "ls -lrt"]
            if not self.runCommandsOnMaster(cmds_list):
                self.updateCwsLog( log_str = package+ " UPGRADE SCRIPT START FAILURE", cws_ip = self.CwsIpAddr, level = "error")
                return False
            time.sleep(1)
            if not self.checkInstallationProcessId():
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Error in Starting the Upgrade on CWS:  "+str(self.CwsIpAddr))
                return False
            self.updateCwsLog( log_str = " "+package+" UPGRADE SCRIPT START SUCCESSFUL", cws_ip = self.CwsIpAddr)
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Error in Starting "+package+" Upgrade on CWS:  "+str(self.CwsIpAddr)+" Error: "+str(e)) 
                return False
            else:
                self.RETRY_COUNT += 1
                if not self.checkUpgradeScriptProcess(cws):
                    self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+"STARTING OF "+package+" UPGRADE ON CWS "+str(self.CwsIpAddr)+" FAILED, RETRYING"+ " Error: "+str(e))
                    time.sleep(5)
                    self.executeUpgradeScript(cws, package)
                else:
                    return True     

    #def ping check 
    def cwsPingCheck(self):
        result = 0  
        self.updateCwsLog(self.CwsIpAddr, " CHECKING NETWORK CONNECTIVITY FOR CWS")
        try:
            cmd = "ping -I "+self.automation.HOST_IP_ADDR+" -c "+ self.automation.PING_PACKETS_AND_ACCEPTABLE_LOSS[0] + " "+self.CwsIpAddr
            pingresult = commands.getoutput(cmd)
            result = int(re.search(" (\d+)% packet loss, time ",  pingresult).group(1))

            if (result > int(self.automation.PING_PACKETS_AND_ACCEPTABLE_LOSS[1])):
                self.CWS_INSTALL_STATUS[0] = "PING FAILURE"
                self.updateCwsLog(log_str = " NETWORK CONNECTIVITY FAILURE FOR CWS ", cws_ip = self.CwsIpAddr)
                return False

            self.updateCwsLog(self.CwsIpAddr, " NETWORK CONNECTIVITY IS GOOD FOR CWS, PROCEEDING ")
            return True 

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error("NETWORK CONNECTIVITY FAILURE FOR CWS Err:"+ str(e)+ str(pingresult))
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str= " NETWORK CONNECTIVITY FAILURE FOR CWS ")
                self.CWS_INSTALL_STATUS[0] = "PING FAILURE"
                return False
            else:
                self.RETRY_COUNT += 1
                self.cwsPingCheck()
            

    #Function to check Master Reachability from Slave
    def checkMasterReachabilityFromSlave(self):
        cmd = self.SSH_CMD_MASTER+self.UNIRANADDR+" ping -c 4 -i 0.2 -W 1 "+ self.CWS_MASTER_IP+" >> /dev/null 2>&1 "
        response = os.system(cmd)
        if response == 0:
            time.sleep(1)
            return True   
        return False

    #Function to check Slave Reachability
    def checkSlaveReachabilityFromMaster(self):
        if not self.checkCwsReachability():
            return False
        cmd = self.SSH_CMD_MASTER+self.CwsIpAddr+" ping -c 4 -i 0.2 -W 1 "+ self.CWS_SLAVE_IP+" >> /dev/null 2>&1 "
        response = os.system(cmd)
        if response == 0:
            time.sleep(1)
            return True   
        return False

    #Function to check the CWS Reachability 
    def checkCwsReachability(self):
        cmd = "ping  -I "+self.automation.HOST_IP_ADDR+" -c 4 -i 0.2 -W 1 "+ self.CwsIpAddr+ ">> /dev/null 2>&1"
        logging.info("PING CONNECTIVITY CMD "+str(cmd))
        response = os.system(cmd)
        if response == 0:
            time.sleep(1)
            ssh_cmd = self.SSH_CMD_MASTER+self.CwsIpAddr+" exit >> /dev/null 2>&1"    
            logging.info("SSH CMD "+str(ssh_cmd))
            result = os.system(ssh_cmd)
            if result == 0:
                return True   
        return False

    #Function to Check the Installation  process on CWS
    def checkInstallationProcessId(self):
        if not self.checkCwsReachability():
            logging.info(self.getDate()+" CWS %s not reachable for process Check" %self.CwsIpAddr)
            return False

        cmd = self.SSH_CMD_MASTER + self.CwsIpAddr+" \"ps -aef | grep "+self.UPGRADE_SCRIPT+" | grep -v grep\"" 
        result = commands.getoutput(cmd)
        if "bash ./"+self.UPGRADE_SCRIPT in result:
            logging.info(self.getDate()+" Process on CWS: "+ str(result))
            return True
        else:
            return False 

    #Function to check FW Package version post install
    def firmwareCheckPostInstall(self):
        self.updateCwsLog(self.CwsIpAddr, " VALIDATING THE FW VERSION POST INSTALL,REBOOT")
        if self.FIRMWARE_VERSION == self.hardware_info["Pkg_ver"]:
            self.updateCwsLog(self.CwsIpAddr, " FIRMWARE VERSION MATCHED POST INSTALLATION "+str(self.FIRMWARE_VERSION))
            self.CWS_INSTALL_STATUS[0] = "SUCCESS ["+(str(self.FIRMWARE_VERSION))+"]"

            return True

        if (self.RETRY_COUNT == self.MAX_RETRIES):
            self.updateCwsLog(self.CwsIpAddr, " FIRMWARE VERSION MISMATCH, Expected:"+ str(self.FIRMWARE_VERSION)+", ON CWS:"+str(self.hardware_info["Pkg_ver"]), "error")
            self.CWS_INSTALL_STATUS[0] = "VER_MISMATCH "
            return False
        else:
            self.RETRY_COUNT += 1
            logging.error(self.getDate()+" FIRMWARE VERSION MISMTACH , RETRYING") 
            time.sleep(5)     
            self.firmwareCheckPostInstall()
         
   
    #Function to Run commands.getoutput 
    def executeCmdAndgetOutput(self,cmd):
        try:
            result = commands.getoutput(cmd)
            logging.info("On Cws: "+str(self.CwsIpAddr)+" Execution of Command: \n"+ str(cmd) +" Output: "+str(result))
        except:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(self.CwsIpAddr, "Unable to Execute Cmd: "+ str(cmd))
                return False
            else:
                self.RETRY_COUNT += 1
                time.sleep(2)
                self.executeCmdAndgetOutput(cmd)
                logging.error(self.CwsIpAddr, "Unable to Execute Cmd: "+ str(cmd)+" Retrying")
        return True
   
    #Function to get the logs from CWS
    def getUpgradeLogs(self, cws):
        if not self.pollCws():
            return False

        Directory_Name = self.automation.BUILD_PATH+"/CWS_LOGS/"
        date = commands.getoutput('date +%D_%T')
        date = date.replace("/", "_") 
        date = date.replace(":", "_") 
        try:
            cmd1 = self.SSH_CMD_MASTER+self.CwsIpAddr+ " [[ -f "+self.automation.REMOTE_PKG_PATH+"upgrade.log ]];"
            os.system(cmd1)
            cmd = self.SCP_CMD+"root@"+self.CwsIpAddr+":" +self.automation.REMOTE_PKG_PATH+"/upgrade.log "+ Directory_Name+"cws_upgrade.log_"+self.CwsIpAddr+"_"+date
            if not os.path.isdir(Directory_Name):
                os.mkdir(Directory_Name)      

            if not self.checkCwsReachability():
                self.updateCwsLog(self.CwsIpAddr, " CWS NOT REACHABLE FOR COPYING THE LOGS")
                return False

            if not self.executeCmdAndgetOutput(cmd):
                return False
            logging.info("SCP Of Upgrade Logs from CWS: "+str(self.CwsIpAddr)+" Successful, Copied to "+Directory_Name+"cws_upgrade.log_"+self.CwsIpAddr+"_"+date)
            
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(date+" Error in Copying Upgrade log from CWS: "+str(self.CwsIpAddr)+" Error: "+str(e)) 
                return False
            else:
                logging.error(date+" Error in Copying Upgrade log from CWS: "+str(self.CwsIpAddr)+",RETRYING Error: "+str(e)) 
                self.RETRY_COUNT += 1
                time.sleep(5)    
                self.getUpgradeLogs(cws)
        
    #Function to check SW package versions post install
    def softwareSlaveCheckPostInstall(self, cws):
        self.updateCwsLog(self.CwsIpAddr, " VALIDATING SW VERSION ON SLAVE POST INSTALL,REBOOT")
        slave_version = ""  
        try:
            cmd = self.SSH_SLAVE_LOCALIP+" cwsboot \n"
            self.sendCommand (cmd)
            time.sleep(8)
            result = cws.recv(65535)
            logging.info("SLAVE SW Output"+ str(result))
            slave_version = re.search("  A  (.*)", result).groups(1)[0].split()[1]
       
            if str(self.automation.SOFTWARE_VERSION) in slave_version:
                self.CWS_INSTALL_STATUS[2] = "SUCCESS ["+(str(slave_version))+"]"
                self.updateCwsLog(self.CwsIpAddr, " SLAVE SOFTWARE VERSION MATCHED POST INSTALLATION "+str(self.automation.SOFTWARE_VERSION))
                logging.info(self.CwsIpAddr+" IN self.softwareSlaveCheckPostInstall, returning True")
                return True
            else:   
                logging.error(self.CwsIpAddr+ " Unable to validate the version on Slave, retrying" +str(e)) 
                self.RETRY_COUNT += 1
                time.sleep(30)    
                self.softwareSlaveCheckPostInstall(cws)
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error("SLAVE SOFTWARE VERSION MISMATCH with error " +str(e)) 
                self.updateCwsLog(self.CwsIpAddr, " SLAVE SOFTWARE VERSION MISMATCH", "error")
                self.CWS_INSTALL_STATUS[2] = "VER_MISMATCH ["+(str(slave_version))+"]"
                return False
            else:
                logging.error("Unable to validate the version on Slave, retrying" +str(e)) 
                self.RETRY_COUNT += 1
                time.sleep(40)    
                self.softwareSlaveCheckPostInstall(cws)
 
    #Function to check SW package versions post install
    def softwareCheckPostInstall(self):
        NODE = "MASTER"
        if self.automation.SLAVE_ONLY_INSTALL:
            NODE = "SLAVE" 

        self.updateCwsLog(self.CwsIpAddr, " VALIDATING SW VERSION ON "+str(NODE)+" POST INSTALL,REBOOT")
        master_version = ""
        try:
            cmd = self.SSH_CMD_MASTER + self.CwsIpAddr+" cwsboot "
            result = commands.getoutput(cmd)
            master_version = re.search("  A  (.*)", result).groups(1)[0].split()[1]
            logging.info("CWSBOOT output on CWS: "+self.CwsIpAddr+ str(result)) 
            if str(self.automation.SOFTWARE_VERSION) in master_version:
                self.CWS_INSTALL_STATUS[1] = "SUCCESS ["+(str(master_version))+"]"
                self.updateCwsLog(self.CwsIpAddr, str(NODE)+" SOFTWARE VERSION MATCHED POST INSTALLATION "+str(self.automation.SOFTWARE_VERSION))
                return True  
            else:
                self.CWS_INSTALL_STATUS[1] = "VER_MISMATCH ["+(str(master_version))+"]"
                self.updateCwsLog(self.CwsIpAddr, str(NODE)+" SOFTWARE VERSION MISMATCH "+ str(master_version)+" "+str(self.automation.SOFTWARE_VERSION)) 
                return False

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                if str(self.automation.SOFTWARE_VERSION) in master_version:
                    self.updateCwsLog(self.CwsIpAddr, " MASTER SOFTWARE VERSION MISMATCH", "error")
                    self.CWS_INSTALL_STATUS[1] = "VER_MISMATCH ["+ str(master_version)+"]"

                return False
            else:
                self.RETRY_COUNT += 1
                time.sleep(10)
                self.softwareCheckPostInstall()
         
 
    #Function to Reboot Slave,Master nodes
    def rebootNodes(self):
        if not self.automation.SLAVE_ONLY_INSTALL and self.automation.MASTER_SLAVE != "MASTER":
            self.RETRY_COUNT = 0
            if not self.rebootSlaveCws():
                return False    

        if self.automation.MASTER_SLAVE != "SLAVE":
            self.RETRY_COUNT = 0
            if not self.rebootMasterCws():
                return False     

        time.sleep(10)
        if self.automation.MASTER_SLAVE != "SLAVE":
            self.RETRY_COUNT = 0
            if not self.pollCws():
                return False     

        if not self.automation.SLAVE_ONLY_INSTALL and self.automation.MASTER_SLAVE != "MASTER":
            self.RETRY_COUNT = 0
            if not self.pollSlaveCws():
                return False     

        time.sleep(10)
        return True

    #Function to Reboot Slave 
    def rebootSlaveAndPoll(self):
        self.RETRY_COUNT = 0
        if not self.rebootSlaveCws():
            return False    

        self.RETRY_COUNT = 0
        if not self.pollSlaveCws():
            return False     

        return True
     
    #Function to reboot the CWS
    def rebootCws  (self, cws_ip, cmd): 
        time.sleep(0.5)
        self.updateCwsLog(log_str = "REBOOT COMMAND  "+str(cmd))
        if not os.system(cmd):
            self.updateCwsLog(log_str = " "+str(cws_ip)+" IS REBOOTED") 
        else: 	
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                self.updateCwsLog(log_str = " UNABLE TO REBOOT CWS: "+str(cws_ip)+", MAX RETRIES DONE ", level = "error") 
                return False			
            else:	 
                self.updateCwsLog(log_str = " UNABLE TO REBOOT CWS: "+str(cws_ip)+", RETRYING ", level = "error") 
                time.sleep(20)
                self.RETRY_COUNT += 1
                self.rebootCws(cws_ip, cmd)
        time.sleep(10)   
        return True		


    #Function to reboot the Master CWS
    def rebootMasterCws(self):
        self.RETRY_COUNT = 0
        if not self.pollCws():
            return False

        cmd = self.SSH_CMD_MASTER+self.CwsIpAddr+ " reboot" 				
        time.sleep(0.5) 
        if not os.system(cmd):
            NODE = "MASTER"
            if self.automation.SLAVE_ONLY_INSTALL:
                NODE = "SLAVE"

            self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " "+str(NODE)+" CWS REBOOTED") 
        else: 	
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                self.updateCwsLog(log_str = " UNABLE TO REBOOT "+str(NODE)+" CWS, MAX RETRIES DONE ", cws_ip = self.CwsIpAddr, level = "error") 
                return False			
            else:	 
                self.updateCwsLog(log_str = " UNABLE TO REBOOT "+str(NODE)+" CWS, RETRYING ", cws_ip = self.CwsIpAddr, level = "error") 
                time.sleep(60)
                self.RETRY_COUNT += 1
                self.rebootMasterCws()
        return True		

    #Function to reboot the Slave CWS
    def rebootSlaveCws(self):
        self.RETRY_COUNT = 0
        if not self.pollSlaveCws():
            return False

        cmd = self.SSH_CMD_MASTER+self.CwsIpAddr+" \"ssh -oStrictHostKeyChecking=no -oConnectTimeout=30 root@"+ self.CWS_SLAVE_IP+" reboot >> /dev/null 2>&1\""
        time.sleep(0.5) 
        if not os.system(cmd):
            self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " SLAVE CWS REBOOTED") 
        else: 	
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                self.updateCwsLog(log_str = " UNABLE TO REBOOT SLAVE CWS, MAX RETRIES DONE ", cws_ip = self.CwsIpAddr, level = "error") 
                return False			
            else:	 
                self.updateCwsLog(log_str = " UNABLE TO REBOOT SLAVE CWS, RETRYING ", cws_ip = self.CwsIpAddr, level = "error") 
                time.sleep(60)
                self.RETRY_COUNT += 1
                self.rebootSlaveCws()
        return True		

    #Function to poll slave IP
    def pollSlaveMgmtIp(self):
        self.updateCwsLog(self.CwsIpAddr, " CHECKING SLAVE REACHABILITY "+str(self.UNIRANADDR))
        while True:
            time.sleep(20)
            if (self.RETRY_COUNT >= 30):
                self.updateCwsLog(log_str = " SLAVE CWS IS NOT UP ", cws_ip = self.UNIRANADDR, level = "error")
                break

            if self.automation.checkSlaveMgmtIPReachability(self.UNIRANADDR, self.CwsIpAddr):
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " SLAVE CWS "+ str(self.UNIRANADDR)+" IS UP ")
                break

            self.RETRY_COUNT += 1
            continue

        if (self.RETRY_COUNT >= 30):
            return False
                
        return True


    #Function to reboot the Master CWS
    def pollCws(self):
        NODE = "MASTER"
        if self.automation.SLAVE_ONLY_INSTALL:
            NODE = "SLAVE"
        self.updateCwsLog(self.CwsIpAddr, " CHECKING "+str(NODE)+" CWS REACHABILITY ")
        while True:
            if (self.RETRY_COUNT >= 30):
                self.updateCwsLog(log_str = str(NODE)+" CWS IS NOT UP ", cws_ip = self.CwsIpAddr, level = "error")
                break

            if self.checkCwsReachability():
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " "+str(NODE)+" CWS IS REACHABLE ")
                break

            time.sleep(20)
            self.RETRY_COUNT += 1
            continue

        if (self.RETRY_COUNT >= 30):
            return False
                
        if not self.loginToMainCws():
            return False

        return True

    #Function to Poll the Slave CWS
    def pollSlaveCws(self):
        self.updateCwsLog(self.CwsIpAddr, " CHECKING SLAVE REACHABILITY FROM MASTER")
        while True:
            if (self.RETRY_COUNT >= 30):
                self.updateCwsLog(log_str = " SLAVE CWS IS NOT UP ", cws_ip = self.CwsIpAddr, level = "error")
                break

            if self.checkSlaveReachabilityFromMaster():
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " SLAVE CWS IS REACHABLE ")
                break
            time.sleep(20)

            self.RETRY_COUNT += 1
            continue

        if (self.RETRY_COUNT >= 30):
            return False

        return True		

    #Function to Poll the Master CWS 169 IP From Slave 
    def pollMasterCwsFromSlave(self):
        self.updateCwsLog(log_str = " CHECKING THE MASTER IP 169.254.1.3 REACHABILITY FROM SLAVE")
        while True:
            if (self.RETRY_COUNT >= 30):
                self.updateCwsLog(log_str = " MASTER CWS IP 169.254.1.3 NOT REACHABLE", cws_ip = self.UNIRANADDR, level = "error")
                break

            if self.checkMasterReachabilityFromSlave():
                self.updateCwsLog(log_str = " MASTER CWS IP 169.254.1.3 IS REACHABLE ")
                break
            time.sleep(20)

            self.RETRY_COUNT += 1
            continue

        if (self.RETRY_COUNT >= 30):
            return False

        return True		


    #Function to check Installation status on CWS
    def checkFirmwareInstallationStatus(self): 
        self.counter = 1 
        self.SLEEP_TIMER = 1
        reboot_counter = 0

        while True:
            if (self.CWS_INSTALL_STATUS[0] != "UNKNOWN"):
                break;
			
            if self.counter >= self.automation.FW_INSTALL_POLL:
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " Max time Exceeded in CWS Firmware Installation, aborting")
                break;

            time.sleep(self.SLEEP_TIMER)
            self.counter += self.SLEEP_TIMER
            if self.checkCwsReachability():
                if not self.checkInstallationProcessId():
                    cmd1 = self.SSH_CMD_MASTER+self.CwsIpAddr+ " [[ -f "+self.automation.REMOTE_PKG_PATH+"upgrade.log ]];"
                    if os.system(cmd1) != 0:
                        if reboot_counter != 0:            
                            self.CWS_INSTALL_STATUS[0] = "CWS_REBOOTED"
                        else:     
                            self.CWS_INSTALL_STATUS[0] = "FAILURE"
                    else: 
                        self.parseUpgradeLog("FIRMWARE")
                else:    
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " FIRMWARE INSTALLATION IN PROGRESS, PLEASE STANDBY")
                    self.parseUpgradeLog("FIRMWARE")
            else:
                if (reboot_counter == 0):
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS UNREACHABLE DURING FIRMWARE INSTALL")
                else: 
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " WAITING FOR CWS TO COMEUP FOR FIRMWARE INSTALL")
                reboot_counter += 1     
                continue 

    #Function to check Installation status on CWS
    def checkSoftwareInstallationProgressOnCws(self): 
        global SCRIPT_LOGGING
        self.counter = 0 
        self.SLEEP_TIMER = 20
        reboot_counter = 0

        while True:
            logging.info("CWS %s , COUNTER is %d" %(self.CwsIpAddr, self.counter))
            if self.counter >= self.automation.SW_INSTALL_POLL:
                self.updateCwsLog(log_str = " MAX TIME EXCEEDED, ABORTING INSTALL")
                break

            if (self.CWS_STATE == "SOFTWARE_INSTALLATION_ABORTED" or self.CWS_STATE == "SOFTWARE_INSTALLATION_SUCCESS" or self.CWS_INSTALL_STATUS[1] == "FAILURE" or self.CWS_INSTALL_STATUS[2] == "FAILURE"):
                logging.info("CWS %s , BREAKING THE LOOP " %self.CwsIpAddr)
                break;

            time.sleep(self.SLEEP_TIMER)
            self.counter += self.SLEEP_TIMER
            logging.info("CWS %s Reachability Check in SW Install" %self.CwsIpAddr) 
            if self.checkCwsReachability(): 
                self.RETRY_COUNT = 0
                logging.info("CWS %s Process Id check in SW Install" %self.CwsIpAddr) 
                if not self.checkInstallationProcessId():
                    cmd1 = self.SSH_CMD_MASTER+self.CwsIpAddr+ " [[ -f "+self.automation.REMOTE_PKG_PATH+"upgrade.log ]];"
                    if os.system(cmd1) != 0:
                        if not self.checkCwsReachability(): 
                           reboot_counter += 1

                        if reboot_counter != 0:            
                            logging.info("CWS %s Rebooted during SW Install" %self.CwsIpAddr) 
                            self.CWS_INSTALL_STATUS[1] = "CWS_REBOOTED"
                            break 
                        else:
                            logging.info("CWS %s , MARKING INSTALLATION AS FAILURE as UPGRADE LOGS %s doesnt exist" %(self.CwsIpAddr, cmd1))
                            self.CWS_INSTALL_STATUS[1] = "FAILURE"
                            self.CWS_INSTALL_STATUS[2] = "FAILURE"
                    else: 
                        self.parseUpgradeLog("SOFTWARE")
                else:  
                    logging.info("CWS %s Process ID Not found in SW Install" %self.CwsIpAddr) 
                    log_str = "" 
                    if self.automation.MASTER_SLAVE:    
                        log_str = " SOFTWARE INSTALLATION ON "+self.automation.MASTER_SLAVE+" IN PROGRESS, PLEASE STANDBY "
                    elif self.CWS_INSTALL_STATUS[2] == "UNKNOWN":
                        log_str = " SOFTWARE INSTALLATION ON SLAVE IN PROGRESS, PLEASE STANDBY "
                    elif self.automation.SLAVE_ONLY_INSTALL: 
                        log_str = " SOFTWARE INSTALLATION ON SLAVE IN PROGRESS, PLEASE STANDBY "
                    elif (self.CWS_INSTALL_STATUS[2] == "SUCCESS" or self.CWS_INSTALL_STATUS[2] == "INSTALLED"):  
                        log_str = " SOFTWARE INSTALLATION ON MASTER IN PROGRESS, PLEASE STANDBY"
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = log_str)
                    self.parseUpgradeLog("SOFTWARE")
                    logging.info("CWS %s Post Parse Upgrade Log in SW Install" %self.CwsIpAddr) 
            else:
                if (reboot_counter == 0):
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " CWS UNREACHABLE DURING SOFTWARE INSTALL")
                else:
                    self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " WAITING FOR CWS TO COMEUP FOR SOFTWARE INSTALL")
                reboot_counter += 1     
                continue   

                              
    #Function to Parse the CWS Upgradelog on Master CWS
    def parseUpgradeLog(self, PKG_TYPE):
        try:
            logging.info("CWS %s In Parse upgrade log Function" %self.CwsIpAddr) 
            cmd = self.SSH_CMD_MASTER + self.CwsIpAddr+" cat "+self.automation.REMOTE_PKG_PATH+"upgrade.log "
            result = commands.getoutput(cmd)
            date = self.getDate()
            cmd= ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n"+date+"Installation Status: \n"+ result +"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
            logging.info(cmd)  
      
            if PKG_TYPE == "FIRMWARE":
                if (self.CWS_INSTALL_STATUS[0] != "INSTALLED" and self.CWS_INSTALL_STATUS[0] != "FAILURE"):
                    if "MASTER FIRWARE INSTALLATION SUCCESS" in result:
                        self.updateCwsLog(self.CwsIpAddr, " FIRMWARE INSTALLATION ON MASTER SUCCESSFUL")
                        self.CWS_INSTALL_STATUS[0] = "INSTALLED"
                    elif "ERROR: FIRMWARE install on Master FAILED" in result:
                        self.updateCwsLog(self.CwsIpAddr, " FIRMWARE INSTALLATION ON MASTER FAILED")
                        self.CWS_INSTALL_STATUS[0] = "FAILURE"
            else:
 
                if (self.CWS_INSTALL_STATUS[2] != "INSTALLED" and self.CWS_INSTALL_STATUS[2] != "FAILURE"):
                    if "SLAVE BUILD INSTALLATION SUCCESS" in result:
                        self.updateCwsLog(self.CwsIpAddr, " SOFTWARE INSTALLATION ON SLAVE SUCCESSFUL")
                        self.CWS_INSTALL_STATUS[2] = "INSTALLED"
                    elif "ERROR: SLAVE CWS INSTALL FAILED" in result:
                        self.updateCwsLog(self.CwsIpAddr, " SOFTWARE  INSTALLATION ON SLAVE FAILED")
                        self.CWS_INSTALL_STATUS[2] = "FAILURE"

                if (self.CWS_INSTALL_STATUS[1] != "INSTALLED" and self.CWS_INSTALL_STATUS[1] != "FAILURE"):
                    if ( "MASTER BUILD INSTALLATION SUCCESS" in result):
                        if self.automation.SLAVE_ONLY_INSTALL: 
                            self.updateCwsLog(self.CwsIpAddr, " SOFTWARE INSTALLATION ON SLAVE SUCCESSFUL")
                        else:
                            self.updateCwsLog(self.CwsIpAddr, " SOFTWARE INSTALLATION ON MASTER SUCCESSFUL")
                        self.CWS_INSTALL_STATUS[1] = "INSTALLED"
                    elif "ERROR: CWS BUILD INSTALL ON MASTER FAILED" in result:
                        self.updateCwsLog(self.CwsIpAddr, " SOFTWARE INSTALLATION ON MASTER FAILED")
                        self.CWS_INSTALL_STATUS[1] = "FAILURE"

            if ("INSTALLATION COMPLETED" in result):
                self.CWS_STATE = "SOFTWARE_INSTALLATION_SUCCESS"
                logging.info("CWS %s Installation succesful" %self.CwsIpAddr) 
            if ("INSTALLATION ABORTED" in result):
                self.CWS_STATE = "SOFTWARE_INSTALLATION_ABORTED"
                logging.info("CWS %s Installation Aborted" %self.CwsIpAddr) 
         
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! Wile parsing Upgrade log "+str(self.CwsIpAddr)+ "Error: "+str(e))
            else:
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" PARSING LOG FAILED ON CWS "+str(self.CwsIpAddr)+" FAILED, RETRYING"+ " Error: "+str(e))
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.parseUpgradeLog( PKG_TYPE)
   


    #Function to update Uniran.ini file
    def updateSlaveUniranFile(self):

        filename =  self.slave_Uniranfile_PATH

        self.RETRY_COUNT = 0
        uniranId       =  "sed -i 's/UNIRANID=.*/UNIRANID="+self.UNIRANID+"/g' "+ filename
        hwcalssid      =  "sed -i 's/HWCLASSID=.*/HWCLASSID="+self.HWCLASSID+"/g' "+ filename
        cloudsrvaddr   =  "sed -i 's/CLOUDSERVERADDR=.*/CLOUDSERVERADDR="+self.CLOUDSERVERADDR+"/g' "+ filename
        sec_gw_addr    =  "sed -i 's/SEC_GW_ADDR=.*/SEC_GW_ADDR="+self.SEC_GW_ADDR+"/g' "+ filename
        uniranaddr     =  "sed -i 's/UNIRANADDR=.*/UNIRANADDR="+self.UNIRANADDR+"/g' "+ filename
        bbpipaddr      =  "sed -i 's/BBPIPADDR=.*/BBPIPADDR="+self.UNIRANADDR+"/g' "+ filename
        bbpMasterIp    =  "sed -i 's/#BBPMASTERIPADDR=.*/BBPMASTERIPADDR="+self.UNIRANADDR+"/g' "+ filename
        bbpSlaveIp     =  "sed -i 's/#BBPSLAVEIPADDR=.*/BBPSLAVEIPADDR="+self.UNIRANADDR+"/g' "+ filename
        gppMgmtIf      =  "sed -i 's/GPPMGMTINTFNAME=.*/GPPMGMTINTFNAME=eth0/g' "+ filename
        gppWanIf       =  "sed -i 's/GPPWANINTFNAME=.*/GPPWANINTFNAME=eth0/g' "+ filename
        meshIf         =  "sed -i 's/GPPWIREDMESHINTF=.*/GPPWIREDMESHINTF=NONE/g' "+ filename
        ipsec          =  "sed -i 's/#IPSEC=ENABLED/IPSEC="+ self.IPSEC+"/g' "+ filename
        hammer         =  "sed -i 's/#HAMMERINTERVAL=15/HAMMERINTERVAL=15/g' "+ filename
        pulicIP        =  "sed -i 's/PUBLIC_IP=.*/PUBLIC_IP=STATIC/g' "+ filename
        wan            =  "sed -i 's/WANCFGEXTERNAL=.*/WANCFGEXTERNAL=1/g' "+ filename
        gppbbpif       =  "sed -i 's/GPPBBPINTFNAME=.*/GPPBBPINTFNAME=eth0/g' "+ filename
        dhcpSrvAdr     =  "sed -i 's/DHCP_SERVER_ADDR=.*/DHCP_SERVER_ADDR=0.0.0.0/g' "+ filename

        try:
            cmds_list = [uniranId, hwcalssid, cloudsrvaddr, sec_gw_addr, uniranaddr, bbpipaddr, bbpMasterIp, bbpSlaveIp, gppMgmtIf, gppWanIf, meshIf, ipsec, hammer, pulicIP, wan, gppbbpif, dhcpSrvAdr]
            for cmd in cmds_list:
                result = commands.getoutput(cmd)
                logging.info("Execution of Cmd "+ str(cmd)+"Result :"+ str(result)) 
            cmd = "cat "+ filename
            logging.info("File "+self.slave_Uniranfile_PATH + " Content is:\n "+commands.getoutput(cmd))
            time.sleep(1)
            cmd = "md5sum "+ self.slave_Uniranfile_PATH+" |  cut -d \" \" -f1"
            self.MD5SUM_SLAVE_CWS_INI_File = commands.getoutput(cmd)
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! Wile configuring uniRan.ini file "+str(self.CwsIpAddr)+ "Error: "+str(e))
                return False
            else:
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" UPDATING SLAVE UNIRAN.INI file FAILED ON CWS "+str(self.CwsIpAddr)+" FAILED, RETRYING"+ " Error: "+str(e))
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.updateSlaveUniranFile()

        return True

   #Function to update network file on slave
    def updateSlaveNetworkFile(self):
        try:
            network_filename =  self.slave_Networkfile_PATH
  
            result= commands.getoutput('grep "option ipaddr" '+network_filename).split("\n")[1].strip()
            newip = "option ipaddr   "+self.network_ipaddr
            ipaddr_replace = "grep -l \""+result+"\" "+network_filename+" | xargs sed -i  's/"+result+"/"+newip+"/g'"

            result= commands.getoutput('grep "option netmask" '+network_filename).split("\n")[1].strip()
            newip = "option netmask  "+self.network_netmask
            mask_replace = "grep -l \""+result+"\" "+network_filename+" | xargs sed -i  's/"+result+"/"+newip+"/g'"

            result= commands.getoutput('grep "option gateway" '+network_filename).split("\n")[0].strip()
            newip = "option gateway  "+self.network_gw
            gw_replace = "grep -l \""+result+"\" "+network_filename+" | xargs sed -i  's/"+result+"/"+newip+"/g'"

            cmds_list = [ipaddr_replace, mask_replace, gw_replace]
            for cmd in cmds_list:
                result = commands.getoutput(cmd)
                logging.info("Execution of Cmd "+ str(cmd)+"Result :"+ str(result))
            time.sleep(1)
            cmd = "cat "+ network_filename
            logging.info("File "+self.slave_Networkfile_PATH + " Content is:\n "+commands.getoutput(cmd))
            cmd = "md5sum "+ self.slave_Networkfile_PATH+" |  cut -d \" \" -f1"
            self.MD5SUM_SLAVE_CWS_NW_File = commands.getoutput(cmd)
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! Wile configuring slave network file  "+str(self.CwsIpAddr)+ "Error: "+str(e))
                return False
            else:
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" UPDATING SLAVE NETWORK file FAILED ON CWS "+str(self.CwsIpAddr)+" FAILED, RETRYING"+ " Error: "+str(e))
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.updateSlaveNetworkFile()

        return True

    #def check M_VLAN Configured on Master CWS
    def checkVlanOnMaster(self, VLAN):
        self.updateCwsLog(log_str = "Checking "+ VLAN + "on Master CWS") 
        try:  
            cmd = self.SSH_CMD_MASTER + self.CwsIpAddr +" \"grep "+VLAN+" "+self.master_UniranConfig+"\" | grep \"^[^#;]\" "
            result = commands.getoutput(cmd)
            logging.info("Output of uniran config is " + str(result))
            if "M_VLANID" in result:
                self.MVLAN_CONFIGURED = True
                self.CWS_INSTALL_STATUS[4] = "CONFIG_EXISTS"
                self.updateCwsLog(log_str = "M_VLAN Already configured on Master CWS")
            elif "S_VLANID" in result:
                self.SVLAN_CONFIGURED = True
                self.CWS_INSTALL_STATUS[2] = "CONFIG_EXISTS"
                self.updateCwsLog(log_str = "S_VLAN Already configured on Master CWS")

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" ERROR WHILE FETCHING "+ VLAN+" FROM MASTER CWS "+str(self.CwsIpAddr)+ "Error: "+str(e))
                return False
            else:
                self.updateCwsLog(log_str =commands.getoutput('date +%D-%T-%3N')+" ERROR WHILE FETCHING "+VLAN +" FROM MASTER CWS "+str(self.CwsIpAddr)+" RETRYING"+ " Error: "+str(e))
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.checkVlanOnMaster(VLAN)
        return True

    #Function to update VLAN parameters on master file
    def updateMasterVLAN(self, node):
        m_vlan         =  "M_VLANID="+self.M_VLAN
        m_vlan_cmd     =   "echo \""+m_vlan+"\"  >>" +self.master_UniranConfig
        s_vlan         =  "S_VLANID="+self.S_VLAN
        s_vlan_cmd     =   "echo \""+s_vlan+"\"  >>" +self.master_UniranConfig

        try:
            if node == "slave":
                cmds_list = [s_vlan_cmd+"\n"]
                cmd = self.SSH_CMD_MASTER + self.CwsIpAddr +" \"grep S_VLANID "+self.master_UniranConfig+"\" | grep \"^[^#;]\" "
                result = commands.getoutput(cmd)
                if s_vlan in result:
                    self.SVLAN_CONFIGURED = True
                    self.updateCwsLog(log_str = "S_VLAN Already configured on Master CWS")
                    return True
                self.updateCwsLog(log_str ="Configuring S_VLAN on Master CWS "+self.master_UniranConfig)
            else:
                cmds_list = [m_vlan_cmd+"\n"]
                cmd = self.SSH_CMD_MASTER + self.CwsIpAddr +" \"grep M_VLANID "+self.master_UniranConfig+"\" | grep \"^[^#;]\""
                result = commands.getoutput(cmd)
                if m_vlan in result:
                    self.MVLAN_CONFIGURED = True
                    self.updateCwsLog(log_str = "M_VLAN Already configured on Master CWS")
                    return True
                self.updateCwsLog(log_str = "Configuring M_VLAN on Master CWS "+self.master_UniranConfig)

            if not self.runCommandsOnMaster(cmds_list):
                return False
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! Wile configuring slave network file  "+str(self.CwsIpAddr)+ "Error: "+str(e))
                return False
            else:
                self.updateCwsLog(log_str = commands.getoutput('date +%D-%T-%3N')+" UPDATING SLAVE NETWORK file FAILED ON CWS "+str(self.CwsIpAddr)+" FAILED, RETRYING"+ " Error: "+str(e))
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.updateMasterVLAN(node)
        return True

    def updateMasterVlan(self):
        if "CONFIGURE" in self.automation.ACTION and self.install_configure == "NW_CONFIGURED":
            self.initiateMasterVlanConfig()
        else:
            self.updateCwsLog(log_str ="INVALID OPTION IN CSV/JSON")

    def install_configure_cws(self):
        if "INSTALL" in self.automation.ACTION and self.install_configure == "IDLE":
            self.initiateUpgrade()
        elif "CONFIGURE" in self.automation.ACTION and self.install_configure == "SUCCESS":
            self.initiateConfigure()
        else:
            self.updateCwsLog(log_str ="INVALID OPTION IN CSV/JSON")
   
    def generateNewFwVersion(self):
        version = self.automation.FirmwareByBand[self.hardware_info["Proj_Code"].lower()][0]
        self.FIRMWARE_VERSION = re.search("_v(.*).pkg", version).group(1).replace("_", ".")
        self.updateCwsLog(cws_ip = self.CwsIpAddr,  log_str = " NEW FIRMWARE VERSION "+str(self.FIRMWARE_VERSION))

    #Function to get Firmware version of CWS
    def fetchFwVersionFromCws(self):
        self.updateCwsLog(cws_ip = self.CwsIpAddr,  log_str = " FETCHING FIRMWARE VERSION")
        try:  
            cmds_list = ["telnet 169.254.100.1 1500", "main -v", "\x04"]
            if not self.runCommandsOnMaster(cmds_list):
                return False
            for element in self.rrhsystem_info[2:-4]:
                if " = " in element:
                    value = re.search("\t(.*) = (.*)\r", element)
                    self.hardware_info[value.group(1).strip(" ")] = value.group(2).strip(" ") 
                    if "Proj_Code" in value.group(1):
                        project_code = self.hardware_info["Proj_Code"] 
                        self.hardware_info["Proj_Code"]  = re.search("PROJ_(.*), ", project_code).group(1)

            result = " CWS FW VERSION: "+str(self.hardware_info["Pkg_ver"])+" BAND: "+str(self.automation.FirmwareByBand[self.hardware_info["Proj_Code"].lower()][1])
            self.updateCwsLog(cws_ip = self.CwsIpAddr,  log_str = result)

            cmd = self.SSH_CMD_MASTER + self.CwsIpAddr+" cwsboot "
            result = commands.getoutput(cmd)
            master_version = re.search("  A  (.*)", result).groups(1)[0].split()[1]
            logging.info("CWSBOOT output on CWS :"+self.CwsIpAddr+ str(result)) 

        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! While Getting FW Version "+str(self.CwsIpAddr)+ "Error: "+str(e))
                return False
            else:
                self.updateCwsLog(log_str = " UNABLE TO FETCH THE FW VERSION ON CWS, RETRYING"+ " Error: "+str(e), cws_ip = self.CwsIpAddr)
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.fetchFwVersionFromCws()
        return True
       
    #Function to initiate Upgrades
    def initiateUpgrade(self): 
        
        self.UPGRADE_RETRY += 1

        if (self.UPGRADE_RETRY > 1): 
            self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " UPGRADE RESTART COUNT: "+str(self.UPGRADE_RETRY))
            if (self.UPGRADE_RETRY == 5):
                self.updateCwsLog(cws_ip = self.CwsIpAddr, log_str = " ABORTING UPGRADE AS CWS REBOOTING CONTINUOUSLY")
                self.getUpgradeLogs(self.cws_master)
                return False

        self.RETRY_COUNT = 0
        if not self.pollCws():
            return False     

        self.RETRY_COUNT = 0
        #Step1: Ping check
        if not self.cwsPingCheck():
            return False 

        self.RETRY_COUNT = 0
        #Step2: Login to Master CWS
        if not self.loginToMainCws():
            if self.cws_master_ssh is not None and self.cws_master_ssh.get_transport() and self.cws_master_ssh.get_transport().is_active():
                self.cws_master_ssh.close()
            return False 

        #Step5: Check the CWS TYPE
        if self.automation.CWS_MODE_CHECK:
            self.RETRY_COUNT = 0
            if not self.checkCwsMode():
                return False 

        #Step3: Check Slave Reachability from Master
        if not self.automation.SLAVE_ONLY_INSTALL and self.automation.MASTER_SLAVE != "MASTER":
            self.RETRY_COUNT = 0
            if not self.pollSlaveCws():
                return False

            #Step4: Enabling Root Access on Slave CWS
            self.RETRY_COUNT = 0
            if not self.enableRootAccessOnSlave():
                self.updateCwsLog(self.CwsIpAddr, "  ENABLING ROOT ACCESS on SLAVE CWS FAILURE", "error")
                return False 
            self.updateCwsLog(self.CwsIpAddr, " ENABLING ROOT ACCESS on SLAVE CWS SUCCESSFUL")

        if self.CWS_FIRMWARE_PKG: 
            #Step8.a: Fetch FW Version from CWS
            if not self.fetchFwVersionFromCws():
                return False 

            #Step8.b: Generate New Version based on the product ID Fetched from Radio card
            self.generateNewFwVersion()

            #Step8.c: Check the CWS FW VERSION
            self.RETRY_COUNT = 0
            if not self.checkCwsFwVersion():
                 return False 

        #Step6: Check the CWS SW VERSION
        if self.CWS_SOFTWARE_PKG:
            self.RETRY_COUNT = 0
            if not self.checkCwsSwVersion():
                return False 
            if not self.automation.SLAVE_ONLY_INSTALL and self.automation.MASTER_SLAVE != "MASTER":
                self.RETRY_COUNT = 0
                if not self.checkSlaveCwsSwVersion(self.cws_master):
                    return False

        #Step8: Copy The Firmware Package to Master CWS & start the installation
        if self.CWS_FIRMWARE_PKG and self.automation.MASTER_SLAVE != "SLAVE": 

            #Step7: Disk space check on Master CWS
            self.RETRY_COUNT = 0
            if not self.checkDiskSpace(disksize = self.automation.DISKSPACE_CWS_FIRMWARE_PKG):
                self.updateCwsLog(self.CwsIpAddr, "  DISK SPACE CHECK ON CWS FAILURE FOR COPYING FW PKG", "error")
                return False 

            self.RETRY_COUNT = 0
            #Step8.d: Generate the UpgradeScript command
            self.CWS_SOFTWARE = "" 
            self.generateUpgradeScript()

            #Step8.e: Copy Upgrade_cws script to Master CWS
            self.RETRY_COUNT = 0
            if not self.scpBuild(self.automation.BUILD_PATH + self.UPGRADE_SCRIPT, "script"):
                self.updateCwsLog(self.CwsIpAddr, " UPGRADE SCRIPT COPY TO MASTER CWS/MD5SUM VALIDATION FAILED", "error")
                self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS CWS REBOOTED DURING BUILD COPY")
                self.CWS_INSTALL_STATUS[0] = "UNKNOWN"
                return self.initiateUpgrade()                   
 
            self.updateCwsLog(self.CwsIpAddr, " UPGRADE SCRIPT COPY TO MASTER CWS/MD5SUM VALIDATION SUCCESSFUL")

            #Step8.f: Scp the Firmware Package to Master Cws & validate Md5sum
            self.RETRY_COUNT = 0
            if not self.scpBuild(self.automation.BUILD_PATH+self.automation.FIRMWARE_PKG, "fw"):
                self.updateCwsLog(self.CwsIpAddr, " FIRMWARE PKG COPY TO MASTER CWS/MD5SUM VALIDATION FAILED", "error")
                self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS CWS REBOOTED DURING BUILD COPY")
                self.CWS_INSTALL_STATUS[0] = "UNKNOWN"
                return self.initiateUpgrade()                   

            self.updateCwsLog(self.CwsIpAddr, " FIRMWARE PKG COPY TO MASTER CWS/MD5SUM VALIDATION SUCCESSFUL")

            #Step8.g: Start the Upgrade script for Firmware installation
            self.RETRY_COUNT = 0
            if not self.executeUpgradeScript(self.cws_master):
                self.updateCwsLog(self.CwsIpAddr, "  UPGRADE SCRIPT ON MASTER CWS STARTING FAILED", "error")
                self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS FIRMWARE UPGRADE SCRIPT START FAILED")
                self.CWS_INSTALL_STATUS[0] = "UNKNOWN"
                return self.initiateUpgrade()                   

            self.updateCwsLog(self.CwsIpAddr, " FIRMWARE INSTALL STARTED ON CWS, PLEASE STANDBY")
            self.CWS_STATE = "FIRMWARE_STARTED"

            #Step8.h: Monitor the Firmware Installation Status on Master CWS
            self.checkFirmwareInstallationStatus()
            if self.CWS_INSTALL_STATUS[0] == "CWS_REBOOTED":
               #Step: Check the CWS FW VERSION
               self.RETRY_COUNT = 0
               if self.checkCwsFwVersion():
                   if self.cws_master_ssh is not None and self.cws_master_ssh.get_transport() and self.cws_master_ssh.get_transport().is_active():
                       self.cws_master_ssh.close()
                   self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS CWS REBOOTED DURING FW INSTALL")
                   self.CWS_INSTALL_STATUS[0] = "UNKNOWN"
                   self.initiateUpgrade()                   
                   return True
 
            #Step8.i: Update the CWS List with FIrmware Installation Status
            self.RETRY_COUNT = 0
            if self.CWS_INSTALL_STATUS[0] != "INSTALLED":
                self.updateCwsLog(self.CwsIpAddr, " FIRMWARE INSTALLATION FAILED")
                return False    
                 
            self.updateCwsLog(self.CwsIpAddr, " FIRMWARE INSTALLATION SUCCESSFUL")
            self.CWS_STATE = "FIRMWARE_SUCCESS"
        
            #Step8.j get the upgrade logs from CWS
            self.getUpgradeLogs(self.cws_master)

            #Step8.k: Reboot the Nodes, Slave followed by Master 
            if not self.rebootNodes():
                return False

            self.RETRY_COUNT = 0
            #Step8.l Fetch the FW Version from CWS
            if not self.fetchFwVersionFromCws():
                return False 

            #Step8.m: Firmware version check
            self.RETRY_COUNT = 0
            if not self.firmwareCheckPostInstall():
                return False

        #Step9: Copy The Software Package to Master CWS & start the installation
        if self.CWS_SOFTWARE_PKG:
            #Step9: Disk space check on Master CWS
            self.RETRY_COUNT = 0
            if not self.checkDiskSpace(disksize = self.automation.DISKSPACE_CWS_SW_PKG):
                self.updateCwsLog(self.CwsIpAddr, "  DISK SPACE CHECK ON CWS FAILURE FOR COPYING SW PKG", "error")
                return False 
 
            self.RETRY_COUNT = 0
            #Step11.d: Generate the UpgradeScript command for Software installtion
            self.CWS_SOFTWARE = self.automation.CWS_SOFTWARE
            self.CWS_FIRMWARE_PKG = "" 
            self.generateUpgradeScript()

            if not self.automation.SLAVE_ONLY_INSTALL and self.automation.MASTER_SLAVE != "MASTER":
                #Step4: Enabling Root Access on Slave CWS
                self.RETRY_COUNT = 0
                if not self.enableRootAccessOnSlave():
                    self.updateCwsLog(self.CwsIpAddr, "  ENABLING ROOT ACCESS on SLAVE CWS FAILURE", "error")
                    return False
                self.updateCwsLog(self.CwsIpAddr, " ENABLING ROOT ACCESS on SLAVE CWS SUCCESSFUL")

            
            #Step11.a: Copy Upgrade_cws script to Master CWS & Validate Md5sum
            self.RETRY_COUNT = 0
            if not self.scpBuild(self.automation.BUILD_PATH + self.UPGRADE_SCRIPT, "script"):
                self.updateCwsLog(self.CwsIpAddr, "  UPGRADE SCRIPT COPY TO "+str(self.CwsIpAddr)+" CWS/MD5SUM VALIDATION FAILED,RETRYING", "error")
                self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS CWS REBOOTED DURING SCRIPT COPY")
                self.CWS_INSTALL_STATUS[2] = "UNKNOWN"
                self.CWS_INSTALL_STATUS[1] = "UNKNOWN"
                return self.initiateUpgrade()
            self.updateCwsLog(self.CwsIpAddr, " UPGRADE SCRIPT COPY TO "+str(self.CwsIpAddr)+" CWS/MD5SUM VALIDATION SUCCESSFUL")

            #Step11.b: Copy The software Package to Master CWS & Validate Md5sum
            self.RETRY_COUNT = 0
            if not self.scpBuild(self.automation.BUILD_PATH+self.automation.CWS_SOFTWARE, "sw"):
                self.updateCwsLog(self.CwsIpAddr, "  SOFTWARE PKG COPY TO "+str(self.CwsIpAddr)+" CWS/MD5SUM VALIDATION FAILED,RETRYING ", "error")
                self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS CWS REBOOTED DURING SCRIPT COPY")
                self.CWS_INSTALL_STATUS[1] = "UNKNOWN"
                self.CWS_INSTALL_STATUS[2] = "UNKNOWN"
                return self.initiateUpgrade()
            self.updateCwsLog(self.CwsIpAddr, " SOFTWARE PKG COPY TO "+str(self.CwsIpAddr)+" CWS/MD5SUM VALIDATION SUCCESSFUL")
    
            self.RETRY_COUNT = 0
            #Step11.c: Check if CWS Upgrade is already running on Master, if so abort this
            if not self.checkUpgradeScriptProcess(self.cws_master):
                self.updateCwsLog(self.CwsIpAddr, "  UPGRADE SCRIPT ALREADY RUNNING ON "+str(self.CwsIpAddr)+" ABORTING THIS", "error")
                return False 

            #Step11.e: Run the CWS Upgrade script on CWS
            self.RETRY_COUNT = 0
            if not self.executeUpgradeScript(self.cws_master, "SOFTWARE"):
                self.updateCwsLog(self.CwsIpAddr, "  UPGRADE SCRIPT ON CWS "+str(self.CwsIpAddr)+" STARTING FAILED", "error")
                self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS SOFTWARE UPGRADE SCRIPT START FAILED")
                self.CWS_INSTALL_STATUS[0] = "UNKNOWN"
                return self.initiateUpgrade()                   

            self.CWS_STATE = "SOFTWARE_STARTED"

            #Step11.f: Check Software Installation Process
            self.RETRY_COUNT = 0
            self.checkSoftwareInstallationProgressOnCws()

            if self.CWS_INSTALL_STATUS[1] == "CWS_REBOOTED":
               #Step: Check the CWS SW VERSION
               self.RETRY_COUNT = 0
               if self.checkCwsSwVersion():
                   self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS CWS REBOOTED DURING SOFTWARE INSTALL")
                   self.CWS_FIRMWARE_PKG = "" 
                   self.CWS_INSTALL_STATUS[1] = "UNKNOWN"
                   self.CWS_INSTALL_STATUS[2] = "UNKNOWN"
                   self.initiateUpgrade()
                   return True

            if (self.CWS_STATE == "SOFTWARE_INSTALLATION_SUCCESS"):
                self.updateCwsLog(self.CwsIpAddr, " SOFTWARE INSTALLATION SUCCESSFUL")
            else:
                self.updateCwsLog(self.CwsIpAddr, " SOFTWARE INSTALLATION FAILED")
                self.RETRY_COUNT = 0
                if self.checkCwsSwVersion():
                    self.updateCwsLog(self.CwsIpAddr, " RESTARTING THE UPGRADE PROCEDURE AS INSTALLATION HAS FAILED")
                    self.CWS_FIRMWARE_PKG = "" 
                    self.CWS_INSTALL_STATUS[1] = "UNKNOWN"
                    self.CWS_INSTALL_STATUS[2] = "UNKNOWN"
                    self.initiateUpgrade()
                    return True

                return False

#            #get the upgrade logs from CWS
            self.getUpgradeLogs(self.cws_master)

            #Step11.g: Reboot the Slave followed & Master 
            if not self.rebootNodes():
                return False

            if self.automation.MASTER_SLAVE != "SLAVE":
                #Step11.h: Software Version check
                self.RETRY_COUNT = 0
                if not self.softwareCheckPostInstall():
                    return False

            if not self.automation.SLAVE_ONLY_INSTALL and self.automation.MASTER_SLAVE != "MASTER":
                #Step4: Enabling Root Access on Slave CWS
                self.RETRY_COUNT = 0
                if not self.enableRootAccessOnSlave():
                    self.updateCwsLog(self.CwsIpAddr, "  ENABLING ROOT ACCESS on SLAVE CWS FAILURE", "error")
                    return False
                self.updateCwsLog(self.CwsIpAddr, " ENABLING ROOT ACCESS on SLAVE CWS SUCCESSFUL")

                #Step11.i: Software Version check
                self.RETRY_COUNT = 0
                self.softwareSlaveCheckPostInstall(self.cws_master)

        self.updateCwsLog(self.CwsIpAddr, " COMPLETED ")
        time.sleep(6)

    #Function to copy the sample uniran/network file to sample_cwsip
    def createIniAndNwFiles(self):
        INI_Template_Path = self.automation.BUILD_PATH+"/TEMPLATES/uniRanConfig.ini.sample" 
        NW_Template_Path  = self.automation.BUILD_PATH+"/TEMPLATES/network.sample"
        date = self.getDate()
        try:
            cmds_list = [ "cp "+INI_Template_Path+" "+self.slave_Uniranfile_PATH, "cp "+NW_Template_Path+" "+self.slave_Networkfile_PATH]
            for cmd in cmds_list:
                if not self.executeCmdAndgetOutput(cmd):
                    return False

            logging.info(date+"Created the INI/Network files ") 
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(date+" Error in Creating Network/INI For Slave CWS: "+str(self.CwsIpAddr)+" Error: "+str(e))
                return False
            else:
                logging.error(date+" Error in Creating Network/INI For Slave CWS: "+str(self.CwsIpAddr)+",RETRYING Error: "+str(e))
                self.RETRY_COUNT += 1
                time.sleep(5)
                self.createIniAndNwFiles()
 
    #Function to copy the sample uniran/network file to sample_cwsip
    def getUniranFileFromSlave(self):
        date = self.getDate()
        try:
            cmds_list = ["scp -o StrictHostKeyChecking=no -oConnectTimeout=30 root@169.254.1.4:/opt/pw/etc/uniRanConfig.ini.sample "+self.slave_Uniranfile_PATH, "scp -o StrictHostKeyChecking=no -oConnectTimeout=30 root@169.254.1.4:/opt/pw/etc/config/network "+self.slave_Networkfile_PATH]
            if not self.runCommandsOnMaster(cmds_list):
                return False
            logging.info(date+"SCP of INI/Network files from Slave to MASTER SUCCESSFUL") 
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(date+" Error in Copying Network/INI From Slave to Master CWS: "+str(self.CwsIpAddr)+" Error: "+str(e))
                return False
            else:
                logging.error(date+" Error in Copying Network/INI From Slave to Master CWS: "+str(self.CwsIpAddr)+",RETRYING Error: "+str(e))
                self.RETRY_COUNT += 1
                time.sleep(5)
                self.getUniranFileFromSlave()
    

    #Function to copy the sample uniran/network file to sample_cwsip
    def getSlaveFilesFromMaster(self):
        date = self.getDate()
        try:
            cmd = self.SCP_CMD+"root@"+self.CwsIpAddr+":/root/slave_uniRanConfig.ini.sample "+self.automation.BUILD_PATH+"/"+self.slave_Uniranfile_PATH
            logging.info(date+"SCP Of Uniran file from CWS: "+str(self.CwsIpAddr)+" Successful, Copied to "+self.automation.BUILD_PATH+"/"+ self.slave_Uniranfile_PATH)
            if not self.executeCmdAndgetOutput(cmd):
                return False

            cmd = self.SCP_CMD+"root@"+self.CwsIpAddr+":/root/slave_network "+self.automation.BUILD_PATH+"/"+self.slave_Networkfile_PATH
            logging.info(date+"SCP Of Network file from CWS: "+str(self.CwsIpAddr)+" Successful, Copied to "+self.automation.BUILD_PATH+"/"+ self.slave_Networkfile_PATH)
            if not self.executeCmdAndgetOutput(cmd):
                return False

            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(date+" Error in getting Slave files (Uniran/Network) from Master CWS: "+str(self.CwsIpAddr)+" Error: "+str(e))
                return False
            else:
                logging.error(date+" Error in getting Slave files (Uniran/Network) from Master CWS:"+str(self.CwsIpAddr)+",RETRYING Error: "+str(e))
                self.RETRY_COUNT += 1
                time.sleep(5)
                self.getSlaveFilesFromMaster()

    def updateNetworkIniFilesOnSlave(self):
        if not self.backupNwIniFile():
            return False

        #Step2.a: CreateNetwork/INI Files from Templatest
        self.RETRY_COUNT = 0
        if not self.createIniAndNwFiles():
            return False 
         
        #Step2.b: Update UniRan.ini file
        self.RETRY_COUNT = 0
        if not self.updateSlaveUniranFile():
            return False 

        #Step2.c: Update Network File
        self.RETRY_COUNT = 0
        if not self.updateSlaveNetworkFile():
            return False 
        self.updateCwsLog(self.CwsIpAddr, " NETWORK FILE UPDATED WITH IP/GW/MASK")
 
        #Step3a. Copy the Network file to Master CWS
        self.RETRY_COUNT = 0
        if not self.scpBuild(self.slave_Networkfile_PATH, "network"):
            self.updateCwsLog(self.CwsIpAddr, "  NETWORK FILE COPY TO MASTER CWS/MD5SUM VALIDATION FAILED", "error")
            return False
        self.updateCwsLog(self.CwsIpAddr, " NETWORK FILE COPY TO MASTER CWS/MD5SUM VALIDATION SUCCESSFUL")
        self.CWS_INSTALL_STATUS[0] = "SUCCESS"

        #Step3a. Copy the Network file to Slave CWS From Master
        self.RETRY_COUNT = 0
        if not self.copyFileToSlave(self.slave_Networkfile_PATH, "network"):
            self.updateCwsLog(self.CwsIpAddr, "  NETWORK FILE COPY TO SLAVE CWS/MD5SUM VALIDATION FAILED ", "error")
            return False
        self.updateCwsLog(self.CwsIpAddr, " NETWORK FILE COPY TO SLAVE CWS/MD5SUM VALIDATION SUCCESSFUL ")

        #Step3b. Copy the INI file to Master CWS
        self.RETRY_COUNT = 0
        if not self.scpBuild(self.slave_Uniranfile_PATH, "uniran"):
            self.updateCwsLog(self.CwsIpAddr, "  UNIRAN CFG FILE COPY TO MASTER CWS/MD5SUM VALIDATION FAILED", "error")
            return False
        self.updateCwsLog(self.CwsIpAddr, " UNIRAN CFG FILE COPY TO MASTER CWS/MD5SUM VALIDATION SUCCESSFUL")

        #Step3b. Copy the INI file to Slave CWS From Master
        self.RETRY_COUNT = 0
        if not self.copyFileToSlave(self.slave_Uniranfile_PATH, "uniran"):
            self.updateCwsLog(self.CwsIpAddr, "  UNIRAN CFG FILE COPY TO SLAVE CWS/MD5SUM VALIDATION FAILED ", "error")
            return False
        self.updateCwsLog(self.CwsIpAddr, " UNIRAN CFG FILE COPY TO SLAVE CWS/MD5SUM VALIDATION SUCCESSFUL ")
        self.CWS_INSTALL_STATUS[1] = "SUCCESS"
        return True

    #Function to update Uniran.ini file
    def updateMvlanOnMaster(self):
        self.updateCwsLog(" UPDATING MVLAN ON MASTER CWS ")
        try:
            m_vlan         =  "M_VLANID="+self.M_VLAN
            m_vlan_cmd     =   " echo \""+m_vlan+"\"  >>" +self.master_UniranConfig
            if not self.cws_slave_ssh.get_transport().is_active():
                logging.info(commands.getoutput('date +%D-%T-%3N')+" SSH Connection to slave is down, reinitiating")
                if not self.pollSlaveMgmtIp():
                    return False

            cmd = "/tmp/"+ self.SSH_CMD_MASTER+self.CWS_MASTER_IP+" \""+m_vlan_cmd+"\""+ "\n"
            logging.info("\n\n"+commands.getoutput('date +%D-%T-%3N')+" EXECUTING COMMAND "+cmd+" on CWS "+ str(self.CwsIpAddr))
            self.cws_slave.send(cmd)
            time.sleep(5)
            output = self.cws_slave.recv(65535)
            logging.info("\n"+commands.getoutput('date +%D-%T-%3N')+" Command "+str(cmd)+" output on CWS:\n "+ str(self.CwsIpAddr)+str(output)+"\n")
            return True
        except Exception as e:
            if (self.RETRY_COUNT == self.MAX_RETRIES):
                logging.error(commands.getoutput('date +%D-%T-%3N')+" Exception! Wile configuring MVLAN ON Master "+str(self.CwsIpAddr)+ "Error: "+str(e))
                return False
            else:
                self.updateCwsLog(log_str =commands.getoutput('date +%D-%T-%3N')+" UNABLE TO CONFIGURE MVLAN ON MASTER "+str(self.CwsIpAddr)+", RETRYING"+ " Error: "+str(e))
                time.sleep(2)
                self.RETRY_COUNT += 1
                self.updateMvlanOnMaster()
        return True

    def invokeFailure(self):
        self.CWS_INSTALL_STATUS[3] += ",EXECUTION FAILED"
        return False 
 
    #Function to initiate Configure
    def initiateConfigure(self): 
        self.RETRY_COUNT = 0
        #Step1: Ping check
        if not self.cwsPingCheck():
            return self.invokeFailure()

        self.RETRY_COUNT = 0
        #Step3: Poll Slave CWS From Master
        if not self.pollCws():
            return self.invokeFailure()

        self.RETRY_COUNT = 0
        #Step2: Login to Master CWS
        if not self.loginToMainCws():
            if self.cws_master_ssh is not None and self.cws_master_ssh.get_transport() and self.cws_master_ssh.get_transport().is_active():
                self.cws_master_ssh.close()
            return self.invokeFailure()

        self.RETRY_COUNT = 0
        #Step3: Poll Slave CWS From Master
        if not self.pollSlaveCws():
            return self.invokeFailure()

        self.RETRY_COUNT = 0
        self.checkVlanOnMaster("M_VLANID")   

        self.RETRY_COUNT = 0
        self.checkVlanOnMaster("S_VLANID")   
    
        self.RETRY_COUNT = 0
        #Step4: Update uniRanConfig.ini file on CWS MASTER to include VLAN information for SLAVE only
        if not self.updateMasterVLAN("slave"):
            return self.invokeFailure()

        if "CONFIG_EXISTS" not in self.CWS_INSTALL_STATUS[2]:
            self.CWS_INSTALL_STATUS[2] = "SUCCESS"

        self.updateCwsLog(log_str = "UPDATION OF S_VLANID ON MASTER CWS IS SUCCESSFUL")

        #Step5: Configure network file on CWS SLAVE., Configure uniRanConfig.ini file on CWS SLAVE
        if not self.updateNetworkIniFilesOnSlave():
            return self.invokeFailure()
        self.updateCwsLog(self.CwsIpAddr, " COMPLETED ")

        #Step6: Reboot the Slave & Master
        self.RETRY_COUNT = 0
        if not self.rebootSlaveCws():
            return self.invokeFailure()

        self.RETRY_COUNT = 0
        if not self.rebootMasterCws():
            return self.invokeFailure()
        self.updateCwsLog(self.CwsIpAddr, " NETWORK/INI CONFIG COMPLETE ")

        
    def startMvlanConfig(self):
        if self.MVLAN_CONFIGURED: 
            self.updateCwsLog(self.CwsIpAddr, " M VLAN ALREADY CONFIGURED ON MASTER")
            self.RETRY_COUNT = 0
            if not self.pollCws():
                return self.invokeFailure()

            self.RETRY_COUNT = 0
            if not self.loginToSlaveCws():
                return self.invokeFailure()

            self.RETRY_COUNT = 0
            if not self.loginToMainCws():
                return self.invokeFailure()
            self.updateCwsLog(self.CwsIpAddr, " MASTER "+str(self.CwsIpAddr)+" & SLAVE CWS "+str(self.UNIRANADDR)+ " ARE REACHABLE")

            self.closeOpenSshSessions()

        else:
            self.RETRY_COUNT = 0
            if not self.loginToSlaveCws():
                return self.invokeFailure()

            self.RETRY_COUNT = 0
            if not self.pollMasterCwsFromSlave():
                return self.invokeFailure()

            if not self.scpBuildToSlave(self.automation.BUILD_PATH + self.sshpass):
                return self.invokeFailure()

            #Update uniRanConfig.ini file on CWS MASTER to include VLAN information for MASTER.
            self.RETRY_COUNT = 0
            if not self.updateMvlanOnMaster():
                return self.invokeFailure()
            self.MVLAN_CONFIGURED = True
            self.CWS_INSTALL_STATUS[4] = "SUCCESS"
            self.updateCwsLog(self.CwsIpAddr, " UPDATION OF M_VLANID ON MASTER CWS IS SUCCESSFUL")
  
            #Step6: Reboot the Master & Slave
            self.RETRY_COUNT = 0
            self.updateCwsLog(self.CwsIpAddr, " REBOOTING MASTER CWS FROM SLAVE")
            cmd = self.SSH_SLAVE + " \" /tmp/"+ self.SSH_CMD_MASTER+self.CWS_MASTER_IP+" reboot \""
            if not self.rebootCws(cws_ip = self.CwsIpAddr, cmd = cmd ):
                return self.invokeFailure()

            self.updateCwsLog(self.CwsIpAddr, " REBOOTING SLAVE CWS "+str(self.UNIRANADDR))
            self.RETRY_COUNT = 0
            cmd = self.SSH_SLAVE +" reboot "
            if not self.rebootCws(cws_ip = self.UNIRANADDR, cmd = cmd):
                return self.invokeFailure()

            self.RETRY_COUNT = 0
            if not self.pollCws():
                return self.invokeFailure()

            self.RETRY_COUNT = 0
            if not self.pollSlaveMgmtIp():
                return self.invokeFailure()

            self.RETRY_COUNT = 0
            if not self.loginToSlaveCws():
                return self.invokeFailure()

            self.RETRY_COUNT = 0
            if not self.loginToMainCws():
                return self.invokeFailure()

            self.updateCwsLog(self.CwsIpAddr, " MASTER "+str(self.CwsIpAddr)+" & SLAVE CWS "+str(self.UNIRANADDR)+ " ARE REACHABLE")
            self.closeOpenSshSessions()


    def closeOpenSshSessions(self):
        if self.cws_master_ssh is not None and self.cws_master_ssh.get_transport() and self.cws_master_ssh.get_transport().is_active():
            self.cws_master_ssh.close()
        if self.cws_slave_ssh is not None and self.cws_slave_ssh.get_transport() and self.cws_slave_ssh.get_transport().is_active():
            self.cws_slave_ssh.close()



class Aautomation(threading.Thread):
    def __init__ (self) :
        threading.Thread.__init__(self)
        self.UPGRADE_SCRIPT  =  "cwsUpgrade.sh"
        self.user            =  'root'
        self.passwd          =  'password'
        self.REMOTE_PKG_PATH =  "/tmp/"
        self.FirmwareByBand = {}
        self.upgradethreads = {}
        self.CwsConfigComplete = []
        self.configMvlanThread = {}

        self.MD5SUM_CWS_SW_PKG       = None
        self.MD5SUM_CWS_FIRMWARE_PKG = None
        self.MD5SUM_UPGRADE_SCRIPT   = None
        self.DISKSPACE_CWS_SW_PKG        = None
        self.DISKSPACE_CWS_FIRMWARE_PKG  = None
        self.installed_cws           = {}
        self.shutdown_flag = threading.Event()
        self.script_starttime = time.time() 
        self.SLAVE_ONLY_INSTALL = False
        self.SW_BUILD_DATE = False

    def run(self):
        while not self.shutdown_flag.is_set():
            time.sleep(0.5)


    def readConfigFiles (self):
        global cwsSession 
        #JSON Parsing
        if not os.path.exists("cws_config.json"):
            logging.error("JSON File cws_config.json doesnt exists")
            sys.exit(1)

        data = open('cws_config.json',)
        json_data = json.load(data)

        self.BUILD_PATH   = json_data["BUILD_PATH"]
        if self.BUILD_PATH.split("/")[-1] != "/":
            self.BUILD_PATH += "/"

        self.FIRMWARE_PKG = json_data["FIRMWARE"]
        self.CWS_SOFTWARE = json_data["SOFTWARE"]
        self.MASTER_SLAVE = json_data["MASTER_SLAVE"]
        self.CWS_IP_ADDR  = json_data["CWS_IP_ADDR"]
        self.HOST_IP_ADDR = json_data["HOST_IP"]
        self.RATE_LIMIT   = json_data["RATE_LIMIT"]
        self.SOFTWARE_VERSION = json_data["SOFTWARE_VER"]
        self.CWS_ROOT_PWD  = json_data["CWS_ROOT_PASSWORD"]
        self.SW_FORCE_INSTALL = json_data["SW_FORCE_INSTALL"]
        self.FW_FORCE_INSTALL = json_data["FW_FORCE_INSTALL"]
        self.SLAVE_ONLY_INSTALL = json_data["SLAVE_ONLY_INSTALL"]
        self.ACTION = json_data["ACTION"]
        self.SW_BUILD_DATE = json_data["SW_BUILD_DATE"]

        if "FILE_TRANSFER" not in json_data:
            self.FILE_TRANSFER = "rsync"
        else:
            self.FILE_TRANSFER = json_data["FILE_TRANSFER"]

        if self.RATE_LIMIT:
            self.RATE_LIMIT = "-l "+ str(self.RATE_LIMIT)

        if "FW_INSTALL_POLL" not in json_data:
            self.FW_INSTALL_POLL = 900
        else:
            self.FW_INSTALL_POLL = json_data["FW_INSTALL_POLL"]

        if "SW_INSTALL_POLL" not in json_data:
            self.SW_INSTALL_POLL = 1200
        else:
            self.SW_INSTALL_POLL = json_data["SW_INSTALL_POLL"]

        if "PING_PACKETS_AND_ACCEPTABLE_LOSS" not in json_data:
            self.PING_PACKETS_AND_ACCEPTABLE_LOSS = [20,0]
        else:
            self.PING_PACKETS_AND_ACCEPTABLE_LOSS = json_data["PING_PACKETS_AND_ACCEPTABLE_LOSS"].split(",")

        if "CWS_MODE_CHECK" not in json_data:
            self.CWS_MODE_CHECK = True
        else:
            self.CWS_MODE_CHECK = json_data["CWS_MODE_CHECK"]

        if "INDIVIDUAL_CWS_LOG" not in json_data:
            self.INDIVIDUAL_CWS_LOG = False
        else:
            self.INDIVIDUAL_CWS_LOG = json_data["INDIVIDUAL_CWS_LOG"]

        if "CWS_SLAVE_ROOT_PWD" not in json_data:
            self.CWS_SLAVE_ROOT_PWD = ""
        else:
            self.CWS_SLAVE_ROOT_PWD = json_data["CWS_SLAVE_ROOT_PWD"]

        if "REFRESH_INTERVAL" not in json_data:
            self.REFRESH_INTERVAL = 15
        else:
            self.REFRESH_INTERVAL = int(json_data["REFRESH_INTERVAL"])

        if "INSTALL_TIMEOUT" not in json_data:
            self.INSTALL_TIMEOUT = 3600
        else:
            self.INSTALL_TIMEOUT = int(json_data["INSTALL_TIMEOUT"])

        self.DEBUG_LOG_PATH = self.BUILD_PATH+ "/DEBUG_LOGS/"
        if self.INDIVIDUAL_CWS_LOG:
            if not os.path.isdir(self.DEBUG_LOG_PATH):
                os.mkdir(self.DEBUG_LOG_PATH)

        # CSV FILE
        if not os.path.exists(self.CWS_IP_ADDR):
            logging.error("CSV File "+ self.CWS_IP_ADDR +" doesnt exists")
            sys.exit(1)

        for line in open(self.CWS_IP_ADDR, 'r'):
            li=line.strip()
            if li.startswith("#") or li.startswith(" ") or line.startswith("\n"):
                continue
            word_list=[word for word in li.split(",")]
            cwsSession[word_list[0].strip("\n")] = CWS(self, word_list)

        if self.FIRMWARE_PKG:
            self.generateFirmwarePkgValues(self.FIRMWARE_PKG)
        

    #Function to generate the firmware package dict
    def generateFirmwarePkgValues(self, package ):
        productId = [ "enb22f40b05", "enb22f40b08", "enbo2740", "enbo3240", "enb22c40b03", "enbo3340", "enbo2840", "enb22c40b66", "enbo2540", "enb22c40b40", "sco2100", "enb22c40b07", "enbo3140", "enbo3040", "enbo2440", "enb22c20b42l", "enbo2220", "enbo2120", "sco2200"]
        cwsBand = ["Band5,RevC", "Band8,RevC", "Band5,RevA", "Band8,RevA", "Band3,RevA", "Band28", "Band13", "Band66", "Band12/17", "Band40", "Band1 (CWS1000)", "Band7", "Band2" , "Band20", "Band14 (CWS2000)", "Band42 TDD (CWS2000)", "Band3", "Band1", "Band3 (CWS 1000)"]

        for i in range(len(productId)): 
            self.FirmwareByBand[productId[i]] = ["", cwsBand[i]]

        destination_path = self.BUILD_PATH+"/BACKUP_LOGS/Firmware_pkg" 
        if not os.path.isdir(destination_path):
            os.makedirs(destination_path)
        else:
            #Remove the files under "/tmp/Firmware_pkg"
            filelist = [ f for f in os.listdir(destination_path) if f.endswith(".pkg") ]
            for f in filelist:
                os.remove(os.path.join(destination_path, f))

        result = tarfile.open(package)
        result.extractall(path = destination_path)
        result = tarfile.open(destination_path+"/kmw_fw.tgz")
        result.extractall(path = destination_path)
        filelist = [ f for f in os.listdir(destination_path) if f.endswith(".pkg") ]
        for f in filelist:
            product_id = f.split("_")[0]
            if product_id in self.FirmwareByBand:
                self.FirmwareByBand[product_id][0] = f
        time.sleep(0.5)
        os.system("rm -rf "+destination_path)


    #Function For doing Pre-Requisite checks
    def preRequisiteChecks(self):

        if self.CWS_SOFTWARE: 
            if not os.path.exists(self.BUILD_PATH+self.CWS_SOFTWARE):
                logging.error("SOFTWARE PACKAGE DOESNT EXIST "+ self.BUILD_PATH+self.CWS_SOFTWARE) 
                print "SOFTWARE PACKAGE DOESNT EXIST "+self.BUILD_PATH+self.CWS_SOFTWARE
                sys.exit(1)

            cmd = "md5sum "+self.BUILD_PATH+self.CWS_SOFTWARE+" |  cut -d \" \" -f1"
            self.MD5SUM_CWS_SW_PKG = commands.getoutput(cmd)
            time.sleep(1)
            self.DISKSPACE_CWS_SW_PKG = os.stat(self.BUILD_PATH+self.CWS_SOFTWARE).st_size/ (1024 * 1024)
            logging.info("SW PKG Size is "+str(self.DISKSPACE_CWS_SW_PKG))

        if self.FIRMWARE_PKG:
            if not os.path.exists(self.BUILD_PATH+self.FIRMWARE_PKG):
                logging.error("FIRMWARE PACKAGE DOESNT EXIST "+ self.BUILD_PATH+self.FIRMWARE_PKG) 
                print "FIRMWARE PACKAGE DOESNT EXIST "+ self.BUILD_PATH+self.FIRMWARE_PKG
                sys.exit(1)

            cmd = "md5sum "+self.BUILD_PATH+self.FIRMWARE_PKG+" |  cut -d \" \" -f1"
            self.MD5SUM_CWS_FIRMWARE_PKG = commands.getoutput(cmd)
            time.sleep(1)
            self.DISKSPACE_CWS_FIRMWARE_PKG = os.stat(self.BUILD_PATH+self.FIRMWARE_PKG).st_size/ (1024 * 1024)
            logging.info("FW PKG Size is "+str(self.DISKSPACE_CWS_FIRMWARE_PKG))

        if not self.CWS_SOFTWARE and not self.FIRMWARE_PKG:
            return False

        if not os.path.exists(self.UPGRADE_SCRIPT):
            logging.error("UPGRADE SCRIPT "+ self.UPGRADE_SCRIPT+" DOESN'T EXIST")
            print ("UPGRADE SCRIPT "+ self.UPGRADE_SCRIPT+" DOESN'T EXIST")
            sys.exit(1)
        cmd = "md5sum "+ self.BUILD_PATH+self.UPGRADE_SCRIPT + " |  cut -d \" \" -f1"
        self.MD5SUM_UPGRADE_SCRIPT = commands.getoutput(cmd)

        return True

    #Function to start CWS Upgrades 
    def startCwsUpgrades(self):
        global cwsSession 
        global threads_cws
        global install_all_threads

        cws_install = 0
        if "INSTALL" in self.ACTION:
            for cws_ip in cwsSession:
                cmd = "grep \""+str(cws_ip)+".*IDLE\" "+self.CWS_IP_ADDR+"  >> /dev/null 2>&1"
                idle_result = os.system(cmd)
                if not idle_result:
                    cws_install = 1
            if not cws_install:
                print ("\nNO CWS STATUS IN THE CSV FILE IS IDLE, PLEASE CHECK THE CSV "+self.CWS_IP_ADDR+"\n")
                return False

        for cws_ip in cwsSession:
            if ("INSTALL" in self.ACTION and cwsSession[cws_ip].install_configure == "IDLE") or ("CONFIGURE" in self.ACTION and cwsSession[cws_ip].install_configure == "SUCCESS"): 
                t = threading.Thread(target = cwsSession[cws_ip].install_configure_cws)
                threads_cws.append(t)
                self.upgradethreads[t._Thread__name] = cws_ip   
                time.sleep(0.5)
        if "INSTALL" in self.ACTION:
            loggerThread = threading.Thread(target = self.logResults)
        elif "CONFIGURE" in self.ACTION:
            loggerThread = threading.Thread(target = self.logConfigResults)
         
        loggerThread.start()
        for i, t in enumerate(threads_cws):
            t.start() 
        if "CONFIGURE" in self.ACTION:
            slaveConnectionThread = threading.Thread(target = self.monitorSlaveReachability)
            slaveConnectionThread.start()
            threads_cws.append(slaveConnectionThread)
            install_all_threads.append(slaveConnectionThread)

        install_all_threads.extend(threads_cws)
        install_all_threads.append(loggerThread)
        loggerThread.join()
        

    #Function to Log
    def logger(self, cws_ip = "", log_str= "" , level = False, console = True):
        global cwsSession 

        date = commands.getoutput('date +%D_%T')
        date = date.replace("/", "_")
        date = date.replace(":", "_")

        if level:
            logging.error(date+" "+cws_ip+" "+ log_str)
        else:
            logging.info(date+" "+cws_ip+" "+ log_str)
        if cws_ip in cwsSession:
            if cwsSession[cws_ip].CWS_INSTALL_STATUS[3] == "UNKNOWN":
                cwsSession[cws_ip].CWS_INSTALL_STATUS[3] = "" 
            if log_str:
                cwsSession[cws_ip].CWS_INSTALL_STATUS[3] = log_str

    #Function to log the results of Installation
    def logSummary(self,result_string ):
        global cwsSession 
        date = commands.getoutput('date +%D/%T')
        if "INSTALL" in result_string:

            if self.installed_cws: 
                print "\n\n\nTOTAL CWS SET FOR INSTALL   : %s" %len(self.upgradethreads.keys())
                print "INSTALLTION COMPLETE ON CWS : %s" %len(self.installed_cws.keys())
                print "DATE OF INSTALLATION        : %s" %date

            logger (log_str = "\t\t\t\t\t\t\t\t\t INSTALLATION SUMMARY")
            logger (log_str = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", date = "" )
            if self.FIRMWARE_PKG and self.CWS_SOFTWARE and not self.MASTER_SLAVE:
                log_str = "{:<30} {:<25} {:<30} {:<30} {:<35}".format('CWS_IP [BAND]','FW_INSTALL', 'SW_INSTALL_MASTER', 'SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS')

            elif not self.FIRMWARE_PKG:
                if self.CWS_SOFTWARE:
                    if self.SLAVE_ONLY_INSTALL:
                        log_str = "{:<28} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS')
                    elif not self.MASTER_SLAVE:
                        log_str = "{:<28} {:<30} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_MASTER', 'SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS')
                    elif self.MASTER_SLAVE == "MASTER":
                        log_str = "{:<28} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_MASTER', 'INSTALLATION_PROGRESS')
                    elif self.MASTER_SLAVE == "SLAVE":
                        log_str = "{:<28} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS')
            elif self.FIRMWARE_PKG:
                if self.CWS_SOFTWARE and self.MASTER_SLAVE == "MASTER":
                    log_str = "{:<30} {:<25} {:<30} {:<35}".format('CWS_IP [BAND]','FW_INSTALL', 'SW_INSTALL_MASTER', 'INSTALLATION_PROGRESS')
                else:
                    log_str = "{:<30} {:<25} {:<35}".format('CWS_IP [BAND]','FW_INSTALL', 'INSTALLATION_PROGRESS')


            logger (log_str = log_str)
            logger (log_str = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", date = "" )
            for ip in cwsSession:
                if ip not in self.upgradethreads.values():
                    continue
                try: 
                    band = " ["+ self.FirmwareByBand[cwsSession[ip].hardware_info["Proj_Code"].lower()][1]+ "]"
                except:
                    band = ""  

                if self.FIRMWARE_PKG and self.CWS_SOFTWARE and not self.MASTER_SLAVE:
                     log_str = "{:<29} {:<27} {:<28} {:<24} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[3])

                elif not self.FIRMWARE_PKG:
                     if self.CWS_SOFTWARE:
                         if self.SLAVE_ONLY_INSTALL:
                             log_str =  "{:<29} {:<28} {:<24}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[3])
                         elif not self.MASTER_SLAVE:
                             log_str = "{:<29} {:<28} {:<24} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[3])
                         elif self.MASTER_SLAVE == "MASTER":
                             log_str =  "{:<29} {:<28} {:<24}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[3])
                         elif self.MASTER_SLAVE == "SLAVE":
                             log_str = "{:<29} {:<28} {:<24}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[3])
                elif self.FIRMWARE_PKG:
                     if self.CWS_SOFTWARE and self.MASTER_SLAVE == "MASTER":
                         log_str = "{:<29} {:<27} {:<28} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[3])
                     else:
                         log_str = "{:<29} {:<27} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[3])
   

                logger (log_str = log_str,  date = "")
            logger (log_str = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", date = "" )
        else:
            logger (log_str = "\n\n\n\t\t\t\t\t\t\t\t\t CONFIGURATION SUMMARY")
            logger (log_str = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", date = "" )
            log_str = "{:<16} {:<25} {:<30} {:<30} {:<30} {:<35}".format('CWS_IP','NW_CONFIG_SLAVE', 'INI_CONFIG_SLAVE', 'SVLAN_CONFIG_MASTER', 'MVLAN_CONFIG_MASTER', 'CONFIG_PROGRESS')
            logger (log_str = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", date = "" )
            logger (log_str = log_str)
            for ip in cwsSession:
                duration = str(datetime.timedelta(seconds= (time.time() - cwsSession[ip].start_time))).split(".")[0]
                log_str = "{:<19} {:<27} {:<30} {:<26} {:<26} {:<4}".format(cwsSession[ip].CwsIpAddr, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[4], cwsSession[ip].CWS_INSTALL_STATUS[3])
                logger (log_str = log_str+" ["+duration + "]", date = "")
            logger (log_str = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", date = "" )
        sys.exit()


    #Function to check the CWS Thread status
    def checkCwsThreadStatus(self):
        for i, t in enumerate(threads_cws):
            if (t.is_alive() is True):
                return True
            elif ("CONFIGURE" in self.ACTION) and (t._Thread__name in self.upgradethreads) and (self.upgradethreads[t._Thread__name] not in self.CwsConfigComplete): 
                cwssess = cwsSession[self.upgradethreads[t._Thread__name]] 
                cwsip = self.upgradethreads[t._Thread__name]   
                if (cwssess.CWS_INSTALL_STATUS[0] == "SUCCESS" and cwssess.CWS_INSTALL_STATUS[1] == "SUCCESS" and ((cwssess.CWS_INSTALL_STATUS[2] == "SUCCESS") or (cwssess.CWS_INSTALL_STATUS[2] == "CONFIG_EXISTS"))) or ("EXECUTION FAILED" in cwsSession[cwsip].CWS_INSTALL_STATUS[3]):
                    self.CwsConfigComplete.append(self.upgradethreads[t._Thread__name])
                return True    
        return False 

    #Function to check the CWS Reachability
    def checkSlaveMgmtIPReachability(self, slaveip, masterip ):
        cmd = "ping -I "+self.HOST_IP_ADDR+" -c 4 -i 0.2 -W 1 "+ slaveip+ ">> /dev/null 2>&1"
        cwsSession[masterip].updateCwsLog(log_str =" CHECKING SLAVE "+str(slaveip)+" REACHABILITY")
        logging.info("Ping command is : "+str(cmd))  
        response = os.system(cmd)
        if response == 0:
            time.sleep(1)
            cmd = "ssh -b "+self.HOST_IP_ADDR+" -oStrictHostKeyChecking=no -oConnectTimeout=30 root@"+str(slaveip)+" exit >> /dev/null 2>&1"
            result = os.system(cmd)
            logging.info("Running the command %s, result %s" %(cmd, result))
            if result == 0:
                return True
        return False
    
    #Function to check the Slave Reachability &configure MVLAN on the master
    def monitorSlaveReachability(self):
        global install_all_threads
        while True:
            time.sleep(20) 
 
            #Check if the CwsConfigComplete is updated with a CWS IP for N/W & Config Complete 
            if self.CwsConfigComplete:
                for cwsip in self.CwsConfigComplete:
                    slave = cwsSession[cwsip].UNIRANADDR
                    if slave in self.configMvlanThread.values():
                        continue

                    if "EXECUTION FAILED" in cwsSession[cwsip].CWS_INSTALL_STATUS[3]:
                        self.configMvlanThread["FAILURE"] = slave
                    #Check the Slave Reachability
                    elif self.checkSlaveMgmtIPReachability(slave, cwsip):
                        t = threading.Thread(target = cwsSession[cwsip].startMvlanConfig)
                        install_all_threads.append(t)
                        self.configMvlanThread[t] = slave
                        time.sleep(1)
                        t.start() 
                        time.sleep(1)
                        t.join()
                        time.sleep(0.2)
                    elif (not cwsSession[cwsip].MVLAN_CONFIGURED) and cwsSession[cwsip].checkCwsReachability():
                        #Check if the Master CWS is Reachable & MVLAN not configured, Mark this case as Failure for SLAVE
                        self.configMvlanThread["FAILURE"] = slave
                        cwsSession[cwsip].updateCwsLog(cwsip, "SLAVE NOT REACHABLE, MORAN ACTIVATION FAILED") 
                       
                if len(self.CwsConfigComplete)  == len(self.configMvlanThread):
                    break

    def updateCsvFileStatus(self, cwsip):
        date = commands.getoutput('date +%D-%T-%3N ')

        cmd = "grep \""+str(cwsip)+".*IDLE\" "+self.CWS_IP_ADDR+"  >> /dev/null 2>&1"
        idle_result = os.system(cmd)
        if idle_result:
            return     

        cmd = "grep -n "+str(cwsip)+ " "+self.CWS_IP_ADDR
        result = commands.getoutput(cmd)
        if result:
            linenumber = result.split(":")[0]
            count = 0
            for i in range(3):
                if cwsSession[cwsip].CWS_EXPECTED_RESULT[i] not in cwsSession[cwsip].CWS_INSTALL_STATUS[i]:
                    count += 1
            if not count:
                logging.info(date+" "+cwsip+" MODIFY THE CSV FILE WITH SUCCESS ")
                cmd = "sed -i '"+linenumber+"s/IDLE/SUCCESS/' "+self.CWS_IP_ADDR
                result = os.system(cmd)
                if not result:
                    logging.info(date+" "+cwsip+" UPDATED CSV FILE WITH SUCCESS")
                    return True
                else:
                    result = os.system(cmd)

    #Function to log the results of Installation
    def logResults(self):
        global cwsSession 
        global install_status
        global threads_cws
        global SCRIPT_LOGGING
 
        while True:
            time.sleep(self.REFRESH_INTERVAL)
            _ = os.system('clear') 

            if self.upgradethreads: 
                print "\nTOTAL CWS SET FOR INSTALL    : %s" %len(self.upgradethreads.keys())
                print "INSTALLATION COMPLETE ON CWS : %s" %len(self.installed_cws.keys())

            print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                       
            if self.FIRMWARE_PKG and self.CWS_SOFTWARE and not self.MASTER_SLAVE:   
                print ("{:<30} {:<25} {:<30} {:<30} {:<35}".format('CWS_IP [BAND]','FW_INSTALL', 'SW_INSTALL_MASTER', 'SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS'))

            elif not self.FIRMWARE_PKG:
                if self.CWS_SOFTWARE:
                    if self.SLAVE_ONLY_INSTALL:
                        print ("{:<28} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS'))
                    elif not self.MASTER_SLAVE:
                        print ("{:<28} {:<30} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_MASTER', 'SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS'))
                    elif self.MASTER_SLAVE == "MASTER":
                        print ("{:<28} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_MASTER', 'INSTALLATION_PROGRESS'))
                    elif self.MASTER_SLAVE == "SLAVE":
                        print ("{:<28} {:<30} {:<35}".format('CWS_IP','SW_INSTALL_SLAVE', 'INSTALLATION_PROGRESS'))
            elif self.FIRMWARE_PKG:
                if self.CWS_SOFTWARE and self.MASTER_SLAVE == "MASTER":
                    print ("{:<30} {:<25} {:<30} {:<35}".format('CWS_IP [BAND]','FW_INSTALL', 'SW_INSTALL_MASTER', 'INSTALLATION_PROGRESS'))
                else:      
                    print ("{:<30} {:<25} {:<35}".format('CWS_IP [BAND]','FW_INSTALL', 'INSTALLATION_PROGRESS'))
               

            print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            for ip in cwsSession:
                 if ip not in self.upgradethreads.values():
                     continue
                 try: 
                     band = " ["+self.FirmwareByBand[cwsSession[ip].hardware_info["Proj_Code"].lower()][1]+"]"
                 except:
                     band = ""  

                 for i, t in enumerate(threads_cws): 
                     if t._Thread__name == self.upgradethreads.keys()[self.upgradethreads.values().index(ip)]:
                         duration = str(datetime.timedelta(seconds= (time.time() - cwsSession[ip].start_time))).split(".")[0]
                         if (t.is_alive() is False) and ("Duration" not in cwsSession[ip].CWS_INSTALL_STATUS[3]):
                             logging.info(str(ip)+"Installation state: "+cwsSession[ip].CWS_INSTALL_STATUS[3])
                             for i in range(3): 
                                 if cwsSession[ip].CWS_INSTALL_STATUS[i] == "INSTALLED":
                                     cwsSession[ip].CWS_INSTALL_STATUS[i] = "UNSUCCESSFUL/INCOMPLETE"
                                     cwsSession[ip].CWS_INSTALL_STATUS[3] = "INSTALLATION UNSUCCESSFUL"

                             cwsSession[ip].CWS_INSTALL_STATUS[3] += "  [Duration: "+ duration+"]"
                             self.installed_cws[ip] = cwsSession[ip].CWS_INSTALL_STATUS[3]
                             time.sleep(1)
                         else:
                             dur = int(str((time.time() - cwsSession[ip].start_time)).split(".")[0])
                             if (dur > self.INSTALL_TIMEOUT) and ("Duration" not in cwsSession[ip].CWS_INSTALL_STATUS[3]):
                                 cwsSession[ip].updateCwsLog(log_str = " MAX TIME EXCEEDED, ABORTING INSTALL [Duration: "+str(dur)+" sec]", cws_ip = ip)
                                 cwsSession[ip].getUpgradeLogs(cwsSession[ip].cws_master)
                                 t._Thread__stopped =True
                                 time.sleep(1)
                                 self.installed_cws[ip] = cwsSession[ip].CWS_INSTALL_STATUS[3]
                                 for i in range(3):
                                     if "SUCCESS [" not in cwsSession[ip].CWS_INSTALL_STATUS[i]:
                                         cwsSession[ip].CWS_INSTALL_STATUS[i] = "UNSUCCESSFUL/INCOMPLETE"

                 if self.FIRMWARE_PKG and self.CWS_SOFTWARE and not self.MASTER_SLAVE:   
                     print ("{:<29} {:<27} {:<30} {:<26} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[3]))
                      
                 elif not self.FIRMWARE_PKG:
                     if self.CWS_SOFTWARE:
                         if self.SLAVE_ONLY_INSTALL:
                             print ("{:<29} {:<26} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[3]))
                         elif not self.MASTER_SLAVE:
                             print ("{:<29} {:<30} {:<26} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[3]))
                         elif self.MASTER_SLAVE == "MASTER":
                             print ("{:<29} {:<26} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[3]))
                         elif self.MASTER_SLAVE == "SLAVE":
                             print ("{:<29} {:<26} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[3]))
                 elif self.FIRMWARE_PKG:
                     if self.CWS_SOFTWARE and self.MASTER_SLAVE == "MASTER":
                         print ("{:<29} {:<27} {:<30} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[3]))
                     else:
                         print ("{:<29} {:<27} {:<60}".format(cwsSession[ip].CwsIpAddr+band, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[3]))
                   
                 count = 0
                 for i in range(3):
                     if "UNSUCCESSFUL/INCOMPLETE" in cwsSession[ip].CWS_INSTALL_STATUS[i]:
                         count+= 1
                 if not count:
                     self.updateCsvFileStatus(ip)
            print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

            if not self.checkCwsThreadStatus():
                logging.info("Installation complete for all the CWS, breaking")
                self.closeSshConnections() 
                break       

    #Function to log the results of Installation
    def logConfigResults(self):
        global cwsSession 
        global install_status
        global threads_cws
 
        while True:
	    time.sleep(self.REFRESH_INTERVAL)

            _ = os.system('clear') 
            print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print ("{:<16} {:<20} {:<22} {:<22} {:<25} {:<35}".format('CWS_IP','NW_CONFIG_SLAVE', 'INI_CONFIG_SLAVE', 'SVLAN_CONFIG_MASTER', 'MVLAN_CONFIG_MASTER', 'CONFIG_PROGRESS'))
            print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            for ip in cwsSession:
                 print ("{:<19} {:<22} {:<22} {:<22} {:<20} {:<60}".format(cwsSession[ip].CwsIpAddr, cwsSession[ip].CWS_INSTALL_STATUS[0], cwsSession[ip].CWS_INSTALL_STATUS[1], cwsSession[ip].CWS_INSTALL_STATUS[2], cwsSession[ip].CWS_INSTALL_STATUS[4], cwsSession[ip].CWS_INSTALL_STATUS[3]))
            print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

            if not self.checkCwsThreadStatus():
                logging.info("Installation complete for all the CWS, breaking")
                break       


    #Function to close all active SSH Connections
    def closeSshConnections(self):
        logging.info(commands.getoutput('date +%D-%T-%3N ')+" Closing all the Active SSH Connections to Master/Slave (if any)\n") 
        for ip in cwsSession:
            if cwsSession[ip].cws_master_ssh is not None and cwsSession[ip].cws_master_ssh.get_transport() and cwsSession[ip].cws_master_ssh.get_transport().is_active():
                cwsSession[ip].cws_master_ssh.close()

            if self.INDIVIDUAL_CWS_LOG and cwsSession[ip].logger.propagate == True: 
                cwsSession[ip].logger.propagate = False

def main():
    global SCRIPT_LOGGING
   
    automation = Aautomation()
    automation.readConfigFiles()

    SCRIPT_LOGGING = automation.BUILD_PATH+"/upgrade_automation_summary.log"
    if not os.path.isdir(automation.BUILD_PATH+"/BACKUP_LOGS"):
        os.mkdir(automation.BUILD_PATH+"/BACKUP_LOGS")

    if os.path.exists(SCRIPT_LOGGING):
        date = commands.getoutput('date +%D_%T')
        date = date.replace("/", "_")
        date = date.replace(":", "_")
        os.rename(SCRIPT_LOGGING, automation.BUILD_PATH+"/BACKUP_LOGS/"+SCRIPT_LOGGING.split("/") [-1]+"_"+date)

    logging.basicConfig(filename=SCRIPT_LOGGING,level=LOGGING_LEVEL)
    system_info = commands.getoutput("uname -a")
    logging.info("System Details: %s" %system_info)
    logging.info(commands.getoutput('date +%D-%T-%3N')+'Starting Upgrade Script\n')
    
    #Function to do pre-requisite check
    if not automation.preRequisiteChecks():
        logger(automation.HOST_IP_ADDR, "  PREREQUISITE CHECK FAILED", "error")
        return False 

    cmd = "cat "+ automation.BUILD_PATH+"cws_config.json"
    result = commands.getoutput(cmd)
    logging.info("JSON CONFIGURATION: \n"+ result+"\n")

    cmd = "cat "+automation.CWS_IP_ADDR
    result = commands.getoutput(cmd)
    logging.info("CSV CONFIGURATION: \n"+ result+ "\n")

    #Function to Start CWS Upgrades
    automation.startCwsUpgrades()
       
    if "CONFIGURE" in automation.ACTION: 
        automation.logSummary("CONFIGURE")
    else:  
        automation.logSummary("INSTALL")

   
if __name__=="__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()
