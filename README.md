
### Worm: replicatorworm.py  ||  extorterworm.py  ||  passwordthiefworm.py



#### Names and email addresses of all team members.:

- 1) Neenu Ann Varghese (CWID- )
- 2) Anusha (CWID- )
- 3) Ashish Merani (CWID- )

## Python Worms:-
## Pre-req for pythom Worms to work.
All the required dependencies need to be installed inorder to sucessfully run the worm.
1. Download the script
2. Go to the downloaded directory via cmd
3. chmod a+x install.sh
4. ./install.sh

### The Replicator Worm 
####Prerequisites: 
1. All the dependencies needs to be installed.
2. Copy this worm to the /tmp folder

####Functionalities:
1. When executed, the worm scans its local area network for presence of other systems running SSH service.
2. The worm carries a dictionary of possible user names and passwords. 
3. The worm attempts to login into discovered host systems using SSH user names and passwords in its dictionary until it successfully logs into one of the hosts or until it has tried all user names and passwords against all hosts without success. If the worm is unable to guess the credentials for any of the discovered systems, it terminates. Otherwise, the worm checks if the remote system has already been infected. If so, then it skips this system and moves on to attacking other systems. If not so, the worm copies itself onto the compromised system, executes itself on the newly compromised system, and terminates on the current system.
4. Once executed on the remote system, the worm checks if the system is is already infected and if so, terminates. Otherwise, the worm attempts to spread to other systems using the above-stated process. This check prevents two copies of the same worm from executing on the same system at the same time.
5. The worm does not launch attacks from the same system more than once.

####Command for running the worm: 
A. Python: python replicator_worm.py 
B. C++ : 1. g++ replicator_worm -lssh -o replicatorW
         2. ./replicatorW

####Output:
1. All the systems in the network with port 22 open, will be infected. They will have infectionMarker_repW_python.txt and/or infectionMarker_repW_CPP.txt in the /tmp folder. This shows that the worm has executed on the system. 
2. After the worm has finished execution, the worm is deleted from the system. SO that users will not be able to decode the logic behind the worm

###The Extorter Worm
####Prerequisites: 
1. All the dependencies needs to be installed.
2. Copy this worm to the /tmp folder
3. /home/ubuntu/Documents folder needs to be present

####Functionalities
1. This worm encompasses all features and conform to all requirements of the replicator worm, except the above requirement.
2. This worm downloads the encryption program from the http://ecs.fullerton.edu/mgofman/openssl URL.
3. After downloading the openssl program the worm creates a tar archive of the /home/cpsc/Documents directory and encrypt it using the openssl program. After the Documents directory has been encrypted, the worm deletes the /home/cpsc/Documents directory and leaves a note (SystemCompromised.txt)telling the user that his files have been encrypted and that he/she needs to purchase the decryption key from the attacker in order to get the files back.
4. All fles is encrypted using password cs456worm (which openssl program accepts as one of the arguments; please see the next section for details).
6. This worm leaves the files on the attacker's system unharmed.

####Command for running the worm: 
A. Python: python extorter_worm.py 
B. C++ : 1. g++ extorter_worm -lssh -o extorterW
         2. ./extorterW
 
####Output:
1. All the systems in the network with port 22 open, will be infected. They will have infectionMarker_extW_python.txt and/or infectionMarker_extW_CPP.txt in the /tmp folder. This shows that the worm has executed on the system. 
2. After the worm has finished execution, the worm is deleted from the system. The worm also deletes the downloaded openssl program, and the tared directory.
3. SystemCompromised.txt and DocumentsDir.tar.enc is left in the /home/ubuntu folder.
 
###The Password File Thief Worm 
####Prerequisites: 
1. All the dependencies needs to be installed.
2. Copy this worm to the /tmp folder

####Functionalities:
1. This worm encompasses all features and conform to all requirements of the replicator worm, except the requirement above.
2. When the is executed on a victim system, it shall copy the /etc/passwd file, the file containing information about system user names and passwords, back to the attacker's system (that is, the system from which the attack was originally initiated).
3. When the /etc/passwd file is copied to the attacker's system it shall be named as passwd <IP of the victim system>. For example, passwd 192.168.1.101.
4. This worm does not touch the password file on the attacker's system (that is, the system from which the attack was originally initiated).

####Command for running the worm: 
A. Python: python passwordthief_worm.py 
B. C++ : 1. g++ passwordthief_worm -lssh -o passwordW
      2. ./passwordW
      
####Output:
1. All the systems in the network with port 22 open, will be infected. They will have infectionMarker_passW_python.txt and/or infectionMarker_passW_CPP.txt in the /tmp folder. This shows that the worm has executed on the system. 
2. After the worm has finished execution, the worm is deleted from the system. The worm also deletes the downloaded openssl program, and the tared directory.
3. All the copied files will be present in the /tmp directory of the attacker machine.


