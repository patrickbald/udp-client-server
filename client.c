
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "pg1lib.h"

void usage(int status){
    printf("Usage: host-name port-number text/file");
    exit(status);
}

int main(int argc, char *argv[]){

    /* server structure */
    struct  hostent *hp;
    struct  sockaddr_in sin;
    int     sock;

    if(argc == 1) {
        usage(1);
    }

    /* Parse arguments */
    char *host_name;
    host_name           = argv[1]; 
    int port_number     = atoi(argv[2]);

    /* Translate host name into peers ip address */
    hp = gethostbyname(host_name);
    if(!hp){
        fprintf(stderr, "unknown host: %s\n", host_name);
        exit(1);
    }

    /* Build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
    sin.sin_port = htons(port_number);

    /* Create Socket */
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if( sock < 0 ){
        perror("unable to create socket\n");
        exit(1);
    }

    // Get clients public key
    char* client_pub_key = getPubKey();

    // Connect and send public key to server
    int pubKeyLen           = strlen(client_pub_key); 
    socklen_t server_len    = sizeof(struct sockaddr_in);
    if(sendto(sock, client_pub_key, pubKeyLen, 0, (struct sockaddr *)&sin, server_len) < 0) {
        perror("Error sending public key to server.\n");
        exit(1);
    }

    /* receive server public key back */
    char server_key[4096];
    if(recvfrom(sock, server_key, 4096, 0, (struct sockaddr *)&sin, &server_len) < 0){
        perror("Error receiving public key back from server\n");
        exit(1);
    }

    /* decrypt server public key */
    char *server_public_key;
    server_public_key = decrypt(server_key);

    /* Read msg to send to server */
    char* msg;
    char file_input[BUFSIZ];
    FILE *fp;
    struct stat path_stat;
    stat(argv[3], &path_stat);

    if(S_ISREG(path_stat.st_mode)){
        fp = fopen(argv[3], "r");
        if(fp != NULL){
            if(fread(file_input, 1, BUFSIZ, fp) < 0){
                printf("read failure\n");
                exit(1);
            }
            msg = file_input;
        }
    } else {
        msg = argv[3];
    }
    
    /* Encrypt message */ 
    char* encrypted_msg = encrypt(msg, server_public_key);

    /* send encrypted message and checksum to server */
    int encrypted_len = strlen(encrypted_msg);
    if(sendto(sock, encrypted_msg, encrypted_len, 0, (struct sockaddr*)&sin, server_len) < 0){
        perror("Error sending encrypted message to server.\n");
        exit(1);
    }

    /* get send time stamp */
    struct timeval send_time;
    double sendtime;
    if(gettimeofday(&send_time, NULL) == 0){
        sendtime = (double)send_time.tv_sec + (double)send_time.tv_usec;
    }

    unsigned long client_checksum       = checksum(msg);
    unsigned long int endian_checksum   = htonl(client_checksum);
    if(sendto(sock, &endian_checksum, sizeof(client_checksum), 0, (struct sockaddr*)&sin, server_len) < 0){
        perror("Error sending checksum to server.\n");
        exit(1);
    }
    printf("Checksum Sent: %lu\n", endian_checksum);

    /* receives response message from server */
    char timestamp[BUFSIZ];
    if(recvfrom(sock, timestamp, sizeof(timestamp), 0, (struct sockaddr*)&sin, &server_len) < 0){
        perror("Error recieving timestamp from server.\n");
        exit(1);
    }
    printf("Server has successfully recieved the message at: %s", timestamp);

    /* get send time stamp */
    struct timeval recv_time;
    double recvtime;
    if(gettimeofday(&recv_time, NULL) == 0){
        recvtime = (double)recv_time.tv_sec + (double)recv_time.tv_usec;
    }

    double rtt = recvtime - sendtime;
    printf("RTT: %.0fus\n", rtt);

}


/* vim: set sts=4 sw=4 ts=4 expandtab ft=c: */
