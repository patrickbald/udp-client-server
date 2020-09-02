#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

#include "pg1lib.h"

#define MAX_LINE 256
#define MAX_PENDING 5

int main(int argc, char *argv[]){

	if (argc == 1){
		exit(1);
	}

	/* Define address struct sin, client_addr */
	struct sockaddr_in sin, client_addr;
	int server_port = atoi(argv[1]);

	/* build server address data structure */
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY; // use the default IP address of server
	sin.sin_port = htons(server_port);

	/* set up passive open for socket on server side*/
	int sock;
	if((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("Error opening socket in server.\n");
		exit(1);
	}

	/* Bind the created socket to the specified address */
	if((bind(sock, (struct sockaddr*)&sin, sizeof(sin))) < 0 ){
		perror("Error binding in server.\n");
		exit(1);
	}

	// Generate server public key
	char* server_key = getPubKey();

	while(1){

		printf("Waiting ...\n");

		// wait to receive clients public key
		char client_pub_key[BUFSIZ];
		socklen_t client_addr_len = sizeof client_addr;
		if(recvfrom(sock, client_pub_key, sizeof(client_pub_key), 0, (struct sockaddr*)&client_addr, &client_addr_len) < 0){
			perror("Error receiving clients key\n");
			break;
		}

		/* encrypt server key */
		char* encrypted_server_key;
		encrypted_server_key = encrypt(server_key, client_pub_key);

		/* send encrypted key back to client */
		int eskey_len = strlen(encrypted_server_key);
		if(sendto(sock, encrypted_server_key, eskey_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0 ){
			perror("Error sending encrypted key to client.\n");
			break;
		}

		/* receive encrypted message from client */
		char msg[BUFSIZ];
		if(recvfrom(sock, msg, sizeof(msg), 0, (struct sockaddr*)&client_addr, &client_addr_len) < 0) {
			perror("Unable to recieve message from client.\n");
			break;
		}

		/* receive checksum from client */
		unsigned long int client_checksum;
		if(recvfrom(sock, &client_checksum, sizeof(client_checksum), 0, (struct sockaddr*)&client_addr, &client_addr_len) < 0){
			perror("Error receiving checksum from client.\n");
			break;
		}

		printf("******* New Message *******\n");

		// get timestamp
		time_t receive_time 	= time(NULL);
		char* timestamp;
		timestamp 				= ctime(&receive_time);
		printf("Received Time: %s", timestamp);

		// decrypt message
		char* decrypt_msg;
		decrypt_msg = decrypt(msg);

		//print date, time, message, and recieved checksum
		printf("Received Message: %s\n", decrypt_msg);	// message
		printf("Received Client Checksum: %lu\n", client_checksum); // checksum

		// calculate checksum from decrypted message
		unsigned long decrypt_checksum;
		decrypt_checksum = checksum(decrypt_msg);
		unsigned long int endian_checksum = ntohl(decrypt_checksum);
		printf("Calculated Checksum: %lu\n", endian_checksum);

		if(endian_checksum == client_checksum){
			if(sendto(sock, timestamp, strlen(timestamp), 0, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0){
				perror("Error sending timestamp to client.\n");
			}
		}

		printf("\n");	
	}
}
