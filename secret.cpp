#include <stdio.h>
#include <iostream>
#include <getopt.h>
#include <string>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>
#include <net/ethernet.h>

#define MAX_DATA_LEN 1000

AES_KEY key_e;
AES_KEY key_d;

class ArgumentParser {
    public:
        const char* file = NULL;
        const char* ip = NULL;
        bool server = false;

    int argumentParser(int argc, char *argv[]){
        const char* const opts = "r:s:l";
        int opt = 0;
        opterr = 0;
        while ((opt = getopt(argc, argv, opts)) != EOF) {
            switch(opt) {
                case 'r':
                    file = optarg;
                    break;
                case 's':
                    ip = optarg;
                    break;
                case 'l':
                    server = true;
                    break;
                case '?':
                default:
                    std::cerr << "Invalid arguments\n";
                    return 1;
            }
        }

        if ((file == NULL || ip == NULL) && !server) {
            std::cerr << "Missing some arguments\n";
            return 1;
        }

        if (access(file, F_OK) ){
            std::cerr << "Invalid file\n";
            return 1;
        }

        return 0;
    }
};


char *encrypt(char *cyphertext){
    int cyphertextlen = strlen(cyphertext);
    unsigned char *output = (unsigned char *)calloc(cyphertextlen + (AES_BLOCK_SIZE % cyphertextlen), 1);
    AES_encrypt((unsigned char*)cyphertext, output, &key_e);
    return (char *)output;
}


char *decrypt(char *cyphertext){
    int cyphertextlen = strlen(cyphertext);
    unsigned char *output = (unsigned char *)calloc(cyphertextlen + (AES_BLOCK_SIZE % cyphertextlen), 1);
    AES_decrypt((unsigned char*)cyphertext, output, &key_d);

    return (char *)output;
}


int run_client(ArgumentParser args){
    struct addrinfo hints, *serverinfo;
	memset(&hints, 0, sizeof(hints));
	int result;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;

	if ((result = getaddrinfo(args.ip, NULL, &hints, &serverinfo)) != 0){
		fprintf(stderr, "IP error: %s\n", gai_strerror(result));
		return 1;
	}
    
    int protocol = serverinfo->ai_family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    int sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
	if (sock == -1){
        while(serverinfo->ai_next != NULL && sock == -1){
            protocol = serverinfo->ai_family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
            sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
            serverinfo = serverinfo->ai_next;
        }
        if (sock == -1){
            fprintf(stderr, "Socket error. Make sure you run this program as sudo\n");
            return 1;
        }
	}

	char packet[1500];
	memset(&packet, 0, 1500);

	struct icmphdr *icmp_header = (struct icmphdr *)packet;
	icmp_header->code = ICMP_ECHO;
	icmp_header->checksum = 0;

    std::ifstream file;
    file.open(args.file);
    char test[MAX_DATA_LEN];
    char *result_cypher;
    while (!file.eof()) {
        file.read(test, MAX_DATA_LEN);
        result_cypher = encrypt(test);
	    memcpy(packet + sizeof(struct icmphdr), result_cypher, strlen(result_cypher));
        //struct ether_header *p = (struct ether_header *)packet;
        
    	if (sendto(sock, packet, sizeof(struct icmphdr) + strlen(result_cypher), 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) == -1){
    		fprintf(stderr, "sendto err :)\n");
    		return 1;
    	}
    }
    return 0;
}

int run_server(){
    return 1;
}

int main(int argc, char *argv[]) {
    ArgumentParser args;
    if (args.argumentParser(argc, argv)) {
        return 1;
    }

    AES_set_encrypt_key((const unsigned char *)"xnorek01", 128, &key_e);
    AES_set_decrypt_key((const unsigned char *)"xnorek01", 128, &key_d);

    if (!args.server) {
        if (run_client(args) != 0) {
            return 1;
        }
    }else {
        if (run_server() != 0) {
            return 1;
        }
    }

    return 0;
}