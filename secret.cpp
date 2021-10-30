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
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h> 

#define MAX_DATA_LEN 1024
#define SIZE_ETHERNET 16
#define START 1
#define TRANSFER 2
#define END 3
#define COMPLEMENT(x) (AES_BLOCK_SIZE - (x % AES_BLOCK_SIZE)) 
const char *ID = "Secretga";

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

        if (access(file, F_OK) && !server){
            std::cerr << "Invalid file\n";
            return 1;
        }

        return 0;
    }
};


struct secrethdr{
    char id[AES_BLOCK_SIZE];
    int type;
    char *file;
    int length = 0;
    int total_length = 0; 
    char data[MAX_DATA_LEN];
};

char *encrypt(char *cyphertext, int length){
    unsigned char *output = (unsigned char *)calloc(length + COMPLEMENT(length), sizeof(char));
    for (int shift = 0; shift < length; shift += AES_BLOCK_SIZE) {
        AES_encrypt((unsigned char*)(cyphertext + shift), (output + shift), &key_e);
    }
    return (char *)output;
}

char *decrypt(char *cyphertext, int length){
    unsigned char *output = (unsigned char *)calloc(length + COMPLEMENT(length), sizeof(char));
    for (int shift = 0; shift < length; shift += AES_BLOCK_SIZE) {
        AES_decrypt((unsigned char*)(cyphertext + shift), (output + shift), &key_d);
    }
    return (char *)output;
}

int client(ArgumentParser args){
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
    struct secrethdr *secret = (struct secrethdr *)(packet + sizeof(struct icmphdr));
	icmp_header->code = ICMP_ECHO;
	icmp_header->checksum = 0;


    std::ifstream file;
    file.open(args.file);
    if (!file.is_open()) {
    	fprintf(stderr, "Couldnt open file\n");
        return 1;
    }

    char buff[MAX_DATA_LEN];
    char *id =  encrypt((char *)ID ,8);
    memcpy(secret->id, id, 16);
    memset(&buff, 0, MAX_DATA_LEN);
    secret->type = START;
    //secret->file = (char *)calloc(strlen(args.file), sizeof(char));
    //strcpy(secret->file, args.file);

    
    if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secrethdr) - (MAX_DATA_LEN - secret->length) + COMPLEMENT(secret->length), 
                0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) == -1){
        fprintf(stderr, "sendto bad\n");
        return 1;
    }
    
    
    char *result_cypher;
    int total_length = 0;
    while (!file.eof()) {
        file.read(buff, MAX_DATA_LEN);
        secret->length = file.gcount();
        secret->type = TRANSFER;
        total_length += secret->length;
        result_cypher = encrypt(buff, secret->length);
        memcpy(secret->data, result_cypher, secret->length + COMPLEMENT(secret->length));
        
    	if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secrethdr) - (MAX_DATA_LEN - secret->length) + COMPLEMENT(secret->length), 
                    0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) == -1){
    		fprintf(stderr, "sendto bad\n");
    		return 1;
    	}
        free(result_cypher);
    }

    free(id);
    free(serverinfo);
    file.close();
    return 0;
}

void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct secrethdr *secret = (struct secrethdr *)(packet + sizeof(struct icmphdr) + SIZE_ETHERNET + sizeof(iphdr));
    char *id = decrypt(secret->id, AES_BLOCK_SIZE);

    if (strcmp(id, ID)){
        return;
    }

    if (secret->type == START) {

    }

    if (secret->type == TRANSFER) {
        char *decoded = decrypt(secret->data, secret->length);
        printf("%s\n", decoded);
    }

}

int server(){
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *filter = "icmp or icmp6";
    struct bpf_program fp;
    pcap_t* handle; 
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet("any", &net, &mask, errbuf) == -1) {
        std::cerr << errbuf << std::endl;
        net = 0;
        mask = 0;
    }

    if ((handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf)) == nullptr){
        std::cerr << errbuf << std::endl;
        return 1;
    }
    
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    if (pcap_loop(handle, 0, gotPacket, nullptr) == PCAP_ERROR){
        return 1;
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

int main(int argc, char *argv[]) {
    ArgumentParser args;
    if (args.argumentParser(argc, argv)) {
        return 1;
    }

    AES_set_encrypt_key((const unsigned char *)"xnorek01", 128, &key_e);
    AES_set_decrypt_key((const unsigned char *)"xnorek01", 128, &key_d);

    if (!args.server) {
        if (client(args) != 0) {
            return 1;
        }
    }else {
        if (server() != 0) {
            return 1;
        }
    }

    return 0;
}