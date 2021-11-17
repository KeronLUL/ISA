/**
 * ISA project - Send and receive file through hidden channel
 * @author Karel Norek, xnorek01
 */
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>
#include <poll.h>
#include <getopt.h>
#include <openssl/aes.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h> 

#define PACKET_SIZE 1500    // Size of a packet
#define MAX_DATA_LEN 1024   // Maximum length of data in packet
#define SIZE_SLL 16         // Size of Linux cooked capture header
#define START 1
#define TRANSFER 2
#define END 3
#define COMPLEMENT(x) (AES_BLOCK_SIZE - (x % AES_BLOCK_SIZE))   // Complement of X to be divisible by AES_BLOCK_SIZE

using namespace std;

const char *ID = "Secretga";

ofstream server_file;
int total_file_length = 0;
vector<char> buffer;

AES_KEY key_e;
AES_KEY key_d;

/**
 *  Class for parsing program arguments
 */
class ArgumentParser {
    public:
        const char* file = nullptr;
        const char* ip = nullptr;
        bool server = false;

    /**
     *  Parse arguments
     * 
     *  @param  argc - Number of arguments
     *  @param  argv - Arguments
     * 
     *  @return Returns 0 if everything is ok, else returns 1
     */
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
                    cerr << "Invalid arguments\n";
                    return 1;
            }
        }

        if ((file == nullptr || ip == nullptr) && !server) {
            cerr << "Missing some arguments\n";
            return 1;
        }

        if ((file != nullptr) && (access(file, F_OK)) && !server){
            cerr << "Invalid file\n";
            return 1;
        }

        return 0;
    }
};

/**
 *  Structure that contains necessary information to be send through packet
 */
struct secrethdr{
    const char id[AES_BLOCK_SIZE];  // ID to be recognized by server
    int type;                       // Type of packet
    int length = 0;                 // Length of data
    char data[MAX_DATA_LEN];        // Data
};

/**
 *  Encrypt given data
 * 
 *  @param data - Data to be encrypted
 *  @param length - Length of data
 * 
 *  @return - Returns encrypted data
 */
char *encrypt_data(char *data, int length){
    unsigned char *output = (unsigned char *)calloc(length + COMPLEMENT(length), sizeof(char));
    if (output == nullptr) {
        cerr << "Allocation failed" << endl;
        return nullptr;
    }
    for (int shift = 0; shift < length; shift += AES_BLOCK_SIZE) {
        AES_encrypt((unsigned char*)(data + shift), (output + shift), &key_e);
    }
    return (char *)output;
}

/**
 *  Decrypt given data
 * 
 *  @param data - Data to be decrypted
 *  @param length - Length of data
 * 
 *  @return - Returns decrypted data
 */
char *decrypt_data(char *data, int length){
    unsigned char *output = (unsigned char *)calloc(length + COMPLEMENT(length), sizeof(char));
    if (output == nullptr) {
        cerr << "Allocation failed" << endl;
        return nullptr;
    }
    for (int shift = 0; shift < length; shift += AES_BLOCK_SIZE) {
        AES_decrypt((unsigned char*)(data + shift), (output + shift), &key_d);
    }
    return (char *)output;
}

/**
 *  Function taken from ISA exaple icmp4.c
 *  Calculate checksum
 */
uint16_t checksum (uint16_t *addr, int len) {
  int count = len;
  uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

/**
 *  Send file given by arguments to given IP
 * 
 *  @param args - Program arguments
 *  @param serverinfo - Structure thats stores info about where to send packet
 *  @param sock - Socket
 *  
 *  @returns - Returns 0 if ok, else 1
 */
int send_file(ArgumentParser args, struct addrinfo *serverinfo, int sock){
    char *file_name = encrypt_data((char *)basename(args.file), strlen(basename(args.file)));
    char *id =  encrypt_data((char *)ID ,8);
    if (file_name == nullptr || id == nullptr) return 1;

	char packet[PACKET_SIZE];
    char buff[MAX_DATA_LEN];
    char *result_cypher;
    int total_length = 0;
    int poll_events;
	memset(&packet, 0, PACKET_SIZE);
    memset(&buff, 0, MAX_DATA_LEN);

    ifstream file;
    file.open(args.file, ios::in | ios::binary);
    if (!file.is_open()) {
        cerr << "Couldn't open file" << endl;
        return 1;
    }

	struct icmphdr *icmp_header = (struct icmphdr *)packet;
    struct secrethdr *secret = (struct secrethdr *)(packet + sizeof(struct icmphdr));
    struct pollfd pfds[1];

    pfds[0].fd = sock;
    pfds[0].events = POLLOUT;

    icmp_header->type = serverinfo->ai_family == AF_INET ? ICMP_ECHO: ICMP6_ECHO_REQUEST;
	icmp_header->code = 0;
	icmp_header->checksum = 0;

    memcpy((char *)secret->id, id, 16);
    memcpy(secret->data, file_name, strlen(basename(args.file)) + COMPLEMENT(strlen(basename(args.file))));
    secret->type = START;
    secret->length = strlen(args.file);
    if (secret->length > 1024) {
        cerr << "File name is too big" << endl;
        return 1;
    }
    icmp_header->checksum = checksum((uint16_t *)packet, sizeof(struct icmphdr) + sizeof(struct secrethdr) - 
                                        (MAX_DATA_LEN - secret->length) + COMPLEMENT(secret->length));
    if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secrethdr) - (MAX_DATA_LEN - secret->length) + COMPLEMENT(secret->length), 
                0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) == -1){
        cerr << "Send to failed" << endl;
        return 1;
    }

    while (!file.eof()) {
        icmp_header->checksum = 0; 

        file.read(buff, MAX_DATA_LEN);
        secret->length = file.gcount();

        secret->type = TRANSFER;
        total_length += secret->length;

        result_cypher = encrypt_data(buff, secret->length);
        if (result_cypher == nullptr) return 1;

        memcpy(secret->data, result_cypher, secret->length + COMPLEMENT(secret->length));

        icmp_header->checksum =  checksum((uint16_t *)packet, sizeof(struct icmphdr) + sizeof(struct secrethdr) - 
                                            (MAX_DATA_LEN - secret->length) + COMPLEMENT(secret->length));

        poll_events = poll(pfds, 1, -1);
        if (poll_events != -1) {
            if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secrethdr) - (MAX_DATA_LEN - secret->length) + COMPLEMENT(secret->length), 
                        0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) == -1){
                cerr << "Send to failed" << endl;
                return 1;
            }
        }else {
            cerr << "Poll error" << endl;
            free(result_cypher);
            return 1;
        }
        free(result_cypher);
    }

    secret->length = total_length;
    secret->type = END;
    memset(secret->data, 0, MAX_DATA_LEN);

    icmp_header->checksum = 0;
    icmp_header->checksum = checksum((uint16_t *)packet, sizeof(struct icmphdr) + sizeof( struct secrethdr));
    if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secrethdr) - MAX_DATA_LEN, 0, (struct sockaddr *)(serverinfo->ai_addr), 
                serverinfo->ai_addrlen) == -1){
        cerr << "Send to failed" << endl;
        return 1;
        
    }
    cout << "File '" << args.file << "' has been sent successfully to " << args.ip << endl; 

    free(id);
    free(file_name);
    file.close();
    return 0;
}

/**
 *  Run client. Prepare socket and server info
 * 
 *  @param args - Program arguments
 *  
 *  @return - Returns 0 if ok, else returns 1
 */
int client(ArgumentParser args){
    struct addrinfo hints, *serverinfo;
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;

    int result;
	if ((result = getaddrinfo(args.ip, nullptr, &hints, &serverinfo)) != 0){
        cerr << "IP error: " << gai_strerror(result) << endl; 
		return 1;
	}

    int protocol = serverinfo->ai_family == AF_INET ? (int)IPPROTO_ICMP : (int)IPPROTO_ICMPV6;
    int sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
	if (sock == -1){
        for(;serverinfo->ai_next != nullptr && sock == -1; serverinfo = serverinfo->ai_next) {
            protocol = serverinfo->ai_family == AF_INET ? (int)IPPROTO_ICMP : (int)IPPROTO_ICMPV6;
            sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
        }
        if (sock == -1){
            cerr << "Socket error. Make sure you run this program as sudo" << endl;
            return 1;
        }
	}

    if (send_file(args, serverinfo, sock)) {
        return 1;
    }

    freeaddrinfo(serverinfo);
    return 0;
}


/**
 *  Handle incoming packets. If it's packet send by client write packet data into file
 * 
 *  @param args - Useless
 *  @param header - Useless
 *  @param packet - Captured packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct sll_header *sll = (struct sll_header *)packet;
    struct secrethdr *secret;
    if (ntohs(sll->sll_protocol) == ETHERTYPE_IP){
        struct iphdr *ip = (struct iphdr *)(packet + SIZE_SLL);
        int ip_len = ip->ihl * 4;
        secret = (struct secrethdr *)(packet + sizeof(struct icmphdr) + SIZE_SLL + ip_len);
    }else if (ntohs(sll->sll_protocol) == ETHERTYPE_IPV6) {
        secret = (struct secrethdr *)(packet + sizeof(struct icmphdr) + SIZE_SLL + sizeof(ip6_hdr));
    }else {
        cout << "Packet doesn't contain IP protocol" << endl;
        return;
    }

    char *id = decrypt_data((char *)secret->id, AES_BLOCK_SIZE);
    if (id == nullptr) return;
    if (strcmp(id, ID)){
        free(id);
        return;
    }

    if (secret->type == START) {
        char *name = decrypt_data(secret->data, secret->length);
        if (name == nullptr) return;
        
        string file_name = name;
        free(name);

        cout << "Receiving file '" << file_name << "' ..." << endl;   
        if (filesystem::exists(file_name)) {
            cerr << "File already exists. File will be overwritten" << endl;
        }

        server_file.open(file_name, ios::binary | ios::out);
        if (!server_file.is_open()) {
            cerr << "Couldn't open file" << endl;
            return;
        }
    }

    if (secret->type == TRANSFER) {
        if (!server_file.is_open()) {
            cerr << "Couldn't open file" << endl;
            return;
        }
        char *decoded = decrypt_data(secret->data, secret->length);
        if (decoded == nullptr) return;
        
        buffer.insert(buffer.end(), decoded, decoded + secret->length);

        if (buffer.size() >= 5242880) {
            server_file.write(buffer.data(), buffer.size()); 
            buffer.clear();
        }
        total_file_length += secret->length;
        free(decoded);
    }

    if (secret->type == END) {
        if (buffer.size() != 0) {
            server_file.write(buffer.data(), buffer.size());
            buffer.clear();
        }
        if (total_file_length != secret->length) {
            cerr << "Total lenght of files is different, some packets may have been lost" << endl;
        }
        total_file_length = 0;
        server_file.close();
        cout << "File transfered" << endl << endl;
    }

    free(id);
}

/**
 *  Run server using pcap to capture incoming packets on "any" interface
 *  Inspired https://www.tcpdump.org/pcap.html
 * 
 *  @return - Returns 0 if ok, else returns 1
 */
int server(){
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *filter = "icmp[icmptype] = icmp-echo or icmp6[icmp6type] = icmp6-echo";
    const char *interface = "any";
    struct bpf_program fp;
    pcap_t* handle; 
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        cerr << errbuf << endl;
        net = 0;
        mask = 0;
    }

    if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == nullptr){
        cerr << errbuf << endl;
        return 1;
    }
    
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    if (pcap_loop(handle, 0, got_packet, nullptr) == PCAP_ERROR){
        return 1;
    }

    if (server_file.is_open()) {
        server_file.close();
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

    // Set encryption key and decryption key
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