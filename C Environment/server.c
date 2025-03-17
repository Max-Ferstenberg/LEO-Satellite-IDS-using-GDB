#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <dirent.h>

/*
    Our main testing environment, emulates server behaviour, routes packets along our simulated satellite topology
    The server processes network traffic, mimicking the behavior of satellites by routing packets between nodes (user terminal, satellites, ground station, PoP) with configurable delays.
    This was designed with GDB usage specifically in mind
*/

// --- Constants defining network delays and packet loss ---
#define UPLINK_DELAY_US     25000   //Delay for User Terminal to Satellite link (in microseconds) - Placeholder value for GDB 
#define DOWNLINK_DELAY_US   25000   //Delay for Satellite to Ground Station link (in microseconds) - Placeholder value for GDB
#define ISL_DELAY_US        5000    //Delay for inter-satellite link (between satellites) (in microseconds) - Placeholder value for GDB
#define PACKET_LOSS_PROBABILITY 0.00 //Simulated packet loss probability, 0% in our case because we don't want to lose any packets for GDB

// --- Simulated MAC addresses for network nodes ---
#define UT_MAC   "00:00:00:00:00:01"  // User Terminal
#define SAT1_MAC "00:00:00:00:00:02"  // Satellite 1
#define SAT2_MAC "00:00:00:00:00:03"  // Satellite 2
#define GS_MAC   "00:00:00:00:00:04"  // Ground Station
#define POP_MAC  "00:00:00:00:00:05"  // Point of Presence

// --- Data structure for packet information ---
//Structure for holding one packet of information
typedef struct {
    const u_char *packet;  //Pointer to the raw packet data
    int len;               //Length of the packet
    char src_ip[INET_ADDRSTRLEN];  //Source IP address
    char dest_ip[INET_ADDRSTRLEN]; //Destination IP address
    int protocol;          //Protocol number
    int src_port;          //Source port number
    int dest_port;         //Destination port number
    char src_mac[18];      //Source MAC address (string)
    char dst_mac[18];      //Destination MAC address (string)
} PacketInfo;

/*
    Function Prototypes:
    - parse_packet: Dissects a raw packet into its components
    - process_packet: Routes the packet through simulated network links
    - process_packet_sat2: Special processing for packets at Satellite 2 - GDB breakpoint
    - simulate_link: Simulates network conditions (delay, loss) between two nodes
    - get_next_hop: Determines the next node (MAC address) in the simulated network path
    - process_pcap_file: Processes an individual PCAP file and logs the order
    - process_directory: Iterates over a directory of PCAP files, processing each one
    - is_uplink_packet: Determines if a packet is part of an uplink flow based on the source MAC
*/

void parse_packet(const u_char* packet, int len, PacketInfo *pinfo);
void process_packet(PacketInfo *pinfo, const char *current_hop_mac, bool is_uplink);
void process_packet_sat2(PacketInfo *pinfo);
void simulate_link(const char *src_mac, const char *dest_mac, PacketInfo *pinfo, bool is_uplink);
const char* get_next_hop(const char* current_mac, bool is_uplink);
void process_pcap_file(const char *filename, FILE *order_file);
void process_directory(const char *dirname);
bool is_uplink_packet(const char *src_mac);

/*
    parse_packet:
    Dissects a raw packet and populates a PacketInfo structure
*/
void parse_packet(const u_char* packet, int len, PacketInfo *pinfo) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    //Get and format MAC addresses
    snprintf(pinfo->src_mac, sizeof(pinfo->src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_shost[0], eth_header->ether_shost[1],
             eth_header->ether_shost[2], eth_header->ether_shost[3],
             eth_header->ether_shost[4], eth_header->ether_shost[5]);
    snprintf(pinfo->dst_mac, sizeof(pinfo->dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_dhost[0], eth_header->ether_dhost[1],
             eth_header->ether_dhost[2], eth_header->ether_dhost[3],
             eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    //Only process IP packets - Satellites only deal with IP
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    //Get IP addresses
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip_header->ip_src), pinfo->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), pinfo->dest_ip, INET_ADDRSTRLEN);

    pinfo->protocol = ip_header->ip_p;

    //Depending on protocol, extract port numbers from TCP or UDP headers
    if (pinfo->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)((char *)ip_header + (ip_header->ip_hl * 4));
        pinfo->src_port = ntohs(tcp_header->th_sport);
        pinfo->dest_port = ntohs(tcp_header->th_dport);
    } else if (pinfo->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)((char *)ip_header + (ip_header->ip_hl * 4));
        pinfo->src_port = ntohs(udp_header->uh_sport);
        pinfo->dest_port = ntohs(udp_header->uh_dport);
    } else {
        pinfo->src_port = -1;
        pinfo->dest_port = -1;
    }
    pinfo->packet = packet;
    pinfo->len = len;
}

/*
    process_packet:
    Routes a packet through the simulated network based on the current node. If the current node is Satellite 2, it is passed to a processing function separate from the rest so that we can attach GDB safely
    Otherwise, the next hop is determined and the packet is forwarded through simulate_link.
*/
void process_packet(PacketInfo *pinfo, const char *current_hop_mac, bool is_uplink) {
    if (strcmp(current_hop_mac, SAT2_MAC) == 0) {
        process_packet_sat2(pinfo);
        return;
    }
    const char *next_hop = get_next_hop(current_hop_mac, is_uplink);
    if (!next_hop) {
        return;
    }
    simulate_link(current_hop_mac, next_hop, pinfo, is_uplink);
}

/*
    is_uplink_packet:
    Determines if a packet is part of an uplink flow by comparing source MAC address
*/
bool is_uplink_packet(const char *src_mac) {
    return (strcmp(src_mac, UT_MAC) == 0);
}

/*
    process_packet_sat2:
    This is where we place our GDB breakpoint, we place the breakpoint at this function, and then hop to the end of function execution, the point immediately after the packet has been processed
*/
void process_packet_sat2(PacketInfo *pinfo) {
    PacketInfo sat2_pinfo;
    parse_packet(pinfo->packet, pinfo->len, &sat2_pinfo);
    bool is_uplink = is_uplink_packet(sat2_pinfo.src_mac);
    const char *next_hop = get_next_hop(SAT2_MAC, is_uplink);
    if (!next_hop) {
        return;
    }
    simulate_link(SAT2_MAC, next_hop, pinfo, is_uplink);
}

/*
    get_next_hop:
    Determines the next node's MAC address in the network path based on the current node and packet direction
    For uplink traffic, the order is: UT -> SAT1 -> SAT2 -> GS -> POP, and the reverse for downlink
*/
const char* get_next_hop(const char* current_mac, bool is_uplink) {
    if (is_uplink) {
        if (strcmp(current_mac, UT_MAC) == 0) return SAT1_MAC;
        if (strcmp(current_mac, SAT1_MAC) == 0) return SAT2_MAC;
        if (strcmp(current_mac, SAT2_MAC) == 0) return GS_MAC;
        if (strcmp(current_mac, GS_MAC) == 0) return POP_MAC;
    } else {
        if (strcmp(current_mac, POP_MAC) == 0) return GS_MAC;
        if (strcmp(current_mac, GS_MAC) == 0) return SAT2_MAC;
        if (strcmp(current_mac, SAT2_MAC) == 0) return SAT1_MAC;
        if (strcmp(current_mac, SAT1_MAC) == 0) return UT_MAC;
    }
    return NULL;
}

/*
    simulate_link:
    Simulates the network link between two nodes by introducing a delay and probabilistically dropping packets to simulate packet loss
    After applying the delay and loss the packet is forwarded to the next hop
*/
void simulate_link(const char *src_mac, const char *dest_mac, PacketInfo *pinfo, bool is_uplink) {
    int delay_us = 0;
    if ((strcmp(src_mac, UT_MAC) == 0 && strcmp(dest_mac, SAT1_MAC) == 0) ||
        (strcmp(src_mac, SAT1_MAC) == 0 && strcmp(dest_mac, UT_MAC) == 0)) {
        delay_us = UPLINK_DELAY_US;
    } else if ((strcmp(src_mac, SAT1_MAC) == 0 && strcmp(dest_mac, SAT2_MAC) == 0) ||
               (strcmp(src_mac, SAT2_MAC) == 0 && strcmp(dest_mac, SAT1_MAC) == 0)) {
        delay_us = ISL_DELAY_US;
    } else if ((strcmp(src_mac, SAT2_MAC) == 0 && strcmp(dest_mac, GS_MAC) == 0) ||
               (strcmp(src_mac, GS_MAC) == 0 && strcmp(dest_mac, SAT2_MAC) == 0)) {
        delay_us = DOWNLINK_DELAY_US;
    }
    usleep(delay_us);  //Introduce delay

    //Packet loss
    if (((double)rand() / RAND_MAX) < PACKET_LOSS_PROBABILITY) {
        return;
    }
    //Forward packet to next hop
    process_packet(pinfo, dest_mac, is_uplink);
}

/*
    process_pcap_file:
    Processes a single PCAP file by reading each packet, parsing it, and simulating its journey
    through the network
*/
void process_pcap_file(const char *filename, FILE *order_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    bool first_packet = true;
    char client_ip[INET_ADDRSTRLEN] = "";
    char server_ip[INET_ADDRSTRLEN] = "";

    handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open pcap: %s\n", errbuf);
        return;
    }

    //Log the name of the processed PCAP file (Just for keeping track of progress)
    fprintf(order_file, "%s\n", filename);
    printf("Processing %s...\n", filename);

    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header))) {
        PacketInfo pinfo;
        parse_packet(packet, header.len, &pinfo);

        //Record client and server IPs from the first packet
        if (first_packet) {
            strcpy(client_ip, pinfo.src_ip);
            strcpy(server_ip, pinfo.dest_ip);
            first_packet = false;
        }

        //Determine packet direction and process accordingly
        bool is_uplink = is_uplink_packet(pinfo.src_mac);
        const char *initial_hop = is_uplink ? UT_MAC : POP_MAC;
        process_packet(&pinfo, initial_hop, is_uplink);
    }

    pcap_close(handle);
    printf("Finished processing %s.\n", filename);
}

/*
    process_directory:
    Traverses our PCAP directory and processes each file
    The processing order is recorded in pcap_order.txt so that we can assign each GDB output to each packet later on
*/
void process_directory(const char *dirname) {
    DIR *dir;
    struct dirent *entry;
    FILE *order_file;

    order_file = fopen("pcap_order.txt", "w");
    if (!order_file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    dir = opendir(dirname);
    if (!dir) {
        perror("opendir");
        fclose(order_file);
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".pcap")) {
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", dirname, entry->d_name);
            process_pcap_file(filepath, order_file);
        }
    }

    closedir(dir);
    fclose(order_file);
}

/*
    main:
    Entry point of the C server, expects one command-line argument specifying the directory
    containing PCAP files, and then processes all those files
*/
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory_path>\n", argv[0]);
        return 1;
    }

    process_directory(argv[1]);

    return 0;
}