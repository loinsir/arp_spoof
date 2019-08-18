#pragma once
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>
using namespace std;

typedef struct
{
    struct ethhdr eth_hdr;
    struct ether_arp arp_hdr;
} arp_packet;

void usage();
void get_node_MAC(pcap_t* fp, const uint8_t* attacker_MAC, const uint8_t* node_IP, uint8_t* node_mac);
void get_attacker_mac(char* dev, uint8_t* attackermac);
void convert_argv_into_ip(uint8_t* IP, char* argv);
void arp_spoof(pcap_t* fp, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* attacker_MAC, uint8_t* target_IP);
