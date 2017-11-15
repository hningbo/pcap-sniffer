#ifndef SNIFFER_H
#define SNIFFER_H
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>

class Sniffer
{
public:
    void get_packet(u_char *arg ,const struct pcap_pkthdr * pkthdr ,const u_char *packet);
    void resolve_packet();
private:
    char *dev;
    Sniffer(char *dev);
    ~Sniffer()
    {

    };
};
#endif
