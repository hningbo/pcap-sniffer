#ifndef SNIFFER_H
#define SNIFFER_H
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>

class Sniffer
{
public:
    char ERR_BUF[PCAP_ERRBUF_SIZE]; 
    static void get_packet(u_char *arg ,const struct pcap_pkthdr * pkthdr ,const u_char *packet);
    void loop_packet();
    void resolve_packet();
    Sniffer(char *dev);
    ~Sniffer()
    {

    };

private:
    char *dev;
    pcap_t *device;
};
#endif
