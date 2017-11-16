#include "Sniffer.h"

Sniffer::Sniffer(char *devname )
{
    /* open a device, wait until a packet arrives */
    device = pcap_open_live(devname, 65535, 1, 0, ERR_BUF);
  
    if(!device)
    {
        printf("error: pcap_open_live(): %s\n", ERR_BUF);
        exit(1);
    }
}

void Sniffer::get_packet(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;

    printf("id: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
  
    int i;
    for(i=0; i<pkthdr->len; ++i)
    {
        printf(" %02x", packet[i]);
        if( (i + 1) % 16 == 0 )
        {
            printf("\n");
        }
    }  
    printf("\n\n");
}
void Sniffer::loop_packet()
{
  int id = 0;
  pcap_loop(device, -1, get_packet, (u_char*)&id);
  
  pcap_close(device);
}
