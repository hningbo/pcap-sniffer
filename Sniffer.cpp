#include "Sniffer.h"

Sniffer::Sniffer(char *devname)
{
    /* open a device, wait until a packet arrives */
    device = pcap_open_live(devname, 65535, 1, 0, ERR_BUF);
  
    if(!device)
    {
        printf("error: pcap_open_live(): %s\n", ERR_BUF);
        exit(1);
    }
    printf("success : pcap_open_live(): %s\n", devname);
}

void Sniffer::get_packet(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;



    printf("id: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
  
    const u_char *send_mac = (u_char *)malloc(sizeof(u_char ) * 6);
    const u_char *recv_mac = (u_char *)malloc(sizeof(u_char ) * 6);
    const u_char *net_protocol = (u_char*)malloc(sizeof(u_char) * 2);
    const u_char *send_ip = (u_char *)malloc(sizeof(u_char ) * 8);
    const u_char *recv_ip = (u_char *)malloc(sizeof(u_char ) * 8);
    const u_char *trans_protocol = (u_char*)malloc(sizeof(u_char) * 1);

    int source_port = 0;
    int dest_port = 0;

    int i;
    for(i=0; i<pkthdr->len; ++i)
    {
        printf(" %02x", packet[i]);
        if( (i + 1) % 16 == 0 )
        {
            printf("\n");
        }
    }
    send_mac = packet;
    recv_mac = packet+6;  
    net_protocol = packet + 12;

    printf("\n");
    printf("Source mac address : ");
    for(int i = 0 ;i<6 ;i++)
    {
        printf(" %02x" ,send_mac[i]);                              
    }
    
    printf("\n");
    printf("Desitination mac address : ");
    for(int i = 0 ;i<6 ;i++)
    {
        printf(" %02x" ,recv_mac[i]);                              
    }

    printf("\n\n");
    printf("The network layer protocol is : ");
    for(int i = 0 ;i<2 ;i++)
    {   
        printf(" %02x" ,net_protocol[i]);                              
    }
    printf("\n");

    if(net_protocol[0] == 0x08 && net_protocol[1] == 0x00)
    {
        const u_char * ip_packet = net_protocol + 2;
        trans_protocol = ip_packet + 9;

        send_ip = ip_packet + 12;
        recv_ip = ip_packet + 16;
        printf("The source ip is : ");
        for(int i = 0 ;i<4 ;i++)
        {
            printf("%d" ,send_ip[i]);
            if(i<3)
            {
                printf(".");
            }
        }

        printf("\n");
        printf("The desitination ip is : ");
        for(int i = 0 ;i<4 ;i++)
        {
            printf("%d" ,recv_ip[i]);  
            if(i<3)
            {
                printf(".");
            }
        } 

        printf("\n");
        
        const u_char ip_header_len = *(ip_packet + 1);
        
        const u_char *trans_packet = ip_packet + ip_header_len;

        if(trans_protocol[0] != 0x06 && trans_protocol[0] != 0x17)
        {
            return ;
        }
        printf("\n");
        printf("The transform layer protocol is : ");
        printf("%02x" ,trans_protocol[0]);
        printf("\n");
        
        if(trans_protocol[0] == 0x6)
        {
            printf("TCP is used in this packet...\n");
            for(int i = 0 ;i<2 ;i++)
            {
                source_port += 256*(1-i)*(*(trans_packet + i));
                dest_port += 256*(1-i)*(*(trans_packet + i + 2));
            }
            printf("The source port is : %d\n" ,source_port);
            printf("The destination port is : %d\n" ,dest_port);
        }

        if(trans_protocol[0] == 0x17)
        {
            printf("UDP is used in this packet...\n");
            for(int i = 0 ;i<2 ;i++)
            {
                source_port += 256*(1-i)*(*(trans_packet + i));
                dest_port += 256*(1-i)*(*(trans_packet + i + 2));
            }
            printf("The source port is : %d\n" ,source_port);
            printf("The destination port is : %d\n" ,dest_port);
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
