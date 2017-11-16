#include"Sniffer.h"

int main()
{
    Sniffer sniffer("ens37");
    sniffer.loop_packet();
}
