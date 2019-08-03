#include <QCoreApplication>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


typedef struct ETHheader {
    uint8_t destMac[6];
    uint8_t srcMac[6];
    uint16_t type;
} eth_header;

typedef struct arp {
    uint16_t hardware_type;
    uint16_t protocol_type;

    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;

    uint16_t operation;

    uint8_t Sender_Mac[6];
    uint8_t Sender_Ip[4];

    uint8_t Target_Mac[6];
    uint8_t Target_Ip[4];
} arp_header;

void get_MAC(uint8_t *mac) {
    scanf("%02x:%02x:%02x:%02x:%02x:%02x", mac, mac+1, mac+2, mac+3, mac+4, mac+5);
}

void get_IP(uint8_t *ip) {
    scanf("%u.%u.%u.%u",ip, ip+1, ip+2, ip+3);
}

int main(int argc, char **argv) {

    pcap_t *fp=0;

    eth_header eth;
    arp_header arp;
    unsigned int optype = 0;

    int length = 0, no=0;
    int i;
    uint8_t packet[1500];
    char errbuf[PCAP_ERRBUF_SIZE], yn;
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);


    if ((fp = pcap_open_live(dev, 65535, 0, 1000, errbuf)) == NULL) {
        fprintf(stderr, "unable to open adapter\n", errbuf);
        exit(1);
    }

    memset(packet, 0, sizeof(packet));


    printf("Dest_Mac (00:00:00:00:00:00) >> ");
    get_MAC(eth.destMac);
    printf("Src_Mac (00:00:00:00:00:00) >> ");
    get_MAC(eth.srcMac);

    eth.type = htons(0x0806);	//arp

    arp.hardware_type = htons(1);
    arp.protocol_type = htons(0x0800);
    arp.hardware_addr_len = 6;
    arp.protocol_addr_len = 4;

    printf("Operation Type \n[ARP request:1, ARP reply:2, RARP request:3, RARP reply:4]\n>> ");
    scanf("%u", &optype);
    if (optype == 1) arp.operation = htons(1);
    else if (optype == 2) arp.operation = htons(2);
    else if (optype == 3) arp.operation = htons(3);
    else if (optype == 4) arp.operation = htons(4);

    printf("Sender Mac (00:00:00:00:00:00) >> ");
    get_MAC(arp.Sender_Mac);

    if(optype == 1){
        printf("use Target MAC 00:00:00:00:00:00 ?\n >> " );
        getchar();
        scanf("%c",&yn);
        if(yn == 'y'){
            memcpy(arp.Target_Mac, "\x00\x00\x00\x00\x00\x00", 6);
        }
    }else{
        printf("Target_Mac (00:00:00:00:00:00) >> ");
        get_MAC(arp.Target_Mac);
    }

    printf("Sender IP (0.0.0.0) >> ");
    get_IP(arp.Sender_Ip);
    printf("Target IP (0.0.0.0) >> ");
    get_IP(arp.Target_Ip);

    memcpy(packet, &eth, sizeof(eth));
    length += sizeof(eth);

    memcpy(packet + length, &arp, sizeof(arp));
    length += sizeof(arp);



    if ((pcap_sendpacket(fp, packet, length)) != 0) {
        fprintf(stderr, "\nError sending packet\n", pcap_geterr(fp));
    }else{
        printf("DONE\n");
    }


    return 0;
}
