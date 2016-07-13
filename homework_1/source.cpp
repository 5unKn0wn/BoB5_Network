#include <arpa/inet.h>
#include <stdio.h>
#include <pcap.h>

#define ETHERTYPEIP 0x0800
#define IPPROTOTCP 6

struct ether_header {
    unsigned char DstMACAddr[6];
    unsigned char SrcMACAddr[6];
    unsigned short EtherType;
};

struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char Header_Length:4;
    unsigned char Version:4;
#endif 
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned char Version:4;
    unsigned char Header_Length:4;
#endif
    unsigned char TOS;
    unsigned short Total_Length;
    unsigned short Identification;
    unsigned short Fragment_Offset;
    unsigned char TTL;
    unsigned char Protocol;
    unsigned short Header_Checksum;
    unsigned int SrcIPAddr;
    unsigned int DstIPAddr;
};

struct tcp_header {
    unsigned short SrcPort;
    unsigned short DstPort;
    unsigned int Seq_Number;
    unsigned int Ack_Number;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char Reserved:4;
    unsigned char Offset:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned char Offset:4;
    unsigned char Reserved:4;
#endif
    unsigned char TCPFlags;
    unsigned short Window;
    unsigned short Checksum;
    unsigned short Urgent_Pointer;
};

void callback(unsigned char*, const pcap_pkthdr*, const unsigned char*);
int main(void) {
    unsigned int ip_hex, subnet_hex;
    struct in_addr inaddr;
    pcap_t* handle;
    char* device, errbuf[PCAP_ERRBUF_SIZE];

    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        printf("[!] error in device_pcap_lookupdev()\n");
        printf("%s\n", errbuf);
        return -1;
    }
    printf("[*] device : %s\n", device);
    
    if (pcap_lookupnet(device, &ip_hex, &subnet_hex, errbuf) == -1) {
        printf("[!] error in pcap_lookupnet()\n");
        printf("%s\n", errbuf);
        return -1;
    }
    inaddr.s_addr = ip_hex;
    printf("[*] ip address : %s\n", inet_ntoa(inaddr));
    inaddr.s_addr = subnet_hex;
    printf("[*] subnetmask address : %s\n", inet_ntoa(inaddr));

    handle = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
    if (handle == NULL) {
        printf("[!] error in pcap_open_live()\n");
        printf("%s\n", errbuf);
        return -1;
    }

    printf("\n");
    pcap_loop(handle, 0, callback, NULL);

    return 0;
}

void callback(unsigned char* param, const pcap_pkthdr* pkthdr, const unsigned char* packet) {
    struct ether_header* ethdr;
    struct ip_header* iphdr;
    struct tcp_header* tcphdr;
    struct in_addr inaddr;
    int IPHeaderLen;

    ethdr = (struct ether_header*)packet;
    if (ntohs(ethdr->EtherType) != ETHERTYPEIP)
        return;
    
    iphdr = (struct ip_header*)(packet + sizeof(ether_header));
    IPHeaderLen = iphdr->Header_Length * 4;
    if (iphdr->Protocol != IPPROTOTCP)
        return;

    tcphdr = (struct tcp_header*)(packet + sizeof(ether_header) + IPHeaderLen);

    printf("[*] Receiving packet\n");
    printf("Source MAC Address : ");
    for (int i = 0; i < 6; i++) 
        printf("%02x:", ethdr->SrcMACAddr[i]);
    printf("\b \n");
    inaddr.s_addr = iphdr->SrcIPAddr;
    printf("Source IP Address : %s\n", inet_ntoa(inaddr));
    printf("Source Port : %d\n", ntohs(tcphdr->SrcPort));

    printf("Destination MAC Address : ");
    for (int i = 0; i < 6; i++) 
        printf("%02x:", ethdr->DstMACAddr[i]);
    printf("\b \n");
    inaddr.s_addr = iphdr->DstIPAddr;
    printf("Destination IP Address : %s\n", inet_ntoa(inaddr));
    printf("Destination Port : %d\n", ntohs(tcphdr->DstPort));
    printf("\n");
    
    return;
}
