#include <arpa/inet.h>
#include <stdio.h>
#include <pcap.h>

#define MACSIZE 6
#define IPADDRLEN 16
#define ETHERTYPEIP 0x0800
#define IPPROTOTCP 6

struct ether_header {
    unsigned char DstMACAddr[MACSIZE];
    unsigned char SrcMACAddr[MACSIZE];
    unsigned short EtherType;
};

struct ip_header {
    unsigned char Header_Length:4;
    unsigned char Version:4;
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
    unsigned char Reserved:4;
    unsigned char Offset:4;
    unsigned char TCPFlags;
    unsigned short Window;
    unsigned short Checksum;
    unsigned short Urgent_Pointer;
};

void callback(unsigned char*, const pcap_pkthdr*, const unsigned char*);
int main(void) {
	char net_str[IPADDRLEN], mask_str[IPADDRLEN];
    unsigned int net_hex, mask_hex;
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
    
    if (pcap_lookupnet(device, &net_hex, &mask_hex, errbuf) == -1) {
        printf("[!] error in pcap_lookupnet()\n");
        printf("%s\n", errbuf);
        return -1;
    }
    inaddr.s_addr = net_hex;
    printf("[*] ip address : %s\n", inet_ntop(AF_INET, &inaddr, net_str, IPADDRLEN));
    inaddr.s_addr = mask_hex;
    printf("[*] subnetmask address : %s\n", inet_ntop(AF_INET, &inaddr, mask_str, IPADDRLEN));

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
	char IPAddr[IPADDRLEN];
    int IPHeaderLen;

    ethdr = (struct ether_header*)packet;
    if (ntohs(ethdr->EtherType) != ETHERTYPEIP)
        return;
    
    iphdr = (struct ip_header*)(packet + sizeof(ether_header));
    IPHeaderLen = iphdr->Header_Length * 4;
    if (iphdr->Protocol != IPPROTOTCP)
        return;

    tcphdr = (struct tcp_header*)((char*)iphdr + IPHeaderLen);

    printf("[*] Receiving packet\n");
    printf("Source MAC Address : ");
    for (int i = 0; i < MACSIZE; i++) 
        printf("%02x:", ethdr->SrcMACAddr[i]);
    printf("\b \n");
    inaddr.s_addr = iphdr->SrcIPAddr;
    printf("Source IP Address : %s\n", inet_ntop(AF_INET, &inaddr, IPAddr, IPADDRLEN));
    printf("Source Port : %d\n", ntohs(tcphdr->SrcPort));

    printf("Destination MAC Address : ");
    for (int i = 0; i < MACSIZE; i++) 
        printf("%02x:", ethdr->DstMACAddr[i]);
    printf("\b \n");
    inaddr.s_addr = iphdr->DstIPAddr;
    printf("Destination IP Address : %s\n", inet_ntop(AF_INET, &inaddr, IPAddr, IPADDRLEN));
    printf("Destination Port : %d\n", ntohs(tcphdr->DstPort));
    printf("\n");
    
    return;
}
