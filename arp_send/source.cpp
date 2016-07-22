#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>

#define ARPPACKETSIZE 28
#define MACADDRLEN 18
#define IPADDRLEN 16

#pragma pack(push, 1)
struct ETH_Header {
	unsigned char DstMACAddr[6];
	unsigned char SrcMACAddr[6];
	unsigned short EtherType;
#define ETHERTYPEARP 0x0806
};

struct ARP_Header {
	unsigned short HardwareType;
#define HWTETHERNET 1	// HardwareType Ethernet = 1
	unsigned short ProtocolType;
#define PROTOTYPEIP 0x0800	// ProtocolType IP = 0x0800
	unsigned char HardwareAddressLength;
	unsigned char ProtocolAddressLength;
#define IPV4SIZE 4
#define MACSIZE 6
	unsigned short OperationCode;
#define OP_REQUEST 1
#define OP_REPLY   2
	unsigned char SourceHardwareAddress[6];
	unsigned int SourceProtocolAddress;
	unsigned char TargetHardwareAddress[6];
	unsigned int TargetProtocolAddress;
};

struct PACKET_Header {
	struct ETH_Header ETH_Packet;
	struct ARP_Header ARP_Packet;
};
#pragma pack(pop)

bool GetMyIPAddr(char*, unsigned int*);
bool GetMyMACAddr(char*, unsigned char*);
bool GetMyGatewayIPAddr(char*, unsigned int*);
bool SendARPPacket(char*, unsigned char*, unsigned int, unsigned int, unsigned int);
bool RecvARPPacket(pcap_t*, struct pcap_pkthdr*, const struct PACKET_Header*);
void SetDefaultARP(struct ARP_Header*, unsigned char*, unsigned int, unsigned int);
void SetDefailtETH(struct ETH_Header*, unsigned char*);
void callback(unsigned char*, struct pkthdr*, unsigned char*);
int main(void) {
	struct in_addr inaddr;
	unsigned char MyMACAddrHex[6], VictimMACAddrHex[6], GatewayMACAddrHex[6];
	char MyMACAddrStr[MACADDRLEN] = { 0 }, VictimMACAddrStr[MACADDRLEN] = { 0 }, GatewayMACAddrStr[MACADDRLEN] = { 0 };
	unsigned int MyIPAddrHex, VictimIPAddrHex, GatewayIPAddrHex;
	char MyIPAddrStr[IPADDRLEN], VictimIPAddrStr[IPADDRLEN], GatewayIPAddrStr[IPADDRLEN];
	char* device, errbuf[PCAP_ERRBUF_SIZE];
	unsigned int net_hex, subnet_hex;
	int fd;

	// Get Network Interface Name
	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		printf("error in lookupdev()\n");
		printf("%s\n", errbuf);
		return -1;
	}
	printf("Network Interface : %s\n", device);

	// Get My IP Address
	if (GetMyIPAddr(device, &MyIPAddrHex) == false) {
		printf("Can't get my IP address\n");
		return -1;
	}
	inaddr.s_addr = MyIPAddrHex;
	inet_ntop(AF_INET, &inaddr, MyIPAddrStr, IPADDRLEN);
	
	// Get My MAC Address
	if (GetMyMACAddr(device, MyMACAddrHex) == false) {
		printf("Can't get my MAC address\n");
		return -1;
	}
	for (int i = 0; i < MACSIZE; i++) 
		sprintf(MyMACAddrStr, "%s%02x%s", MyMACAddrStr, MyMACAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));
	
	// Get Gateway's IP Address
	if (GetMyGatewayIPAddr(device, &GatewayIPAddrHex) == false) {
		printf("Can't get my Gateway IP address\n");
		return -1;
	}
	inaddr.s_addr = GatewayIPAddrHex;
	inet_ntop(AF_INET, &inaddr, GatewayIPAddrStr, IPADDRLEN);

	// Print Information
	printf("MAC Address : %s\n", MyMACAddrStr);
	printf("IP Address : %s\n", MyIPAddrStr);
	printf("Gateway IP Address : %s\n", GatewayIPAddrStr);

	// Get Victim IP Address from User
	printf("\nInput victim's IP Address : ");
	fgets(VictimIPAddrStr, IPADDRLEN, stdin);
	VictimIPAddrHex = inet_addr(VictimIPAddrStr);
	
	// Send ARP Packet to Victim, Gateway for Getting Victim, Gateway's MAC Address
	if (SendARPPacket(device, MyMACAddrHex, MyIPAddrHex, VictimIPAddrHex, GatewayIPAddrHex) == false) {
		printf("Cat't send ARP_REQUEST Packet\n");
		return -1;
	}
	// printf("\nVictim MAC Address : %s\n", VictimMACAddrStr);
	// printf("Gateway MAC Address : %s\n", GatewayMACAddrStr);

	return 0;
}

bool GetMyIPAddr(char* device, unsigned int* IPAddr) {
	struct ifaddrs *ifaddr, *ifa;
	struct sockaddr_in* inaddr;
	int family, s;

	if (getifaddrs(&ifaddr) == -1) {
		perror("Error in getifaddrs()\n");
		exit(-1);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) 
			continue;

		if ((strcmp(ifa->ifa_name, device) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
			inaddr = (struct sockaddr_in*)ifa->ifa_addr;
			*IPAddr = inaddr->sin_addr.s_addr;

			freeifaddrs(ifaddr);
			return true;
		}
	}

	freeifaddrs(ifaddr);
	return false;
}

bool GetMyMACAddr(char* device, unsigned char* MACAddr) {
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, strlen(device));
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(MACAddr, ifr.ifr_hwaddr.sa_data, MACSIZE);
		close(fd);

		return true;
	}
	close(fd);

	return false;
}

bool GetMyGatewayIPAddr(char* device, unsigned int* GatewayIPAddrHex) {
	struct in_addr inaddr;
	unsigned int Gateway_hex;
	char *interface = NULL, *Gateway = NULL;
	char line[100];
	FILE* fp;

	fp = fopen("/proc/net/route", "rt");
	if (fp == NULL) {
		printf("can't open /proc/net/route\n");
		return false;
	}

	while (fgets(line, 100, fp)) {
		interface = strtok(line, "\t");
		if (strcmp(interface, device) != 0) 
			continue;

		for (int i = 0; i < 2; i++) 
			Gateway = strtok(NULL, "\t");

		if (strcmp(Gateway, "00000000") == 0) 
			continue;

		break;
	}
	*GatewayIPAddrHex = strtol(Gateway, NULL, 16);

	return true;
}

void SetDefaultARP(struct ARP_Header* packet, unsigned char* SourceMACAddr, unsigned int SourceIPAddr, unsigned int DestIPAddr) {
	packet->HardwareType = htons(HWTETHERNET);
	packet->ProtocolType = htons(PROTOTYPEIP);
	packet->HardwareAddressLength = MACSIZE;
	packet->ProtocolAddressLength = IPV4SIZE;
	packet->OperationCode = htons(OP_REQUEST);
	for (int i = 0; i < MACSIZE; i++) 
		packet->SourceHardwareAddress[i] = SourceMACAddr[i];
	packet->SourceProtocolAddress = SourceIPAddr;
	for (int i = 0; i < MACSIZE; i++)
		packet->TargetHardwareAddress[i] = 0x00;
	packet->TargetProtocolAddress = DestIPAddr;
}

void SetDefaultETH(struct ETH_Header* packet, unsigned char* SourceMACAddr) {
	for (int i = 0; i < MACSIZE; i++) 
		packet->DstMACAddr[i] = 0xff;
	for (int i = 0; i < MACSIZE; i++) 
		packet->SrcMACAddr[i] = SourceMACAddr[i];
	packet->EtherType = htons(ETHERTYPEARP);
}

bool SendARPPacket(char* device, unsigned char* MyMACAddrHex, unsigned int MyIPAddrHex, unsigned int VictimIPAddrHex, unsigned int GatewayIPAddrHex) {
	struct PACKET_Header Packet_Victim, Packet_Gateway;
	struct pcap_pkthdr* pkthdr;
	const PACKET_Header* Packet_Recv;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;

	SetDefaultARP(&Packet_Victim.ARP_Packet, MyMACAddrHex, MyIPAddrHex, VictimIPAddrHex);
	SetDefaultARP(&Packet_Gateway.ARP_Packet, MyMACAddrHex, MyIPAddrHex, GatewayIPAddrHex);
	SetDefaultETH(&Packet_Victim.ETH_Packet, MyMACAddrHex);
	SetDefaultETH(&Packet_Gateway.ETH_Packet, MyMACAddrHex);

	handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		printf("error in pcap_open_live()\n");
		printf("%s\n", errbuf);
		return false;
	}

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Gateway, sizeof(struct PACKET_Header)) != 0) {
			perror("error in pcap_sendpacket()\n");
			return false;
	}
	
	/*while (1) {
		int ret = pcap_next_ex(handle, &pkthdr, (const u_char**)&Packet_Recv);
		if (ret == 0)
			continue;
		else if (ret == -1) 
			return false;
		printf("%02x %02x %02x %02x %02x %02x\n", Packet_Recv->ETH_Packet.DstMACAddr[0], Packet_Recv->ETH_Packet.DstMACAddr[1], Packet_Recv->ETH_Packet.DstMACAddr[2], Packet_Recv->ETH_Packet.DstMACAddr[3], Packet_Recv->ETH_Packet.DstMACAddr[4], Packet_Recv->ETH_Packet.DstMACAddr[5]);
	}*/
	
	if (RecvARPPacket(handle, pkthdr, Packet_Recv) == false) {
		printf("error to send ARP Packet\n");
		return false;
	}
	// pcap_next_ex(handle, &pkthdr, (const unsigned char**)&Packet_recv);
	// if (Packet_recv == NULL) {
	//	printf("fucking\n");
	//	return false;
	// }


	return true;
}

bool RecvARPPacket(pcap_t* handle, struct pcap_pkthdr* pkthdr, const struct PACKET_Header* packet) {
	const char* filter = "dst host 192.168.0.7 && arp";
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;

	while (1) {
		ret = pcap_next_ex(handle, &pkthdr, (const unsigned char**)&packet);
		if (ret == 0) 
			continue;
		else if (ret == -1) {
			printf("error in pcap_next_ex()\n");
			return false;
		}	
		printf("%02x %02x %02x %02x %02x %02x\n", packet->ETH_Packet.DstMACAddr[0], packet->ETH_Packet.DstMACAddr[1], packet->ETH_Packet.DstMACAddr[2], packet->ETH_Packet.DstMACAddr[3], packet->ETH_Packet.DstMACAddr[4], packet->ETH_Packet.DstMACAddr[5]);
		return true;
		}
	return false;
}

void callback(unsigned char* param, struct pkthdr* pkthdr, unsigned char* packet) {
}
