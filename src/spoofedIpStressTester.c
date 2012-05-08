/*
 ============================================================================
 Author      : PherricOxide
 Description : Network application stress testing tool for sending large amounts
 of UDP packets with fuzzed fields

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this software. If not, see <http://www.gnu.org/licenses/>.
 ============================================================================
 */


#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>


bool fuzzRandom_SrcIp = false;
bool fuzzSequential_SrcIp = false;

bool fuzzRandom_DstIp  = false;
bool fuzzSequential_DstIp  = false;

bool fuzzRandom_SrcPort = false;
bool fuzzSequential_SrcPort = false;

bool fuzzRandom_DstPort = false;
bool fuzzSequential_DstPort = false;


bool fuzzPayloadSize = false;

bool fuzzPacketInterval = false;


// Defaults (probably not what you want, make sure to enter real values in args)
uint8_t srcMac[] = {0x22,0x33,0x44,0x55,0x66,0x77};
uint8_t dstMac[6];

uint32_t dstIp;
uint32_t dstIpMin = 0;
uint32_t dstIpMax = ~0;

uint32_t srcIp;
uint32_t srcIpMin = 0;
uint32_t srcIpMax = ~0;

int packetCount = 0;

// In useconds
int intervalMin = 1000;
int intervalMax = 10000;

// In bytes
int payloadSizeMin = 1;
int payloadSizeMax = 1000;

uint16_t srcPort = 0;
uint16_t srcPortMin = 0;
uint16_t srcPortMax = 65535;

uint16_t dstPort = 0;
uint16_t dstPortMin = 0;
uint16_t dstPortMax = 65535;


inline unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

int main(int argc, char **argv)
{

	if (argc < 2) {
		printf("Usage options (may not apply to all fuzzing types),\n");
	    printf("-srcip x.x.x.x\n");
	    printf("-dstip x.x.x.x\n\n");

	    printf("-srcmac xx:xx:xx:xx:xx:xx\n");
	    printf("-dstmac xx:xx:xx:xx:xx:xx\n\n");
	    
		printf("-srcport x\n");
		printf("-srcportmin x\n");
		printf("-srcportmax x\n\n");

	    printf("-dstport x\n");
	    printf("-dstportmin x\n");
	    printf("-dstportmax x\n\n");
	    
		printf("-payloadmin x\n");
	    printf("-payloadmax x\n\n");
	    
		printf("-intervalmin x\n");
		printf("-intervalmax x\n\n");
	    
		printf("-packetcount x\n\n");

		printf("Fuzzer options\n");
		printf("-fuzzRandomSrcPort\n");
		printf("-fuzzSequentialSrcPort\n");
		printf("-fuzzRandomDstPort\n");
		printf("-fuzzSequentialDstPort\n");
		printf("-fuzzRandomSrcIp\n");
		printf("-fuzzSequentialSrcIp\n");
		printf("-fuzzRandomDstIp\n");
		printf("-fuzzSequentialDstIp\n");
		printf("-fuzzPayloadSize\n");
		printf("-fuzzPacketInterval\n");


		printf("\nNeed more help? Use the source Luke.\n");
		return -1;
	}

	// Error checking? Nope. Don't enter inputs wrong, this is quick and dirty and will explode
	printf("\n=== Parsing user input ===\n");
	for (int i = 0; i < argc; i++)
	{
		if (!strcmp(argv[i], "-dstip"))
		{
		  dstIp = inet_addr(argv[i+1]);
		  printf("Targeting IP address %s\n", argv[i+1]);
		}
		else if (!strcmp(argv[i], "-srcip"))
		{
		  srcIp = inet_addr(argv[i+1]);
		  printf("Spoofed source IP address %s\n", argv[i+1]);
		}
		else if (!strcmp(argv[i], "-srcmac"))
		{
			sscanf(argv[i+1], "%x:%x:%x:%x:%x:%x", &srcMac[0], &srcMac[1], &srcMac[2], &srcMac[3], &srcMac[4], &srcMac[5]);
			printf("Spoofed source MAC address %x:%x:%x:%x:%x:%x\n", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
		}
		else if (!strcmp(argv[i], "-dstmac"))
		{
			sscanf(argv[i+1], "%x:%x:%x:%x:%x:%x", &dstMac[0], &dstMac[1], &dstMac[2], &dstMac[3], &dstMac[4], &dstMac[5]);
			printf("Targeting MAC address %x:%x:%x:%x:%x:%x\n", dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5]);
		}
		else if (!strcmp(argv[i], "-srcport"))
		{
			srcPort = atoi(argv[i+1]);
			printf("Source port set to %d\n", srcPort);
		}
		else if (!strcmp(argv[i], "-dstport"))
		{
			dstPort = atoi(argv[i+1]);
			printf("Source port set to %d\n", dstPort);
		}
		else if (!strcmp(argv[i], "-intervalmin"))
		{
			intervalMin = atoi(argv[i+1]);
			printf("Set min interpacket delay to %d useconds\n", intervalMin);
		}
		else if (!strcmp(argv[i], "-intervalmax"))
		{
			intervalMax = atoi(argv[i+1]);
			printf("Set max interpacket delay to %d useconds\n", intervalMax);
		}


		else if (!strcmp(argv[i], "-srcportmin"))
		{
			srcPortMin = atoi(argv[i+1]);
			printf("Set min src port to %d\n", srcPortMin);
		}
		else if (!strcmp(argv[i], "-srcportmax"))
		{
			srcPortMax = atoi(argv[i+1]);
			printf("Set max src port to %d\n", srcPortMax);
		}
		else if (!strcmp(argv[i], "-dstportmin"))
		{
			dstPortMin = atoi(argv[i+1]);
			printf("Set min dst port  to %d\n", dstPortMin);
		}
		else if (!strcmp(argv[i], "-dstportmax"))
		{
			dstPortMax = atoi(argv[i+1]);
			printf("Set max dst port to %d\n", dstPortMax);
		}


		else if (!strcmp(argv[i], "-srcipmin"))
		{
			srcIpMin = inet_addr(argv[i+1]);
			printf("Set min src ip to %s\n", argv[i+1]);
		}
		else if (!strcmp(argv[i], "-srcipmax"))
		{
			srcIpMax = inet_addr(argv[i+1]);
			printf("Set max src ip to %s\n", argv[i+1]);
		}
		else if (!strcmp(argv[i], "-dstipmin"))
		{
			dstIpMin = inet_addr(argv[i+1]);
			printf("Set min dst ip  to %s\n", argv[i+1]);
		}
		else if (!strcmp(argv[i], "-dstipmax"))
		{
			dstIpMax = inet_addr(argv[i+1]);
			printf("Set max dst ip to %s\n", argv[i+1]);
		}


		else if (!strcmp(argv[i], "-payloadmin"))
		{
			payloadSizeMin = atoi(argv[i+1]);
			printf("Set min payload size to %d bytes\n", payloadSizeMin);
		}
		else if (!strcmp(argv[i], "-payloadmax"))
		{
			payloadSizeMax = atoi(argv[i+1]);
			printf("Set max payload size to %d bytes\n", payloadSizeMax);
		}
		else if (!strcmp(argv[i], "-packetcount"))
		{
			packetCount = atoi(argv[i+1]);
			printf("Number of packets to send: %d\n", packetCount);
		}

		// Fuzzer options
		else if (!strcmp(argv[i], "-fuzzRandomSrcPort"))
		{
			printf("Randomly fuzzing src port\n");
			fuzzRandom_SrcPort= true;
		}
		else if (!strcmp(argv[i], "-fuzzSequentialSrcPort"))
		{
			printf("Sequentially fuzzing src port\n");
			fuzzSequential_SrcPort = true;
		}
		else if (!strcmp(argv[i], "-fuzzRandomDstPort"))
		{
			printf("Randomly fuzzing dst port\n");
			fuzzRandom_DstPort = true;
		}
		else if (!strcmp(argv[i], "-fuzzSequentialDstPort"))
		{
			printf("Sequentially fuzzing dst port\n");
			fuzzSequential_DstPort = true;
		}
		else if (!strcmp(argv[i], "-fuzzRandomSrcIp"))
		{
			fuzzRandom_SrcIp = true;
		}
		else if (!strcmp(argv[i], "-fuzzSequentialSrcIp"))
		{
			fuzzSequential_SrcIp = true;
		}
		else if (!strcmp(argv[i], "-fuzzRandomDstIp"))
		{
			fuzzRandom_DstIp = true;
		}
		else if (!strcmp(argv[i], "-fuzzSequentialDstIp"))
		{
			fuzzSequential_DstIp = true;
		}
		else if (!strcmp(argv[i], "-fuzzPayloadSize"))
		{
			fuzzPayloadSize = true;
		}
		else if (!strcmp(argv[i], "-fuzzPacketInterval"))
		{
			fuzzPacketInterval = true;
		}



	}
	printf("=== Done parsing user input ===\n\n");



	if (fuzzSequential_SrcIp || fuzzRandom_SrcIp) {srcIp = srcIpMin;}	
	if (fuzzSequential_DstIp || fuzzRandom_DstIp) {dstIp = dstIpMin;}
	if (fuzzSequential_SrcPort || fuzzRandom_SrcPort) {srcPort = srcPortMin;}
	if (fuzzSequential_DstPort || fuzzRandom_DstPort) {dstPort = dstPortMin;}




	unsigned int iseed = (unsigned int)time(NULL);
  	srand (iseed);

	int sockfd;
	int i;
	int payloadSize;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
		perror("socket");

	int tx_len = 0;
	int headersLength = 0;

	// TODO: Enforce 1500 bytes max or UDP packet splitting across several frames
	// The headers are 8 bytes for UDP and 20 bytes for IP
	char sendbuf[2048];
	memset(sendbuf, 0,  2048);

	/* Ethernet frame header */
	struct ether_header *eh = (struct ether_header *) sendbuf;
	for (i = 0; i < 6; i++)
		eh->ether_dhost[i] = dstMac[i];

	for (i = 0; i < 6; i++)
		eh->ether_shost[i] = srcMac[i];

	eh->ether_type = htons(ETH_P_IP);
	headersLength += sizeof(struct ether_header);


	/* IP Header */
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16; // Low delay
	iph->id = htons(54321);
	iph->ttl = 30;
	iph->protocol = 17; // UDP
	/* Destination IP address */
	iph->daddr = dstIp;
	iph->saddr = srcIp;
	headersLength += sizeof(struct iphdr);


	struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
	/* UDP Header */
	udph->source = htons(srcPort);
	udph->dest = htons(dstPort);
	udph->check = 0; // skip
	headersLength += sizeof(struct udphdr);

	/* Packet data */
	// TODO: Allow fuzzing of this
	for (int d = 0; d < payloadSizeMax; d++)
	{
		sendbuf[headersLength + d] = 0x42;
	}

	tx_len = headersLength + payloadSizeMin;

	/* Length of UDP payload and header */
	udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));
	/* Length of IP payload and header */
	iph->tot_len = htons(tx_len - sizeof(struct ether_header));
	/* Calculate IP checksum on completed header */
	iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);


	/* Destination address */
	struct sockaddr_ll socket_address;

	/* Index of the network device */
	// TODO: Throw in an interface command line option
	socket_address.sll_ifindex = if_nametoindex("eth0");
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	for (i = 0; i < 6; i++)
		socket_address.sll_addr[i] = dstMac[i];



	
	printf("=== Sending fuzzed packets ===\n");
	int j = 0;
	for (j = 0; j < packetCount; j++)
	{
		if (fuzzPayloadSize)
		{
			payloadSize = payloadSizeMin + rand()%(payloadSizeMax - payloadSizeMin);
			//printf("Sending payload size %d\n", payloadSize);

			/* Length of UDP payload and header */
			udph->len = htons(headersLength + payloadSize - sizeof(struct ether_header) - sizeof(struct iphdr));
			/* Length of IP payload and header */
			iph->tot_len = htons(headersLength + payloadSize - sizeof(struct ether_header));
			/* Calculate IP checksum on completed header */
			//iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);
		}
		else
		{
			payloadSize = payloadSizeMin;
		}


		// Send the packet we crafted
		/* Calculate IP checksum on completed header */
		iph->check = 0;
		iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);
		if (sendto(sockfd, sendbuf, headersLength + payloadSize, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		{
			printf("Send failed\n");
		}

		// Set up the headers for the next packet
		if (fuzzSequential_SrcIp)
		{
			printf("Fuzzing src ip\n");
			iph->saddr = htonl(ntohl(iph->saddr)+ 1);

			if (iph->saddr == srcIpMax)
			{
				iph->saddr = srcIpMin;
			}
		}
		
		if (fuzzSequential_DstIp)
		{
			iph->daddr = htonl(ntohl(iph->daddr)+ 1);

			if (iph->daddr == dstIpMax)
			{
				iph->daddr = dstIpMin;
			}
		}

		if (fuzzRandom_SrcIp)
		{
			iph->saddr = srcIpMin + rand()%(srcIpMax - srcIpMin);	
		}

		if (fuzzRandom_SrcPort)
		{
			udph->source = htons(srcPortMin + rand()%(srcPortMax - srcPortMin));		
		}

		if (fuzzRandom_DstPort)
		{
			udph->dest = htons(srcPortMin + rand()%(dstPortMax - dstPortMin));		
		}

		if (fuzzSequential_SrcPort)
		{
			srcPort++;
			if (srcPort > srcPortMax)
			{
				srcPort = srcPortMin;
			}
			udph->source = htons(srcPort);
		}

		if (fuzzSequential_DstPort)
		{
			dstPort++;
			if (srcPort > dstPortMax)
			{
				srcPort = dstPortMin;
			}
			udph->dest = htons(dstPort);
		}



		if (fuzzPacketInterval)
		{
			int sleepInterval = intervalMin + rand()%(intervalMax - intervalMin);
			//printf("Sleeping %d\n", sleepInterval);
			usleep(sleepInterval);
		}
		else
		{
			usleep(intervalMin);
		}
	}

	printf("=== Finished! Exiting now ===\n");
	return EXIT_SUCCESS;
}
