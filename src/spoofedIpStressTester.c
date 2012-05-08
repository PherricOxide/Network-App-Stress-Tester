/*
 ============================================================================
 Name        : spoofedIpStressTester.c
 Author      : PherricOxide
 Description : Network application stress testing tool for sending large amounts
 of UDP packets with spoofed source and MAC addresses to a host with known IP and MAC.

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


#define FuzzSrcIp 0
#define FuzzPayloadSize 1
#define FuzzPacketInterval 2

// Defaults (probably not what you want, make sure to enter real values in args)
u_int8_t srcMac[] = {0x22,0x33,0x44,0x55,0x66,0x77};
u_int16_t srcPort = 42;
u_int16_t dstPort = 42;

u_int8_t dstMac[6];
char *destIp;
char *srcIp = "192.168.10.42";

int packetCount = 0;

// In useconds
int intervalMin = 5000;
int intervalMax = 5001;

// In bytes
int payloadSizeMin = 10;
int payloadSizeMax = 11;


int fuzzmask = 0;



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
	    printf("-dstport x\n\n");
	    printf("-payloadmin x\n");
	    printf("-payloadmax x\n\n");
	    printf("-intervalmin x\n");
	    printf("-intervalmax x\n\n");
	    printf("-packetcount x\n\n");

	    printf("-fuzzmask x\n");
		printf("Fuzz bitmask bit names options,\n");
		printf("    FuzzSrcIp %d\n", FuzzSrcIp);
		printf("    FuzzPayloadSize %d\n", FuzzPayloadSize);
		printf("    FuzzPacketInterval %d\n", FuzzPacketInterval);


		printf("\nNeed more help? Use the source Luke.\n");
		return -1;
	}

	// Error checking? Nope. Don't enter inputs wrong, this is quick and dirty and will explode
	printf("\n=== Parsing user input ===\n");
	for (int i = 0; i < argc; i++)
	{
		if (!strcmp(argv[i], "-dstip"))
		{
		  destIp = argv[i+1];
		  printf("Targeting IP address %s\n", destIp);
		}
		else if (!strcmp(argv[i], "-srcip"))
		{
		  srcIp = argv[i+1];
		  printf("Spoofed source IP address %s\n", srcIp);
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
		else if (!strcmp(argv[i], "-fuzzmask"))
		{
			// TODO: Make this input useable for normal people (eg people who can't compute bitmasks in their head)
			fuzzmask = atoi(argv[i+1]);
			printf("Fuzzmask is : %d\n", fuzzmask);
		}

	}
	printf("=== Done parsing user input ===\n\n");


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
	iph->daddr = inet_addr(destIp);
	iph->saddr = inet_addr(srcIp);
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


	// Initialize fuzzer stuff
	if (fuzzmask & (1 << FuzzSrcIp))
	{
		iph->saddr = 0;
	}


	int j = 0;
	for (j = 0; j < packetCount; j++)
	{
		if (fuzzmask & (1 << FuzzPayloadSize))
		{
			payloadSize = payloadSizeMin + rand()%(payloadSizeMax - payloadSizeMin);
			//printf("Sending payload size %d\n", payloadSize);

			/* Length of UDP payload and header */
			udph->len = htons(headersLength + payloadSize - sizeof(struct ether_header) - sizeof(struct iphdr));
			/* Length of IP payload and header */
			iph->tot_len = htons(headersLength + payloadSize - sizeof(struct ether_header));
			/* Calculate IP checksum on completed header */
			iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);
		}
		else
		{
			payloadSize = payloadSizeMin;
		}


		// Send the packet we crafted
		if (sendto(sockfd, sendbuf, headersLength + payloadSize, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		{
			printf("Send failed\n");
		}

		// Set up the headers for the next packet
		if (fuzzmask & (1 << FuzzSrcIp))
		{
			iph->saddr = htonl(ntohl(iph->saddr)+ 1);
			//printf("Sending from IP %d\n", iph->saddr);
		}


		if (fuzzmask & (1 << FuzzPacketInterval))
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

	return EXIT_SUCCESS;
}
