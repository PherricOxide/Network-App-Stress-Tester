/*
 ============================================================================
 Name		 : FAST: Fuzzing Application Stress Tester
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
#include <linux/icmp.h>

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
uint8_t srcMac[6];
uint8_t dstMac[6];

uint32_t dstIp;
uint32_t dstIpMin = 1;
uint32_t dstIpMax = ~0;

uint32_t srcIp;
uint32_t srcIpMin = 1;
uint32_t srcIpMax = ~0;

int packetCount = 0;

// In useconds
int interval = 5000;
int intervalMin = 1000;
int intervalMax = 10000;

// In bytes
int payloadSize = 1;
int payloadSizeMin = 1;
int payloadSizeMax = 1000;

uint16_t srcPort = 0;
uint16_t srcPortMin = 0;
uint16_t srcPortMax = 65535;

uint16_t dstPort = 0;
uint16_t dstPortMin = 0;
uint16_t dstPortMax = 65535;

char * dstIpString;

inline unsigned short csum(unsigned short *buf, int bytes)
{
	unsigned long sum;
	for(sum=0; bytes>1; bytes -= 2)
		sum += *buf++;
	if (bytes)
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

int main(int argc, char **argv)
{

	if (argc < 2) {
		printf("Usage options (may not apply to all fuzzing types),\n");
	    printf("-srcip x.x.x.x\n");
	    printf("-srcipmin x.x.x.x\n");
	    printf("-srcipmax x.x.x.x\n\n");
	    
		printf("-dstip x.x.x.x\n");
		printf("-dstipmin x.x.x.x\n");
		printf("-dstipmax x.x.x.x\n\n");

	    printf("-srcmac xx:xx:xx:xx:xx:xx\n");
	    printf("-dstmac xx:xx:xx:xx:xx:xx\n\n");
	    
		printf("-srcport x\n");
		printf("-srcportmin x\n");
		printf("-srcportmax x\n\n");

	    printf("-dstport x\n");
	    printf("-dstportmin x\n");
	    printf("-dstportmax x\n\n");
	    
		printf("-payload x\n");
		printf("-payloadmin x\n");
	    printf("-payloadmax x\n\n");
	    
		printf("-interval x\n");
		printf("-intervalmin x\n");
		printf("-intervalmax x\n\n");
	    

		printf("Fuzzer options\n");
		printf("-fuzz[Random|Sequential]SrcPort\n");
		printf("-fuzz[Random|Sequential]DstPort\n");
		printf("-fuzz[Random|Sequential]SrcIp\n");
		printf("-fuzz[Random|Sequential]DstIp\n\n");
		
		printf("-fuzzPayloadSize\n\n");
		printf("-fuzzPacketInterval\n\n");
		
		printf("-packetcount x\n\n");


		printf("\nNeed more help? Use the source Luke.\n");
		return -1;
	}

	// Fills the srcMac array in with the MAC address of the machine
	// you are on. If the -srcmac <address> option is used, it will simply
	// overwrite this array with the new chosen MAC address to spoof with.

	unsigned int s0,s1,s2,s3,s4,s5;

	FILE * file = fopen("/sys/class/net/vboxnet0/address", "r");

	if(file != NULL)
	{
		fscanf(file, "%x:%x:%x:%x:%x:%x", &s0,&s1,&s2,&s3,&s4,&s5);
		srcMac[0] = (uint8_t)s0;
		srcMac[1] = (uint8_t)s1;
		srcMac[2] = (uint8_t)s2;
		srcMac[3] = (uint8_t)s3;
		srcMac[4] = (uint8_t)s4;
		srcMac[5] = (uint8_t)s5;
	}

	fclose(file);

	// Error checking? Nope. Don't enter inputs wrong, this is quick and dirty and will explode
	printf("\n=== Parsing user input ===\n");
	for (int i = 0; i < argc; i++)
	{
		//printf("Parsing arg %s\n", argv[i]);
		if (argv[i][0] == '-') 
		{
			if (!strcmp(argv[i], "-dstip"))
			{
				dstIpString = argv[i + 1];
				dstIp = inet_addr(argv[i+1]);
				printf("Targeting IP address '%s' is '%d'\n", argv[i+1], dstIp);

				// Fills the dstMac array dynamically s.t. the dstMac
				// flag must needs only be called when the machine
				// in question lies outside the local ethernet segment
				// Nota bene: if the -dstMac flag is called before 
				// the -dstip flag is, the address will be overwritten below;
				// conversely, if the -dstip is called first, -dstmac will
				// overwrite the result of the code below.
				// Must be given after -srcip

				struct icmphdr* icmp;
				struct sockaddr_in connection;
				int found = 0;
				unsigned int d0,d1,d2,d3,d4,d5;
				int sockfd;
				int optval;	
				size_t nbytes = 256;
				char* line;
				char* pch;
				char* packet = (char *)calloc(1, sizeof(struct icmphdr));
				icmp = (struct icmphdr*) (packet);

				if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
				{
					perror("socket");
					free(packet);
					continue;
				}

				setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

				icmp->type = ICMP_ECHO;
				icmp->code = 0;
				icmp->un.echo.id = random();
				icmp->un.echo.sequence = 0;
				icmp->checksum = 0;
				icmp->checksum = csum((unsigned short *)icmp, sizeof(struct icmphdr));
				
				connection.sin_family = AF_INET;
				connection.sin_addr.s_addr = dstIp;

				sendto(sockfd, packet, sizeof(struct icmphdr), 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
				sendto(sockfd, packet, sizeof(struct icmphdr), 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));

				close(sockfd);
				free(packet);

				sleep(1);

				FILE * file = fopen("/proc/net/arp", "r");
				
				line = (char *) malloc(nbytes + 1);	

				while(getline(&line, &nbytes, file) > 0)
				{
					pch = strtok(line, " \t\n");

					if(!strcmp(pch, dstIpString))
					{
						pch = strtok(NULL, " \t\n");
						pch = strtok(NULL, " \t\n");
						pch = strtok(NULL, " \t\n");

						sscanf(pch, "%x:%x:%x:%x:%x:%x", &d0,&d1,&d2,&d3,&d4,&d5);

						dstMac[0] = (uint8_t)d0;
						dstMac[1] = (uint8_t)d1;
						dstMac[2] = (uint8_t)d2;
						dstMac[3] = (uint8_t)d3;
						dstMac[4] = (uint8_t)d4;
						dstMac[5] = (uint8_t)d5;

						found = 1;
	
						break;
					}
				}

				fclose(file);

				free(line);

				printf("Targeting MAC address %x:%x:%x:%x:%x:%x\n", dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5]);
			}
			else if (!strcmp(argv[i], "-srcip"))
			{
				srcIp = inet_addr(argv[i+1]);
				printf("Spoofed source IP address %s\n", argv[i+1]);
			}
			else if (!strcmp(argv[i], "-srcmac"))
			{
				unsigned int d0,d1,d2,d3,d4,d5;

				sscanf(argv[i + 1], "%x:%x:%x:%x:%x:%x", &d0,&d1,&d2,&d3,&d4,&d5);
				srcMac[0] = (uint8_t)d0;
				srcMac[1] = (uint8_t)d1;
				srcMac[2] = (uint8_t)d2;
				srcMac[3] = (uint8_t)d3;
				srcMac[4] = (uint8_t)d4;
				srcMac[5] = (uint8_t)d5;

				printf("Spoofed source MAC address %x:%x:%x:%x:%x:%x\n", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
			}
			else if (!strcmp(argv[i], "-dstmac"))
			{
				unsigned int d0,d1,d2,d3,d4,d5;

				sscanf(argv[i+1], "%x:%x:%x:%x:%x:%x", &d0,&d1,&d2,&d3,&d4,&d5);

				dstMac[0] = (uint8_t)d0;
				dstMac[1] = (uint8_t)d1;
				dstMac[2] = (uint8_t)d2;
				dstMac[3] = (uint8_t)d3;
				dstMac[4] = (uint8_t)d4;
				dstMac[5] = (uint8_t)d5;

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
			else if (!strcmp(argv[i], "-interval"))
			{
				interval = atoi(argv[i+1]);
				printf("Set interpacket delay to %d useconds\n", interval);
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

			else if (!strcmp(argv[i], "-payload"))
			{
				payloadSize = atoi(argv[i+1]);
				printf("Set payload size to %d bytes\n", payloadSize);
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
			else
			{
				printf("\nERROR: option '%s' is not recognized! Please see usage instructions\n\n", argv[i]);
				return -1;
			}
		}

	}

	printf("=== Done parsing user input ===\n\n");

	if (fuzzSequential_SrcIp || fuzzRandom_SrcIp) {srcIp = srcIpMin;}	
	if (fuzzSequential_DstIp || fuzzRandom_DstIp) {dstIp = dstIpMin;}
	if (fuzzSequential_SrcPort || fuzzRandom_SrcPort) {srcPort = srcPortMin;}
	if (fuzzSequential_DstPort || fuzzRandom_DstPort) {dstPort = dstPortMin;}

	printf("Targeting IP address '%d'\n", dstIp);

	unsigned int iseed = (unsigned int)time(NULL);
	srand (iseed);

	int sockfd;
	int i;

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

	tx_len = headersLength + payloadSize;

	/* Length of UDP payload and header */
	udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));
	/* Length of IP payload and header */
	iph->tot_len = htons(tx_len - sizeof(struct ether_header));
	/* Calculate IP checksum on completed header */
	iph->check = 0;
	iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr));


	/* Destination address */
	struct sockaddr_ll socket_address;

	/* Index of the network device */
	// TODO: Throw in an interface command line option
	socket_address.sll_ifindex = if_nametoindex("vboxnet1");
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
			//iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr));
		}


		// Send the packet we crafted
		/* Calculate IP checksum on completed header */
		iph->check = 0;
		iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr));
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
			iph->saddr = htonl(ntohl(srcIpMin) + rand()%(ntohl(srcIpMax) - ntohl(srcIpMin)));	
		}

		if (fuzzRandom_DstIp)
		{
			iph->daddr = htonl(ntohl(dstIpMin) + rand()%(ntohl(dstIpMax) - ntohl(dstIpMin)));	
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
			usleep(interval);
		}
	}

	printf("=== Finished! Exiting now ===\n");
	return EXIT_SUCCESS;
}
