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

// Change these values for you own network
u_int8_t destMac[] = {0x00,0x23,0xae,0x6f,0x97,0x08};
u_int8_t srcMac[] = {0x22,0x33,0x44,0x55,0x66,0x77};
char *destIp = "192.168.3.147";

inline unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

int main(int argc, char **argv) {
	int sockfd;
	int i;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
		perror("socket");

	int tx_len = 0;
	char sendbuf[1024];
	memset(sendbuf, 0, 1024);

	/* Ethernet header */
	struct ether_header *eh = (struct ether_header *) sendbuf;
	for (i = 0; i < 6; i++)
		eh->ether_dhost[i] = destMac[i];

	for (i = 0; i < 6; i++)
		eh->ether_shost[i] = srcMac[i];

	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);


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
	tx_len += sizeof(struct iphdr);


	struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
	/* UDP Header */
	udph->source = htons(3423);
	udph->dest = htons(5342);
	udph->check = 0; // skip
	tx_len += sizeof(struct udphdr);

	/* Packet data */
	sendbuf[tx_len++] = 0xde;
	sendbuf[tx_len++] = 0xad;
	sendbuf[tx_len++] = 0xbe;
	sendbuf[tx_len++] = 0xef;

	/* Length of UDP payload and header */
	udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));
	/* Length of IP payload and header */
	iph->tot_len = htons(tx_len - sizeof(struct ether_header));
	/* Calculate IP checksum on completed header */
	iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);


	/* Destination address */
	struct sockaddr_ll socket_address;

	/* Index of the network device */
	socket_address.sll_ifindex = if_nametoindex("eth0");
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	for (i = 0; i < 6; i++)
		socket_address.sll_addr[i] = destMac[i];

	iph->saddr = 1;
	int j = 0;
	for (j = 0; j < INT_MAX; j++)
	{
		if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");
		iph->saddr++;

		if (j % 100 == 0)
		{
			printf("Sending packet #%d. Press a key to continue\n", j);
			getchar();
			printf("Going...\n");
		}

		usleep(5000);

	}

	return EXIT_SUCCESS;
}
