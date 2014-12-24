#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/ioctl.h>
#include <net/if.h>

void eth_analyze(char *buffer, int len);
void ip_analyze(char *buffer, int len);
void tcp_analyze(char *buffer, int len);
void udp_analyze(char *buffer, int len);
void arp_analyze(char *buffer, int len);
void rarp_analyze(char *buffer, int len);
void init_pppoe_analyze(char *buffer, int len);
void pppoe_analyze(char *buffer, int len);

int main(int argc,char **argv)
{
	char ethname[10];
	char buffer[ETH_FRAME_LEN];
	int sock,err,n;
	struct ifreq ifr;

	printf("input the ethname(eth0 or wlan0):");
	scanf("%s",ethname);
	if(strcmp(ethname, "eth0") != 0 && strcmp(ethname, "wlan0")){
		perror("ethname error!\n");
		exit(1);
	}

	sock = socket(AF_PACKET, SOCK_PACKET, htons(0x0003));
	if(sock < 0){
		perror("socket error!\n");
		exit(1);
	}

	/*
	**设置网卡为混杂模式
	*/
	strcpy(ifr.ifr_name, ethname);
	err = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if(err < 0){
		perror("ioctl error!\n");
		close(sock);
		exit(1);
	}
	ifr.ifr_flags |= IFF_PROMISC;
	err = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if(err < 0){
		perror("set flags error!\n");
		close(sock);
		exit(1);
	}

	while(1){
		n = recvfrom(sock, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		if(n < 42){
			continue;
		}else{
			printf("-----------------------------------\n");
			eth_analyze(buffer,n);
		}
	}
}


void eth_analyze(char *buffer, int len)
{
	int i;
	struct ethhdr *p_eth = (struct ethhdr*)buffer;

	printf("Receive %d bytes\n",len);
	printf("Destination MAC:");
	for(i = 0; i < ETH_ALEN-1; ++i){
		printf("%02x:",p_eth->h_dest[i]);
	}
	printf("%02x\n",p_eth->h_dest[ETH_ALEN-1]);	
	printf("Source      MAC:");
	for(i = 0; i < ETH_ALEN-1; ++i){
		printf("%02x:",p_eth->h_source[i]);

	}
	printf("%02x\n",p_eth->h_source[ETH_ALEN-1]);

	switch(ntohs(p_eth->h_proto)){
		case 0x0800:
			ip_analyze(buffer,len);
			break;
		case 0x0806:
			arp_analyze(buffer,len);
			break;
		case 0x8035:
			rarp_analyze(buffer,len);
			break;
		case 0x8863:
			init_pppoe_analyze(buffer,len);
			break;
		case 0x8864:
			pppoe_analyze(buffer,len);
			break;
		default:
			printf("Other MAC dates!\n");
	}

}

void ip_analyze(char *buffer, int len)
{
	struct iphdr *p_ip = (struct iphdr*)(buffer + ETH_HLEN);
	printf("Source      IP:%s\n",inet_ntoa(p_ip->saddr));
	printf("Destination IP:%s\n",inet_ntoa(p_ip->saddr));
	switch(p_ip->protocol){
		case 6:
			tcp_analyze(buffer,len);
			break;
		default:
			printf("Other IP dates!\n");
	}
}

void tcp_analyze(char *buffer, int len)
{
	int lenth = 0;
	char *daddr = NULL;
	struct iphdr *p_ip = (struct iphdr*)(buffer + ETH_HLEN);
	struct tcphdr *p_tcp = (struct tcphdr*)(p_ip + p_ip->ihl * 4);
	printf("TCP:\n");
	daddr = (char*)(p_tcp + 20);
	lenth = len - 18 - p_ip->ihl * 4 - 20;
	printf("Date length:%d\n",lenth);
}
void udp_analyze(char *buffer, int len)
{
	printf("UDP dates!\n");
}
void arp_analyze(char *buffer, int len)
{
	printf("ARP dates!\n");
}
void rarp_analyze(char *buffer, int len)
{
	printf("RARP dates!\n");
}
void init_pppoe_analyze(char *buffer, int len)
{
	printf("PPPOE Discovery Stage !\n");
}
void pppoe_analyze(char *buffer, int len)
{
	printf("PPPOE Session Stage!\n");
}

