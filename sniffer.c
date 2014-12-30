#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>

void ip_analyze(char *buffer, int len);
void eth_analyze(char *buffer, int len);
void tcp_analyze(char *buffer, int len);
void udp_analyze(char *buffer, int len);
void arp_analyze(char *buffer, int len);
void egp_analyze(char *buffer, int len);
void igp_analyze(char *buffer, int len);
void icmp_analyze(char *buffer, int len);
void igmp_analyze(char *buffer, int len);
void ipv6_analyze(char *buffer, int len);
void ospf_analyze(char *buffer, int len);
void rarp_analyze(char *buffer, int len);
void pppoe_analyze(char *buffer, int len);
void init_pppoe_analyze(char *buffer, int len);

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

	printf("Capture %d bytes\n",len);
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
	printf("Destination IP:%s\n",inet_ntoa(p_ip->daddr));
	switch(p_ip->protocol){
		case 1:
			icmp_analyze(buffer,len);
			break;
		case 2:
			igmp_analyze(buffer,len);
			break;
		case 6:
			tcp_analyze(buffer,len);
			break;
		case 8:
			egp_analyze(buffer,len);
			break;
		case 9:
			igp_analyze(buffer,len);
			break;
		case 17:
			udp_analyze(buffer,len);
			break;
		case 41:
			ipv6_analyze(buffer,len);
			break;
		case 89:
			ospf_analyze(buffer,len);
			break;		
		default:
			printf("Other IP dates!\n");
	}
}

void tcp_analyze(char *buffer, int len)
{
	int lenth = 0;
	struct iphdr *p_ip = (struct iphdr*)(buffer + ETH_HLEN);
	struct tcphdr *p_tcp = (struct tcphdr*)(p_ip + p_ip->ihl * 4);
	/*
	char *daddr = NULL;
	daddr = (char*)(p_tcp + 20);
	*/
	lenth = len - 18 - p_ip->ihl * 4 - 20;
	printf("TCP :\n");
	printf("Src  Port:%d\n",ntohs(p_tcp->source));
	printf("Dest Port:%d\n",ntohs(p_tcp->dest));
	printf("Date length:%d\n",lenth);
}
void udp_analyze(char *buffer, int len)
{
	int lenth = 0;
	struct iphdr *p_ip = (struct iphdr*)(buffer + ETH_HLEN);
	struct udphdr *p_udp = (struct udphdr*)(p_ip + p_ip->ihl * 4);
	/*
	char *daddr = NULL;
	daddr = (char*)(p_udp + p_udp->len);
	*/
	lenth = len - 18 - p_ip->ihl * 4 - 8;
	printf("UDP :\n");
	printf("Src  Port:%d\n",ntohs(p_udp->source));
	printf("Dest Port:%d\n",ntohs(p_udp->dest));
	printf("Date length:%d\n",lenth);
	
}
void arp_analyze(char *buffer, int len)
{
	/*
	** arp数据：硬件类型(2)+协议类型(2)+硬件地址长度(1)+协议地址长度(1)+操作方式(2)
	**     +发送方硬件地址(6)+发送方协议地址(4)+接收方硬件地址(6)+接收方协议地址(4) 	
	*/
	struct arphdr *p_arp = (struct arphdr*)(buffer + ETH_HLEN);
	printf("ARP :\n");
	switch(ntohs(p_arp->ar_op)){
		case 1:
			printf("ARP request!\n");
			break;
		case 2:
			printf("ARP reply!\n");
			break;
		default:	
			printf("others ARP!\n");
	}
}
void icmp_analyze(char *buffer, int len)
{	
	printf("ICMP dates\n");	
}

void rarp_analyze(char *buffer, int len)
{
	printf("RARP dates!\n");
}
void init_pppoe_analyze(char *buffer, int len)
{
	printf("PPPoE Discovery Stage !\n");
}
void pppoe_analyze(char *buffer, int len)
{
	printf("PPPoE Session Stage!\n");
}
void igmp_analyze(char *buffer, int len)
{
	printf("igmp dates!\n");
}
void egp_analyze(char *buffer, int len)
{
	printf("egp dates!\n");
}
void igp_analyze(char *buffer, int len)
{
	printf("igp dates!\n");
}
void ipv6_analyze(char *buffer, int len)
{
	printf("ipv6 dates!\n");
}
void ospf_analyze(char *buffer, int len)
{
	printf("ospf dates!\n");
}


