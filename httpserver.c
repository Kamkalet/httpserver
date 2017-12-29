#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For
#include<stdlib.h>    //m
#include<string.h>    //s
 
#include <netinet/icmp6.h> //Pro
#include <netinet/udp.h>   //Pr
#include<netinet/tcp.h>  
#include<netinet/ip6.h>    
#include<netinet/if_ether.h>  //For ETH_P_IP
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <inttypes.h>

#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<errno.h>

#include<sys/socket.h>
#include<sys/types.h>
#include<sys/ioctl.h>

#include<net/if.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<netinet/udp.h>

#include<linux/if_packet.h>

#include<arpa/inet.h>

	// data for MAC address of server device
 //b8:27:eb:08:8d:65 
 #define DESTMAC0	0xb8
 #define DESTMAC1	0x27
 #define DESTMAC2	0xeb
 #define DESTMAC3	0x08
 #define DESTMAC4	0x8d
 #define DESTMAC5	0x65
 struct sockaddr_ll sadr_ll;

// data from IPv6
struct in6_addr ip6_src;	/* source address */
struct in6_addr ip6_dst;	/* destination address */

// funs
void service_error(char *message);
void process_packet(unsigned char* buffer, int size, int dsc);
void print_ethernet_header(unsigned char* buffer, int size);
void print_ip6_header(unsigned char* buffer, int size);
void print_icmp6_packet(unsigned char* buffer , int size);
void print_tcp_packet(unsigned char* buffer , int size);
int create_socket();
void send_icmp6_answer(unsigned char* buffer, int socket_desc);
uint16_t checksum (void * buffer, int bytes);
void print_packet_in_hex(int start, int end, char* packet);

// data received from socket about source...
struct sockaddr destination;
int addr_size;

//begin the suffering
int main (int argc, char **argv)
{
	printf("Starting server\n");
	
	printf("%d\n", sizeof(struct icmp6_hdr));

	int socket_desc_rcv = create_socket();
	int socket_desc_send = create_socket();
	unsigned char *buffer;

	printf("Starting receiving...\n");
	
	int bytes;
	//data saved after receiving
	buffer = (unsigned char *) malloc (1000* sizeof (unsigned char));
	memset(buffer,0, 1000);
	
	//RECEIVING
	while(1){
		if ((bytes = recvfrom (socket_desc_rcv, (void*)buffer, 1000, 0, &destination, &addr_size)) < 0)  {
			service_error("recvfrom() failed ");
		}else{

			printf("%x", buffer);
			process_packet(buffer, bytes, socket_desc_send);
		
		}
	}
	
	free(buffer);
	return (EXIT_SUCCESS);
}

void service_error(char *message){
	
	perror(message);
	exit (1);
	
}

int create_socket(){
	
	int socket_desc;
	struct ifreq ifr;
	
	// create raw socket for basic packets and sniffing ethernet packets
	if (((socket_desc = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)) 
		service_error("Error receiving listening socket desc: ");
		
	// binding socket to interface eth0
	memset(&ifr, 0, sizeof(struct ifreq));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "eth0");
	ioctl(socket_desc, SIOCGIFINDEX, &ifr);
	
	char *devname = "eth0";
	if(setsockopt(socket_desc, SOL_SOCKET, SO_BINDTODEVICE,  devname, 4)<0){
		service_error("Error binding");
	}
	
	return socket_desc;
	
}

void process_packet(unsigned char* buffer, int size, int dsc)
{

    struct ip6_hdr *ip6h = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));

    switch ((unsigned int)ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt) //Check the Protocol and do accordingly...
    {
        case 58:  //ICMPv6 Protocol
            print_icmp6_packet( buffer , size);
            send_icmp6_answer(buffer, dsc);
            break;
        case 6:  //TCP Protocol
            //print_tcp_packet(buffer , size);
            break;
        default: 
            //print_icmp6_packet( buffer , size);
            break;
    }

}

void send_icmp6_answer(unsigned char* buffer, int socket_desc){
	
	struct ethhdr *eth = (struct ethhdr *)buffer;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
	struct icmp6_hdr *icmph6 = (struct icmp6_hdr *)(buffer + 40 + sizeof(struct ethhdr));
	
	struct ifreq ifreq_i;
	strncpy(ifreq_i.ifr_name, "eth0", IFNAMSIZ-1);
	if((ioctl(socket_desc, SIOCGIFINDEX, &ifreq_i))<0){
			service_error("error indexing");
	}

	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
	sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
	sadr_ll.sll_addr[0] = DESTMAC0;
	sadr_ll.sll_addr[1] = DESTMAC1;
	sadr_ll.sll_addr[2] = DESTMAC2;
	sadr_ll.sll_addr[3] = DESTMAC3;
	sadr_ll.sll_addr[4] = DESTMAC4;
	sadr_ll.sll_addr[5] = DESTMAC5;
	
	//packet to be sent
	unsigned char packet[4096];
	memset (packet, 0, 4096);
	
	struct ethhdr *eth_send = malloc(sizeof(struct ethhdr));
	struct ip6_hdr *ip6h_send = malloc(sizeof(struct ip6_hdr));
	
	struct nd_neighbor_advert *na = malloc(sizeof(struct nd_neighbor_advert));

	memcpy(eth_send->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth_send->h_source, sadr_ll.sll_addr, ETH_ALEN);
	eth_send->h_proto = htons(ETH_P_IPV6);
	
	int a = 24;
	memcpy(&ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_flow, &ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow, sizeof(uint32_t));
	memcpy(&ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_plen, &ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen, sizeof(uint16_t));
	memcpy(&ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_nxt, &ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt, sizeof(uint8_t));
	memcpy(&ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_hlim, &ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim, sizeof(uint8_t));
	memcpy(&ip6h_send->ip6_ctlun.ip6_un2_vfc, &ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
	memcpy(&ip6h_send->ip6_src, &ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
	memcpy(&ip6h_send->ip6_dst, &ip6h->ip6_src, sizeof(struct in6_addr));
	memcpy(&ip6h_send->ip6_src, &ip6h->ip6_dst, sizeof(struct in6_addr));
	inet_pton(AF_INET6, "fe80::b0cc:7ba1:3f07:4b14", &ip6h_send->ip6_src);
	inet_pton(AF_INET6, "fe80::b0cc:7ba1:3f07:4b14", &na->nd_na_target);
	
	na->nd_na_hdr.icmp6_type = 136; // advestisement neghtbor
	na->nd_na_hdr.icmp6_code = 0; 

	na->nd_na_hdr.icmp6_cksum = htons(0xf432);
	na->nd_na_hdr.icmp6_dataun.icmp6_un_data8[0] = 0x06; // for O ans S flags

	
	memcpy(packet, eth_send, sizeof(struct ethhdr));
	memcpy(packet+sizeof(struct ethhdr), ip6h_send, sizeof(struct ip6_hdr));
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr), na, sizeof(struct nd_neighbor_advert));
	
	int target_link_layer_address = 0x02;
	int length = 0x01;
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) , &target_link_layer_address, 1);
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) + 1, &length, 1);
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) + 2, sadr_ll.sll_addr, 6);
	
	int bytes;
	
	if (bytes = sendto(socket_desc, packet,  sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) + 8, 0, (const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll)) < 0)
    {
		service_error("sendto failed");
    }
   
   	 printf("%d\n", bytes);
		    exit(1);

}

uint16_t
checksum (void * buffer, int bytes) {
   uint32_t   total;
   uint16_t * ptr;
   int        words;

   total = 0;
   ptr   = (uint16_t *) buffer;
   words = (bytes + 1) / 2; // +1 & truncation on / handles any odd byte at end

   /*
    *   As we're using a 32 bit int to calculate 16 bit checksum
    *   we can accumulate carries in top half of DWORD and fold them in later
    */
   while (words--) total += *ptr++;

   /*
    *   Fold in any carries
    *   - the addition may cause another carry so we loop
    */
   while (total & 0xffff0000) total = (total >> 16) + (total & 0xffff);

   return (uint16_t) total;
}

void print_packet_in_hex(int start, int end, char* packet){
	
	printf("\n");
	int i = start;

	for (i = 0 & ~15; i < end; i++)
	{
		if ((i & 15) == 0) 
			printf("%04x ",i);
		printf((i<0)?"   ":"%02x%c",(unsigned char)packet[i],((i+1)&15)?' ':'\n');
	}
	if ((i & 15) != 0)
    printf("\n");
    
}


void print_ethernet_header(unsigned char* buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
     
    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : 0x%x \n", htons(eth->h_proto));
    
}

void print_ip6_header(unsigned char* buffer, int size)
{
    print_ethernet_header(buffer , size);
   
    unsigned short ip6_hdrlen = 40;
         
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
     
    memset(&ip6_src, 0, sizeof(struct in6_addr));
    memcpy(&ip6_src, &ip6h->ip6_src, INET6_ADDRSTRLEN);
    //ip6_src.s6_addr = ip6h->ip6_src.s6_addr;

     
    memset(&ip6_dst, 0, sizeof(struct in6_addr));
    memcpy(&ip6_dst, &ip6h->ip6_dst, INET6_ADDRSTRLEN);

    printf("\n");

	//user-fiendly ipv6 address
	char source[INET6_ADDRSTRLEN];
	char destination[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip6_src, source, sizeof(source));
	inet_ntop(AF_INET6, &ip6_dst, destination, sizeof(destination));
	
	
    printf("IPv6 Header\n");
    printf("   |-Version,class,flow: %u\n", (unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow));
    printf("   |-Payload length    : %d\n", (unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen));
    printf("   |-Next header       : %u\n", (unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt));
    printf("   |-Hop limit         : %u\n", (unsigned int) ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    printf("   |-Source IP         : %s\n", source);
    printf("   |-Destination IP    : %s\n", destination);
    
}

void print_icmp6_packet(unsigned char* buffer , int size)
{
	// always 40 bytes
    unsigned short ip6_hdrlen = 40;
     
    struct ip6_hdr *iph6 = (struct ip6_hdr *)(buffer  + sizeof(struct ethhdr));
     
    struct icmp6_hdr *icmph6 = (struct icmp6_hdr *)(buffer + ip6_hdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + ip6_hdrlen + sizeof icmph6;
     
    printf("\n\n***********************ICMP Packet*************************\n"); 
     
    print_ip6_header(buffer , size);
       
    printf("\n");
    printf("ICMP Header\n");
    printf("   |-Type : %d",(unsigned int)(icmph6->icmp6_type));
    printf("   |-Code : %d\n",(unsigned int)(icmph6->icmp6_code));
    printf("   |-Checksum : 0x%x\n",ntohs(icmph6->icmp6_cksum));
	printf("   |-Some data : 0x%x\n",(unsigned int)(icmph6->icmp6_dataun.icmp6_un_data32));
    printf("\n");
    printf("\n###########################################################");
    
}

void print_tcp_packet(unsigned char* buffer, int size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;

    struct tcphdr *tcph = (struct tcphdr*)(buffer + 40 + sizeof(struct ethhdr));
             
    printf("\n\n***********************TCP Packet*************************\n");    
         
    print_ip6_header(buffer,size);
         
    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : 0x%04x\n", ntohl(tcph->seq));
    printf("   |-Acknowledge Number : 0x%04x\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    //printf("\n");
    //printf("                        DATA Dump                         ");
    //printf("\n");
         
    //printf(logfile,"IP Header\n");
    //PrintData(Buffer,iphdrlen);
         
    //fprintf(logfile,"TCP Header\n");
    //PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    //fprintf(logfile,"Data Payload\n");  
    //PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                         
    printf("\n###########################################################");
}
