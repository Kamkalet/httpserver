
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>    
#include <string.h>    
 
#include <netinet/in.h>
#include <netinet/icmp6.h> 
#include <netinet/udp.h>   
#include <netinet/tcp.h>  
#include <netinet/ip6.h>    
#include <netinet/if_ether.h>  
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <inttypes.h>

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/if_ether.h>

#include <linux/if_packet.h>

#include <arpa/inet.h>

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
void send_tcp_ACK(unsigned char* buffer, int socket_desc);
void service_error(char *message);
void process_packet(unsigned char* buffer, int size, int dsc);
void print_ethernet_header(unsigned char* buffer, int size);
void print_ip6_header(unsigned char* buffer, int size);
void print_icmp6_packet(unsigned char* buffer , int size);
void print_tcp_packet(unsigned char* buffer , int size);
int create_socket();
void send_icmp6_answer(unsigned char* buffer, int socket_desc);

uint16_t
checksum (uint16_t *addr, int len);
void print_packet_in_hex(int start, int end, char* packet);
void send_tcp_answer(unsigned char* buffer, int socket_desc);

//buff holds either data or options (or both)
int calculate_tcp_checksum(struct ip6_hdr *ip6h_send ,struct tcphdr *tcp_send , char *options, int buffsize);

uint16_t
tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr,char *options);


// data received from socket about source...
struct sockaddr destination;
int addr_size;

//begin the suffering
int main (int argc, char **argv)
{
	printf("Starting server\n");

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
            print_tcp_packet(buffer , size);
            
            struct tcphdr *tcph = (struct tcphdr*)(buffer + 40 + sizeof(struct ethhdr));

            // if its first packet in handshaking, send SYN, ACK
            if(tcph->ack == 0) send_tcp_answer(buffer, dsc);
            
            // if HTTP Request is received ( must be PUSH flag on, and
            // HTTP port is the source
            else if(tcph->psh==1 && ntohs(tcph->dest) == 80)
				send_tcp_ACK(buffer, dsc);
            
            break;
        default: 
            //print_icmp6_packet( buffer , size);
            break;
    }

}

uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;
  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
	sum += *(addr++);
	count -= 2;
  }
  // Add left-over byte, if any.
  if (count > 0) {
	sum += *(uint8_t *) addr;
  }
  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
	sum = (sum & 0xffff) + (sum >> 16);
  }
  // Checksum is one's compliment of sum.
  answer = ~sum;
  return (answer);
}

void send_tcp_ACK(unsigned char* buffer, int socket_desc){

    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr*)(buffer + 40 + sizeof(struct ethhdr));
      
    // retrievieng data of the interface
    struct ifreq ifreq_i;
    strncpy(ifreq_i.ifr_name, "eth0", IFNAMSIZ-1);
    if((ioctl(socket_desc, SIOCGIFINDEX, &ifreq_i))<0){
        service_error("error indexing");
    }
	
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
    sadr_ll.sll_halen = ETH_ALEN; // length of the mac address
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
    struct tcphdr *tcp_send = malloc(sizeof(struct tcphdr));
    memset(tcp_send, 0, sizeof(struct tcphdr));

	//ETHERNET section
    memcpy(eth_send->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth_send->h_source, sadr_ll.sll_addr, ETH_ALEN);
    eth_send->h_proto = htons(ETH_P_IPV6);

	// IPv6 section
    ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60002ecf);
    
    // THIS CHANGES
    ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(20);
    
    memcpy(&ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_nxt, &ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt, sizeof(uint8_t));
    ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64; // was 128
    memcpy(&ip6h_send->ip6_ctlun.ip6_un2_vfc, &ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
    memcpy(&ip6h_send->ip6_src, &ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
    
    memcpy(&ip6h_send->ip6_dst, &ip6h->ip6_src, sizeof(struct in6_addr));
    memcpy(&ip6h_send->ip6_src, &ip6h->ip6_dst, sizeof(struct in6_addr));
    inet_pton(AF_INET6, "fe80::b0cc:7ba1:3f07:4b14", &ip6h_send->ip6_src);
    
    // TCP section
    memcpy(&tcp_send->dest, &tcph->source, sizeof(u_short));
    tcp_send->source = htons(80);
    
    //*THIS part changer from the other
    memcpy(&tcp_send->seq, &tcph->ack_seq, sizeof(tcp_seq)); // sequence number (u_long)
    memcpy(&tcp_send->ack_seq, &tcph->seq, sizeof(uint32_t)); 
    
    // and THIS FLAG
    tcp_send->doff = 5;
    
    tcp_send->urg = 0;
    tcp_send->ack = 1;
    tcp_send->psh = 0;
    tcp_send->rst = 0;
    
    // and THIS
    tcp_send->syn = 0;
    tcp_send->fin = 0;
    
    //AND THIS
	tcp_send->window = htons(234);
	
	tcp_send->check = 0;
	tcp_send->urg_ptr = 0;
	
	// NO OPTIONS NOR DATA
	
	// AND THIS CHANGES
	tcp_send->check = calculate_tcp_checksum(ip6h_send, tcp_send, NULL,0);
	
    memcpy(packet, eth_send, sizeof(struct ethhdr));
	memcpy(packet+sizeof(struct ethhdr), ip6h_send, sizeof(struct ip6_hdr));
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr), tcp_send, sizeof(struct tcphdr)); //TCP

    int bytes;
	printf("\n\n\nSending TCP packet\n");
	if (bytes = sendto(socket_desc, packet,  sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) ,0 , (const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll)) < 0)
    {
		service_error("sendto failed: ");
    }
        
    free(eth_send);
    free(ip6h_send);
    free(tcp_send);

}


void send_tcp_answer(unsigned char* buffer, int socket_desc){


    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr*)(buffer + 40 + sizeof(struct ethhdr));
      
    // retrievieng data of the interface
    struct ifreq ifreq_i;
    strncpy(ifreq_i.ifr_name, "eth0", IFNAMSIZ-1);
    if((ioctl(socket_desc, SIOCGIFINDEX, &ifreq_i))<0){
        service_error("error indexing");
    }
	
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
    sadr_ll.sll_halen = ETH_ALEN; // length of the mac address
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
    struct tcphdr *tcp_send = malloc(sizeof(struct tcphdr));
    memset(tcp_send, 0, sizeof(struct tcphdr));

	//ETHERNET section
    memcpy(eth_send->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth_send->h_source, sadr_ll.sll_addr, ETH_ALEN);
    eth_send->h_proto = htons(ETH_P_IPV6);

	// IPv6 section
    ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60002ecf);
    memcpy(&ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_plen, &ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen, sizeof(uint16_t));
    memcpy(&ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_nxt, &ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt, sizeof(uint8_t));
    ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64; // was 128
    memcpy(&ip6h_send->ip6_ctlun.ip6_un2_vfc, &ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
    memcpy(&ip6h_send->ip6_src, &ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
    
    memcpy(&ip6h_send->ip6_dst, &ip6h->ip6_src, sizeof(struct in6_addr));
    memcpy(&ip6h_send->ip6_src, &ip6h->ip6_dst, sizeof(struct in6_addr));
    inet_pton(AF_INET6, "fe80::b0cc:7ba1:3f07:4b14", &ip6h_send->ip6_src);
    
    // TCP section
    memcpy(&tcp_send->dest, &tcph->source, sizeof(u_short));
    tcp_send->source = htons(80);
    memcpy(&tcp_send->ack_seq, &tcph->seq, sizeof(tcp_seq)); // sequence number (u_long)
    uint32_t ack_seq_inv = ntohl(tcp_send->ack_seq);
    ack_seq_inv++;
    uint32_t ack_seq_inv2 = htonl(ack_seq_inv);
    memcpy(&tcp_send->ack_seq, &ack_seq_inv2, sizeof(uint32_t)); 

    //sequence number
    int value = 0x99abc9a4;
    memcpy(&tcp_send->seq, &value, 4); // sequence number (u_long)
    
    //memcpy(&tcp_send->ack_seq, &(tcph->ack_seq), sizeof(u_long)); //ack number (u_long)
    tcp_send->doff = 8;
    tcp_send->urg = 0;
    tcp_send->ack = 1;
    tcp_send->psh = 0;
    tcp_send->rst = 0;
    tcp_send->syn = 1;
    tcp_send->fin = 0;
	tcp_send->window = htons(28800);
	tcp_send->check = 0;
	tcp_send->urg_ptr = 0;
	
	// OPTIONS
	char options[12];
	int max_segment_size = htonl(0x020405a0);
	int nop = 0x01;
	int tcp_stack_permitted_option = htons(0x0402); //TRUE
	int window_scale = (0x070303);
	memcpy(options,&max_segment_size, sizeof(u_int32_t)); 
	memcpy(options + 4, &nop, 1); 
	memcpy(options + 5, &nop, 1); 
	memcpy(options + 6, &tcp_stack_permitted_option, sizeof(u_int16_t)); 
	memcpy(options + 8, &nop, 1); 
	memcpy(options + 9, &window_scale, 3); 
	
	tcp_send->check = calculate_tcp_checksum( ip6h_send,tcp_send, options, 12);
	
    memcpy(packet, eth_send, sizeof(struct ethhdr));
	memcpy(packet+sizeof(struct ethhdr), ip6h_send, sizeof(struct ip6_hdr));
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr), tcp_send, sizeof(struct tcphdr)); //TCP
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr) + sizeof(struct tcphdr), options, sizeof(options)); 

    int bytes;
	printf("\n\n\nSending TCP packet\n");
	if (bytes = sendto(socket_desc, packet,  sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + sizeof(options), 0, (const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll)) < 0)
    {
		service_error("sendto failed");
    }
    
    print_packet_in_hex(0,86, packet);
    
    free(eth_send);
    free(ip6h_send);
    free(tcp_send);

}

// version for ipv6 pseudoheader
struct tcp_phdr{
	
		struct in6_addr src_addr;
		struct in6_addr dst_addr;
		uint32_t length;
		uint8_t zero[3]; //reserved according to specification
		uint8_t protocol;
		
};


int calculate_tcp_checksum(struct ip6_hdr *ip6h_send ,struct tcphdr *tcp_send , char *options, int buffsize){
	
	struct tcp_phdr pseudoheader;
	memcpy(&pseudoheader.src_addr, &ip6h_send->ip6_src, sizeof(ip6h_send->ip6_src));
	memcpy(&pseudoheader.dst_addr, &ip6h_send->ip6_dst, sizeof(ip6h_send->ip6_dst));
	memset(pseudoheader.zero, 0, 3);
	pseudoheader.protocol = 0x06;
	pseudoheader.length = htonl(sizeof(struct tcphdr) + buffsize);
	
	char buffer[4096];
	
	memcpy(buffer, &pseudoheader, sizeof(struct tcp_phdr)); 
	memcpy(buffer+sizeof(struct tcp_phdr), tcp_send, sizeof(struct tcphdr)); 
	
	int cksm;
	// if no options nor data segment
	if(options!=NULL && buffsize!=0){
		memcpy(buffer+sizeof(struct tcp_phdr)+ sizeof(struct tcphdr), options, buffsize); 
		cksm = checksum((uint16_t*)buffer, sizeof(struct tcp_phdr)+ buffsize+ sizeof(struct tcphdr));
	} else {
		cksm = checksum((uint16_t*)buffer, sizeof(struct tcp_phdr) + sizeof(struct tcphdr));
	}
	
	return cksm;
	
}

void send_icmp6_answer(unsigned char* buffer, int socket_desc){
	
	struct ethhdr *eth = (struct ethhdr *)buffer;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
	struct icmp6_hdr *icmph6 = (struct icmp6_hdr *)(buffer + 40 + sizeof(struct ethhdr));
	
	struct ifreq ifreq_i;
	
	if(icmph6->icmp6_type != 135) return;
	    
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
	
	na->nd_na_hdr.icmp6_type = 136; // advestisement neighbor
	na->nd_na_hdr.icmp6_code = 0; 

	na->nd_na_hdr.icmp6_cksum = htons(0x6193);
	na->nd_na_hdr.icmp6_dataun.icmp6_un_data8[0] = 0x60; // for O ans S flags
	
	memcpy(packet, eth_send, sizeof(struct ethhdr));
	memcpy(packet+sizeof(struct ethhdr), ip6h_send, sizeof(struct ip6_hdr));
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr), na, sizeof(struct nd_neighbor_advert));
	
	//OPTIONS
	int target_link_layer_address = 0x02;
	int length = 0x01;
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) , &target_link_layer_address, 1);
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) + 1, &length, 1);
	memcpy(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) + 2, sadr_ll.sll_addr, 6);
	
	int bytes;
	printf("\n\n\nSending ICMPv6 packet\n");
	if (bytes = sendto(socket_desc, packet,  sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert) + 8, 0, (const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll)) < 0)
    {
		service_error("sendto failed");
    }

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
    printf("\n");
    printf("                        DATA/Options                         ");
    printf("\n");

    print_packet_in_hex( (sizeof(struct ethhdr) + 40 + tcph->doff*4)
		,size , (char*)buffer);
                         
    printf("\n###########################################################");
}
