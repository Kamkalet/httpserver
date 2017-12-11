#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For
#include<stdlib.h>    //m
#include<string.h>    //s
 
#include <netinet/icmp6.h> //Pro
#include<netinet/udp.h>   //Pr
#include<netinet/tcp.h>  
#include<netinet/ip6.h>    
#include<netinet/if_ether.h>  //For ETH_P_IP
#include<net/ethernet.h>  
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <inttypes.h>


struct in6_addr ip6_src;	/* source address */
struct in6_addr ip6_dst;	/* destination address */

void service_error(char *message);
void process_packet(unsigned char* buffer, int size, int dsc);
void print_ethernet_header(unsigned char* buffer, int size);
void print_ip6_header(unsigned char* buffer, int size);
void print_icmp6_packet(unsigned char* buffer , int size);
void print_tcp_packet(unsigned char* buffer , int size);
int create_socket();
void send_icmp6_answer(buffer);

int main (int argc, char **argv)
{
	printf("Starting server\n");

	int socket_desc_rcv = create_socket();
	int socket_desc_send = create_socket();
	unsigned char *buffer;


	printf("Starting receiving...\n");
	int bytes;
	//data saved after receiving
	buffer = (unsigned char *) malloc (65536* sizeof (unsigned char));
	//RECEIVING
	while(1){
		if ((bytes = recvfrom (socket_desc_rcv, (void*)buffer, 65536, 0, NULL, (socklen_t*)sizeof (struct sockaddr_in6))) < 0)  {
			service_error("recvfrom() failed ");
		}else{
			//printf("succes\n");
			//printf("Number of bytes: %d", bytes);
			//printf("\n");
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
		
	// binding socket to interface etc0
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

	//printf("%d",sizeof(struct ethhdr));
    struct ip6_hdr *ip6h = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
       
	//printf("next header: %d\n",(unsigned int)ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt);
	// check next header value
    switch ((unsigned int)ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt) //Check the Protocol and do accordingly...
    {
        case 58:  //ICMP Protocol
            print_icmp6_packet( buffer , size);
            send_icmp6_answer(buffer. dsc);
            break;

        case 6:  //TCP Protocol
            print_tcp_packet(buffer , size);
            break;
        default: 
            //print_icmp6_packet( buffer , size);
            break;
    }

}

void send_icmp6_answer(unsigned char* buffer, int socket_desc){
	
	struct ethhdr *eth = (struct ethhdr *)buffer;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
	struct icmp6_hdr *icmph6 = (struct icmp6_hdr *)(buffer + ip6_hdrlen  + sizeof(struct ethhdr));
	
	//packet to be sent
	unsigned char packet[4096];
	memset (packet, 0, 4096);
	
	struct ethhdr *eth_send = (struct ethhdr *)packet;
	struct ip6_hdr *ip6h_send = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));
	struct icmp6_hdr *icmph6_send = (struct icmp6_hdr *)(packet + 40 + sizeof(struct ethhdr));
	
	memcpy(eth_send->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth_send->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth_send->h_proto, eth->h_proto, sizeof __be16);
	
	memcpy(packet, eth, sizeof(struct ethhdr));
	
	memcpy(ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_flow, ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow, sizeof(uint32_t));
	memcpy(ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_plen, ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen, sizeof(uint16_t));
	memcpy(ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_nxt, ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt, sizeof(uint8_t));
	memcpy(ip6h_send->ip6_ctlun.ip6_un1.ip6_un1_hlim, ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim, sizeof(uint8_t));
	memcpy(ip6h_send->ip6_ctlun.ip6_un2_vfc, ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
	memcpy(ip6h_send->ip6src, ip6h->ip6_ctlun.ip6_un2_vfc, sizeof(uint8_t));
	memcpy(ip6h_send->ip6_ctlun.ip6_dst, ip6h->ip6_ctlun.ip6_dst, sizeof(struct in6_addr));
	memcpy(ip6h_send->ip6_ctlun.ip6_dst, ip6h->ip6_ctlun.ip6_dst, sizeof(struct in6_addr));
	
	
	
	eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
	  printf("   |-Version,class,flow: %u\n", (unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow));
    printf("   |-Payload length    : %u\n",(unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen));
    printf("   |-Next header       : %u\n", (unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt));
    printf("   |-Hop limit         : %u\n",(unsigned int)ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim);
	
	
	
	
	
	if (sendto (socket_desc, packet, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
		service_error("sendto failed");
    }
	
}

void print_ethernet_header(unsigned char* buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
     
    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
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
	inet_ntop(AF_INET6,&ip6_src,source,sizeof(source));
	inet_ntop(AF_INET6,&ip6_dst,destination,sizeof(destination));
	
	
    printf("IPv6 Header\n");
    printf("   |-Version,class,flow: %u\n", (unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow));
    printf("   |-Payload length    : %u\n",(unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen));
    printf("   |-Next header       : %u\n", (unsigned int)(ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt));
    printf("   |-Hop limit         : %u\n",(unsigned int)ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    printf("   |-Source IP         : %s\n",source);
    printf("   |-Destination IP    : %s\n",destination);
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
             
    /*if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }*/
     
    printf("   |-Code : %d\n",(unsigned int)(icmph6->icmp6_code));
    printf("   |-Checksum : %d\n",ntohs(icmph6->icmp6_cksum));
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");
 
    //fprintf(logfile , "IP Header\n");
    //PrintData(Buffer,iphdrlen);
         
    //fprintf(logfile , "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    //PrintData(Buffer + header_size , (Size - header_size) );
     
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
