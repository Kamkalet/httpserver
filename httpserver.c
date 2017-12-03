#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For
#include<stdlib.h>    //m
#include<string.h>    //s
 
#include<netinet/ip_icmp.h>   //Pro
#include<netinet/udp.h>   //Pr
#include<netinet/tcp.h>  
#include<netinet/ip.h>    /
#include<netinet/if_ether.h>  //For ETH_P_IP
#include<net/ethernet.h>  /
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
 #include <net/if.h>
// Define some constants.


void service_error(char *message);

int main (int argc, char **argv)
{
	printf("Starting server\n");

	struct ifreq ifr;
	int socket_desc;
	unsigned char *buffer;

	// create raw socket for basic packets and sniffing ethernet packets
	if (((socket_desc = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)) 
		service_error("Error receiving listening socket desc: ");
		
	// binding socket to interface etc0
	memset(&ifr, 0, sizeof(struct ifreq));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "eth0");
	ioctl(socket_desc, SIOCGIFINDEX, &ifr);
	char *devname = "eth0";
	if(setsockopt(socket_desc, SOL_SOCKET, SO_BINDTODEVICE,  devname, 10)<0){
		service_error("Error binding");
	}


	printf("Starting receiving...\n");
	int bytes;
	//data saved after receiving
	buffer = (unsigned char *) malloc (65536* sizeof (unsigned char));
	//RECEIVING
	while(1){
		if ((bytes = recvfrom (socket_desc, (void*)buffer, 65536, 0, NULL, (socklen_t*)sizeof (struct sockaddr_in6))) < 0)  {
			service_error("recvfrom() failed ");
		}else{
			printf("succes\n");
			printf("Number of bytes: %d", bytes);
			printf("\n");
		}
	}
	

	free(buffer);
	return (EXIT_SUCCESS);
}

void service_error(char *message){
	
	perror(message);
	exit (1);
	
}

void process_packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer , size);
            break;

        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
        default: 

            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

