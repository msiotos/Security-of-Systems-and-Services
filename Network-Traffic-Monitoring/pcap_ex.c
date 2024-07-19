#include <stdio.h>
#include <getopt.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h> 
#include <string.h> 
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>	
#include <netinet/ip.h>	

int nf=0, tcp_f=0, udp_f=0, total_others=0, total_packets=0, total_tcps=0, total_udps=0, total_bytes_tcp=0, total_bytes_udp=0;
char* filter_expression = NULL;

pcap_t* handle;
int retnum=0;

typedef struct net_flow{
	char source_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	unsigned int protocol;
	unsigned int sport;
	unsigned int dport;

	struct net_flow* next;

}flow;

typedef struct retransmission{

	char source_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	int payload;
	struct tcphdr *tcp;

	struct retransmission* next;

}retr;

flow* net = NULL;
retr* retrans_glb = NULL;
retr* current_flow=NULL;

int c=0;
void print_help_message();
void process_pcap_file(char *pcap_file);
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void print_console_stats();
int apply_filter(const unsigned char *packet);



void print_console_stats()
{
	printf("                  Statistics                  \n");
	printf("----------------------------------------------\n");
	printf("   Total network flows captured: %d\n", nf);
	printf("   Total TCP network flows captured: %d\n", tcp_f);
	printf("   Total UDP network flows captured: %d\n", udp_f);
	printf("   Total packets captured: %d\n", total_packets);
	printf("   Total TCP packets captured: %d\n", total_tcps);
	printf("   Total UDP packets captured: %d\n", total_udps);
	printf("   Total bytes of TCP packets captured: %d\n", total_bytes_tcp);
	printf("   Total bytes of UDP packets captured: %d\n", total_bytes_udp);
}


flow * in_list(flow * net, char* ips, char* ipd, int pr, unsigned int sp, unsigned int dp){
	flow* tmp = net;
    while(tmp != NULL){

        if(tmp->protocol == pr && tmp->sport==sp && tmp->dport==dp && strcmp(tmp->source_ip,ips)==0 && strcmp(tmp->dest_ip,ipd)==0 ){
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}

void new_net(flow * net, char* ips, char* ipd, int pr, unsigned int sp, unsigned int dp){

	flow* new = (flow*)malloc(sizeof(flow));
	flow* tmp = net;

	while(tmp->next != NULL){
		tmp = tmp->next;
	}

	tmp->next = new;
	memcpy(new->source_ip,ips,INET_ADDRSTRLEN);
	memcpy(new->dest_ip,ipd,INET_ADDRSTRLEN);
	new->protocol = pr;
	new->sport    = sp;
	new->dport    = dp;
	new->next 	  = NULL;

	++nf;
	if(new->protocol == IPPROTO_TCP)
		++tcp_f;
	else if (new->protocol == IPPROTO_UDP)
		++udp_f;

}

retr* add_to_current_flow(retr* head ,retr* new){

	if(new==NULL)
	 return head;
	
	if(head==NULL){
		head=new; 
		return head;}

	else{
		
		retr* temp=head;
		while(temp->next!=NULL)		
			temp=temp->next;
		
		temp->next=new;
	}
	return head;
}	



retr* add_trans(retr* head ,retr* new){	
	
	current_flow=NULL;

	if(new==NULL)
		return head;
	
	if(head==NULL){
		 head=new;
		 return head;}
	else{
		retr* temp=head;
		
		
		while(temp->next!=NULL){
			if(strcmp(temp->source_ip,new->source_ip)==0 && strcmp(temp->dest_ip,new->dest_ip)==0 && ntohs(new->tcp->source)==ntohs(temp->tcp->source) \
			 && ntohs(new->tcp->dest)==ntohs(temp->tcp->dest)){			

				retr* current;
				current=(retr*)malloc(sizeof(retr));
				
				current->tcp=temp->tcp;
				strcpy(current->source_ip,temp->source_ip);
				strcpy(current->dest_ip,temp->dest_ip);
				current->payload = temp->payload;
				current->next=NULL;
				
				current_flow = add_to_current_flow(current_flow,current);	
				
			}		
			temp=temp->next;
		}
		temp->next=new;	
	}
	
	if(current_flow!=NULL){

		while(current_flow->next!=NULL){

			if((current_flow->tcp->seq-1!=new->tcp->ack_seq) && (new->tcp->syn==1 || new->tcp->fin==1 || new->payload>0 ) &&
			   (current_flow->tcp->seq + current_flow->payload > new->tcp->seq)&&  new->tcp->ack ==1){
				printf("[TCP RETRANSMISSION]\n\n"); 
				retnum++;
				break;
			}
			current_flow=current_flow->next;	
		}
				
		
	}
	
	return head;
}

void check_retr( char* ips,char* ipd, struct tcphdr *tcph,int payload){


			retr* tmp_retr ;

			tmp_retr=(retr*)malloc(sizeof(retr));
			memcpy(tmp_retr->source_ip,ips,INET_ADDRSTRLEN);
			memcpy(tmp_retr->dest_ip,ipd,INET_ADDRSTRLEN);


			tmp_retr->payload = payload;
			tmp_retr->tcp=tcph;
			tmp_retr->next = NULL;

			retrans_glb = add_trans(retrans_glb,tmp_retr);
}


void tcp_info(const u_char * packet, int size)
{

	flow* tmp_flow = NULL;
	char s_ip[INET_ADDRSTRLEN];
	char d_ip[INET_ADDRSTRLEN];
	unsigned short ip_len;
	const struct ip * iphead = (struct ip *)(packet  + sizeof(struct ethhdr) );

	struct ether_header *eptr = (struct ether_header*)packet;

	if (ntohs(eptr->ether_type) != ETHERTYPE_IP && ntohs(eptr->ether_type) != ETHERTYPE_IPV6) {
		printf("Not an IPv4 or IPv6 packet. Skipped\n");
		return;
	}
	ip_len = iphead->ip_hl*4;
	
	inet_ntop(AF_INET, &(iphead->ip_src), s_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iphead->ip_dst), d_ip, INET_ADDRSTRLEN);
	

	struct tcphdr *tcph=(struct tcphdr*)(packet + ip_len + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + ip_len + tcph->doff*4;
	int payload_length = size-header_size;
	total_bytes_tcp = total_bytes_tcp + size;

	if (net==NULL){

		tmp_flow=(flow*)malloc(sizeof(flow));
		memcpy(tmp_flow->source_ip,s_ip,INET_ADDRSTRLEN);
		memcpy(tmp_flow->dest_ip,d_ip,INET_ADDRSTRLEN);

		tmp_flow->protocol = (unsigned int)iphead->ip_p;
		tmp_flow->sport    = ntohs(tcph->source);
		tmp_flow->dport	   = ntohs(tcph->dest);
		tmp_flow->next 	   = NULL;
		net = tmp_flow;

		++nf;
		++tcp_f;


	}else{
		if((tmp_flow = in_list(net,s_ip,d_ip,(unsigned int)iphead->ip_p,ntohs(tcph->source),ntohs(tcph->dest)))==NULL)
			new_net(net,s_ip,d_ip,(unsigned int)iphead->ip_p,ntohs(tcph->source),ntohs(tcph->dest));
		}


	printf("|Source IP: %s| |Dest. IP: %s| |Protocol: TCP| ",s_ip,d_ip);
	printf("|Source Port: %u| |Dest. Port: %u| |Header Length: %d| |Payload Length: %d|\n",ntohs(tcph->source),ntohs(tcph->dest),(unsigned int)tcph->doff*4, payload_length);
	printf("|Payload Memory Address: %p|\n\n", (void*)(packet + header_size));

	check_retr(s_ip,d_ip,tcph,payload_length);

	return;
}


void udp_info(const u_char * packet, int size)
{

	flow* tmp_flow = NULL;
	char s_ip[INET_ADDRSTRLEN];
	char d_ip[INET_ADDRSTRLEN];
	unsigned short ip_len;

	const struct ip * iphead = (struct ip *)(packet  + sizeof(struct ethhdr) );
	struct ether_header *eptr = (struct ether_header*)packet;

	if (ntohs(eptr->ether_type) != ETHERTYPE_IP && ntohs(eptr->ether_type) != ETHERTYPE_IPV6) {
		printf("Not an IPv4 or IPv6 packet. Skipped\n");
		return;
	}
	ip_len = iphead->ip_hl*4;
	
	inet_ntop(AF_INET, &(iphead->ip_src), s_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iphead->ip_dst), d_ip, INET_ADDRSTRLEN);
	

	struct udphdr *udph=(struct udphdr*)(packet + ip_len + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + ip_len +sizeof(udph);
	int payload_length = size-header_size;

	total_bytes_udp = total_bytes_udp + size;

	if (net==NULL){

		tmp_flow=(flow*)malloc(sizeof(flow));
		memcpy(tmp_flow->source_ip,s_ip,INET_ADDRSTRLEN);
		memcpy(tmp_flow->dest_ip,d_ip,INET_ADDRSTRLEN);

		tmp_flow->protocol = (unsigned int)iphead->ip_p;
		tmp_flow->sport    = ntohs(udph->source);
		tmp_flow->dport	   = ntohs(udph->dest);
		tmp_flow->next 	   = NULL;
		net = tmp_flow;

		++nf;
		++udp_f;

	}else{
		if((tmp_flow = in_list(net,s_ip,d_ip,(unsigned int)iphead->ip_p,ntohs(udph->source),ntohs(udph->dest)))==NULL)
			new_net(net,s_ip,d_ip,(unsigned int)iphead->ip_p,ntohs(udph->source),ntohs(udph->dest));
	}

	printf("|Source IP: %s| |Dest. IP: %s| |Protocol: UDP| ",s_ip,d_ip);
	printf("|Source Port: %u| |Dest. Port: %u| |Header Length: %d| |Payload Length: %d|\n",ntohs(udph->source),ntohs(udph->dest),(unsigned int)udph->len, payload_length);
	printf("|Payload Memory Address: %p|\n\n", (void*)(packet + header_size));
	return;
}


void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){

  if (filter_expression!=NULL && !apply_filter(packet)) {
      // Packet does not match the filter, skip processing
      return;
  }

	int size = header->caplen;

	struct iphdr *ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
	++total_packets;
	switch (ip_header->protocol) 
	{
		case IPPROTO_TCP: 
			++total_tcps;
			tcp_info(packet , size);

			break;
		
		case IPPROTO_UDP: 
			++total_udps;
			udp_info(packet , size);

			break;
		default: 
			++total_others;
			break;		
	}

}



void process_pcap_file(char *pcap_file) {

char errbuf[PCAP_ERRBUF_SIZE];
handle = pcap_open_offline(pcap_file, errbuf);

if (handle != NULL) {

    pcap_loop(handle,-1,packet_handler,NULL);
    print_console_stats();

} else {
    fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
    return;
}



pcap_close(handle);

return;
}

void terminate_process(int signum){

	pcap_breakloop(handle);
	pcap_close(handle);

}


void process_live(char * dev){

	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;		
	bpf_u_int32 net;		
	int timeout = 1000;
    
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Error finding device: %s\n", errbuf);
		mask = 0;
		net  = 0;
    }

    FILE *file_output = fopen("log.txt", "a");
    if (file_output == NULL) {
        fprintf(stderr, "Error opening log.txt for writing.\n");
        exit(EXIT_FAILURE);
    }

    if (dup2(fileno(file_output), STDOUT_FILENO) == -1) {
        fprintf(stderr, "Error redirecting stdout to file.\n");
        exit(EXIT_FAILURE);
    }

    fclose(file_output);

   handle = pcap_open_live(dev,BUFSIZ,0,timeout,errbuf);   

    if(handle == NULL){
        printf("Error for pcap_open_live(): %s\n",errbuf);
		return ;
	}

	signal(SIGINT, terminate_process);
	pcap_loop(handle,timeout,packet_handler,NULL);
	
	print_console_stats();

	return;
}

void available_dev(){

	pcap_if_t *alldevs , *device;

	char errbuf[PCAP_ERRBUF_SIZE] , *devname ;
	int count = 1;
	
	printf("Finding available devices ... ");
	
	if(pcap_findalldevs(&alldevs , errbuf))
	{
		printf("Error finding devices : %s" , errbuf);
        exit(EXIT_FAILURE);
	}
	
	printf("\nAvailable Devices are :\n");
	for(device = alldevs ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		count++;
	}
    pcap_freealldevs(alldevs);

	return;
}


int apply_filter(const unsigned char *packet) {

//We take the Ethernet and IP headers of the packet to check for the filter
struct ethhdr *eth_header = (struct ethhdr *)packet;
struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

//Variables for subfilters specification
int index = 0;
int length = 0;

//printf("GFE: %s\n", filter_expression);
//printf("Search protocol: %d\n", ip_header->protocol);

//AFTER TESTING WE FIGURED OUT THAT: 
//TCP packets are number 6
//UDP packets are number 17

//### CASE 1: CHECK IF TCP PROTOCOL ###
if (strcmp(filter_expression, "tcp") == 0 && ip_header->protocol != 6) {
  //printf("Packet is not TCP\n");
    return 0;
}

//### CASE 2: CHECK IF UDP PROTOCOL ###
if (strcmp(filter_expression, "udp") == 0 && ip_header->protocol != 17) {
  //printf("Packet is not UDP\n");
    return 0;
}

//### CASE 3: CHECK FOR SPECIFIC IP ADDR ###
if(strstr(filter_expression,"ip:")) {

index=3;
length=15;

char ip_number[length + 1];
strncpy(ip_number, filter_expression + index, length);
ip_number[length] = '\0';
//printf("IP number: %s\n", ip_number);

struct in_addr desired_ip;
inet_pton(AF_INET, ip_number, &desired_ip);

if (ip_header->saddr != desired_ip.s_addr && ip_header->daddr != desired_ip.s_addr) {
  //printf("IP does not match\n");
  return 0; 
}

}

//### CASE 4: CHECK FOR SPECIFIC PORT NUMBER ###
if(strstr(filter_expression,"port:")) {

//printf("1st check: enters port filter...\n");

index=5;
length=5;

char port_number[length + 1];
strncpy(port_number, filter_expression + index, length);
port_number[length] = '\0';
//printf("Port number: %s\n", port_number);

int desired_port = atoi(port_number);

//If its TCP
if (ip_header->protocol == 6) {

//printf("2st check: enters tcp port...\n");
struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
if (ntohs(tcp_header->dest) != desired_port && ntohs(tcp_header->source) != desired_port) {
  //printf("Port does not match\n");
  return 0;
}

//If its UDP
} else if (ip_header->protocol == 17) { 

//printf("3st check: enters udp port...\n");

struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

if (ntohs(udp_header->dest) != desired_port && ntohs(udp_header->source) != desired_port) {
  //printf("Port does not match\n");
  return 0;
}

}

}

//PACKET PASSED ALL FILTERS OR NO FILTER IS PRESENT
//printf("End of Search: Successful!\n");
return 1; 

}

void print_help_message() {

  printf(
    "Options:\n"
    "\t-i Network interface name (e.g., eth0)\n"
    "\t-r Packet capture filename (e.g., test.pcap)\n"
    "\t-f Filter expression (e.g., port 8080)\n"
    "\t-h Help message\n"
  );

  printf(
    "Execution examples:\n"
    "\tsudo ./pcap_ex -i enp0s3 (save the packets in log.txt)\n"
    "\t./pcap_ex -r test_pcap_5mins.pcap (print the outputs in terminal)\n"
    "\tsudo ./pcap_ex -f port: 58380 -i enp0s3\n\n"
  );

	available_dev(); // Print available devices 

  exit(EXIT_FAILURE);

}

int main(int argc, char **argv) {

  int opt;
  char *pcap_filename = NULL;
  char *interface = NULL;
  char *filter = NULL;

  while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
    switch(opt) {

      case 'i':
        interface = strdup(optarg);
        process_live(interface);
        break;

      case 'r':
        pcap_filename = strdup(optarg);
        process_pcap_file(pcap_filename);
        break;

      case 'f':
        filter_expression = optarg;
        break;

      case 'h':
        print_help_message();

      default:
        print_help_message();
    }
  }

  free(pcap_filename);

  return 0;
}


	