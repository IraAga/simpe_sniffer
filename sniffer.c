#include "header.h"

#define YELLOW "\033[0;33m"
#define RED    "\033[0;31m"
#define GREEN "\033[0;32m"
#define RESET "\033[0m"

int
main (int argc, char *argv[])
{
	printf("Packet\n");
	/* user input variables */
	int opt;
	int i;
	char *filter_expression;	/* reading the fiter the user provides us with */
	int num_pkts;			/* number of packets to be captured */

	char *dev, errbuf[PCAP_ERRBUF_SIZE];	
	char ip[13];				/* capture device's ip address */
	char subnet_mask[13];		/* capture device's subnet mask */
	char *filename;				/* the filename of the pcap file */
	bpf_u_int32 ip_raw;		
	bpf_u_int32 mask_raw;		/* gonna give it to pcap_lookupnet(); */
	int lookup_net;
	pcap_t *handle;				/* handler for capturing */
	struct bpf_program filter; /* compiled version of filter expression */
	struct in_addr addr;       /* Internet address */
	pcap_if_t *interfaces;
	pcap_if_t *tmp_i; 			/* tmep for iterating through interfaces */
	pcap_dumper_t *dumpfile;	/* We use this in order to save the live captured pacekt to a pcap file */

	filter_expression = NULL;
	num_pkts = -1;
	opt = 0;
	filename = strdup("dumpfile");

	/* Creating logfiles */
	pkt_log = fopen("pkt_logfile", "w");
	if (pkt_log == NULL) {
		perror( "File did not open" );
		return 1;
	}
	pfp_log = fopen("pfp_log", "w");
	if (pfp_log == NULL) {
		perror( "Fopen failed..." );
		return 1;
	}

	fprintf(pkt_log, "%-5s", "No");
	fprintf(pkt_log, "%-5s", "Size");
	fprintf(pkt_log, "%-18s", "Timestamp");
	fprintf(pkt_log, "%-9s", "Protocol");
	fprintf(pkt_log, "%-15s " , "Source Ip");
	fprintf(pkt_log, "%-15s", "Dest Ip");
	fprintf(pkt_log, "%-15s\n", "IP");
	fprintf(pkt_log,"-------------------------------------------------------------------------\n");	

	printf("argc: %d\n", argc);
	/* Checking user input */
	while ((opt = getopt(argc, argv, "f:n:o:")) != -1) {
		switch (opt)
		{
		case 'f':
			filter_expression = strdup(optarg);
			printf("Filter: %s\n", filter_expression);
			break;
		case 'n':
			num_pkts = atoi(optarg);
			printf("Number of packets to be captured: %d\n", num_pkts);
			break; 
		case 'o':
			filename = strdup(optarg);
			printf("Dumpfile: %s\n", filename);
			break;
		default:
			printf("Parameters missing...\n");
			break;
		}
	}

	/* Look for the first available network device, aside from loopback */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
			fprintf(stderr, "Couldn't find the default device: %s\n", errbuf);
			return(2);
	}

	// printf("Printing all available network devices:");
	// if (pcap_findalldevs(&interfaces, errbuf) == -1) {
	// 	printf("pcap_findalldevs failed: %s\n", errbuf);
	// 	return 2;
	// }	

	// i = 0;
	// for (tmp_i = interfaces; tmp_i; tmp_i = tmp_i->next) {
	// 	printf("\n%d : %s", i++, tmp_i->name);
	// }
	// printf("\n");

	/* Find the device's ip and subnet mask*/
	lookup_net = pcap_lookupnet(dev, &ip_raw, &mask_raw, errbuf);
	if ( lookup_net == -1) {
		fprintf(stderr, "pcap_lookupnet failed: %s", errbuf);
		return 2;
	}
	/* Convert ip in human readable form */
	addr.s_addr = ip_raw;
	strcpy(ip, inet_ntoa(addr));
	if (ip == NULL) {
		perror("inet_ntoa ip address");
		return 2;
	}
	/* Convert subnet mask in human readable form */
	addr.s_addr = mask_raw;
	strcpy(subnet_mask, inet_ntoa(addr));
	if (subnet_mask == NULL) {
		perror("inet_ntoa subnet mask");
		return 2;
	}
	/* Create a handler */
	handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);
	if (handle == NULL){
		printf( "pcap_open_live failed > %s\n" , errbuf);
		return 1;
	}
	/* Create Dumpfile */
	dumpfile = pcap_dump_open(handle, filename);
	if (dumpfile == NULL) {
		printf("Failed to open dumpfile\n");
		return 1;
	}

	/* if a filter expr is given then apply the filter on the handle */
	if (argc >1) {
		printf("(!) FILTER will be applied\n" );
		/* Compile the filter expression */
		if (pcap_compile(handle, &filter, filter_expression, 0, mask_raw) == -1) {
			printf( "pcap_compile failed > %s\n" , pcap_geterr(handle));
			return 2;
		}
		/* Set filter program */
		if (pcap_setfilter(handle, &filter) != 0) {
			printf( "pcap_setfilter failed > %s\n" , pcap_geterr(handle));
			return 2;	
		}
	} else {
		printf("(!) NO FILTER will be applied\n" );
	}
	/* Begin capturing */
	printf( "> Capturing...\n" );
	pcap_loop(handle, num_pkts, pkt_handler, (char *)dumpfile);

	printf( "\nPRINT_FLOWS\n" );	
	print_flows();

	fclose(pkt_log);

	// printf("--------------------------\n");
	// printf("Device: %s\n", dev);
	// printf("Ip: %s\n", ip);
	// printf("Subnet mask:%s\n", subnet_mask);
	// printf("--------------------------\n");

	pcap_freecode(&filter);
	pcap_dump_close(dumpfile);
	pcap_close(handle);
	return 0;
}

void 
pkt_handler (u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethhdr *eth_header; 	/* ethernet header */
	struct iphdr *ip_header;	/* ip header without the ethernet header */
	int eth_header_size;		/* ethernet header size */
	int ip_header_size;			/* ip header size */
	int proto_header_size;		/* protocol header size */
	int total_header_size; 		/* size of all headers before payload */
	int payload_size; 			/* payload size */

	/* logfile entry */
	static int count = 1; 	/* packet counter */
	int pkt_size; 			/* packet size */
	char *protocol;			/* TCP/UDP */
	char *src_ip;			/* source ip of the pkt */
	char *dst_ip;			/* destination ip of pkt */
	char *ip_version;		/* ip version */
	
	eth_header = NULL;
	ip_header = NULL;
	protocol = NULL;
	src_ip = NULL;
	dst_ip = NULL;
	ip_version = NULL;
	pkt_size = 0;
	eth_header_size = 0;
	ip_header_size = 0;
	proto_header_size = 0;

	eth_header = (struct ethhdr *)packet;

	// fprintf(stdout, "\n____________________\n\n> 	_%d_\n", count);
	pcap_dump(args, header, packet);

	/* packet size */
	pkt_size = header->len; // frame length
	/* Check if this packet is using TCP */
	ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
	if (ip_header->protocol == 6) {
		printf("Protocol: %d\n", ip_header->protocol);		
		protocol = strdup("TCP");
	}else if (ip_header->protocol == 17) {
		printf("Protocol: %d\n", ip_header->protocol);
		protocol = strdup("UDP");
	}else {
		printf(	"Protocol: %d\n" , ip_header->protocol);
		protocol =  (char *)malloc(4);
		sprintf(protocol, "%u", ip_header->protocol);
	}

	/* Determine IP version */
	if (ntohs(eth_header->h_proto) == 2048 ) {
		ip_version = strdup("IPv4");
	} else if (ntohs(eth_header->h_proto) == 34525) {
		ip_version = strdup("IPv6");
	} else {
		ip_version = strdup("---");
	}
	
	/* Obtain the source ip of pkt */
	memset(&pkt_addr, 0, sizeof(pkt_addr));
	pkt_addr.s_addr = ip_header->saddr;
	src_ip = strdup(inet_ntoa(pkt_addr));

	/* Obtain the destination ip of pkt */
	memset(&pkt_addr, 0, sizeof(pkt_addr));
	pkt_addr.s_addr = ip_header->daddr;
	dst_ip = strdup(inet_ntoa(pkt_addr));

	/* Payload Size */
	// printf("--- Payload ---\n" );
	eth_header_size = 14;		/* always 14 bytes */
	ip_header_size = (ip_header->ihl) * 4;
	if (strcmp(protocol, "TCP") == 0) {
		struct tcphdr *proto_header = NULL;
		proto_header = (struct tcphdr *)(packet + eth_header_size + ip_header_size);
		proto_header_size = proto_header->doff;
		proto_header_size = proto_header_size * 4;
		printf( "Ethhdr: %d, Iphdr: %d, Tcphdr : %d\n" , eth_header_size, ip_header_size, proto_header_size );
	} else if (strcmp(protocol, "UDP") == 0) {
		struct udphdr *proto_header = NULL;
		proto_header = (struct udphdr *)(packet + eth_header_size + ip_header_size);
		proto_header_size = 8;
		printf( "Ethhdr: %d, Iphdr: %d, Udphdr : %d\n" , eth_header_size, ip_header_size, proto_header_size );
	} else {
		printf("Not a TCP/UDP packet\n");
	}
	if (proto_header_size != 0) {
		total_header_size = eth_header_size + ip_header_size + proto_header_size;
		payload_size = header->caplen - total_header_size;
		printf( "Payload size: %d\n" , payload_size);
		printf("----------------\n" );

		if (fl_list == NULL) { /* first flow */
			insert_flow(src_ip, dst_ip, payload_size);
		} else {
			search_flow(src_ip, dst_ip, payload_size);
		}
	}
	/* Save */
	fprintf(pkt_log, "%-5d", count);
	fprintf(pkt_log, "%-5d", pkt_size);
	fprintf(pkt_log, "%-ld.%06ld", header->ts.tv_sec, header->ts.tv_usec);
	fprintf(pkt_log, "%5s    ", protocol);
	fprintf(pkt_log, " %-15s " , src_ip);
	fprintf(pkt_log, "%-16s", dst_ip);
	fprintf(pkt_log, "%-15s\n", ip_version);
	/* After updating the logfile increase the counter */
	count++;
}

/* Search for an existing flow in the list
 *		- if it finds one, it updates it
 *		- else inser a node for the newly found flow, in the flows list
 * */
void
search_flow (char *ip1, char *ip2, int payload) 
{	
	struct flow *tmp;
	tmp = fl_list;
	
	while (tmp != NULL) { 
		if ( (strcmp(ip1, tmp->ip1) == 0) || (strcmp(ip2, tmp-> ip1) == 0) ) {
			if ( (strcmp(ip2, tmp->ip1) == 0) || (strcmp(ip2, tmp->ip2) == 0) ) {
				update_flow(tmp, payload);
				return;
			}
		}
		tmp = tmp->next;
	}
	/* We have to insert a new flow OR first insertion */
	tmp = NULL;
	insert_flow(ip1, ip2, payload);
	return;
}

/*	
 *		- creates new flow node  
 *		- create new list for the payload sizes of this new flow 
 *		- saves the first payload for this flow 
 */
void
insert_flow (char *ip1, char *ip2, int payload)
{
	struct flow *tmp = NULL;
	struct seq *new_pld;

	tmp = (struct flow *)malloc(sizeof(struct flow));
	if (tmp == NULL) {
		printf("Memory Allocation failed...\n");
		return ;
	}

	tmp->ip1 = strdup(ip1);		/* Copy the ip's of this new flow*/
	tmp->ip2 = strdup(ip2);
	tmp->pcount = 1;			/* Already Captured the first packet for this flow */
	tmp->pls = NULL;			
	tmp->tail = NULL;

	tmp->next = fl_list;	 /* next of new head points to old head */
	fl_list = tmp;			 /* new node becomes the head */

	/* new flow means new sequence of payloads for our new flow
	 *			- create the first node of payload list
	 *			- initialize it and save the first payload size
	 *			  for this flow
	 */
	new_pld = NULL;
	new_pld = (struct seq *) malloc(sizeof(struct seq));
	if (new_pld == NULL) {
		printf("Memory Allocation failed...\n");
		return ;
	}

	new_pld->val = payload;
	new_pld->next = NULL;
	
	tmp->pls = new_pld;
	tmp->tail = new_pld;	
	return;
}

/* Update an existing flow
 *		- increased the captured payload counter for a specific flow 
 *		- creates and adds a new payload node to payload list for this flow
 *		  at the end of the list, for an alreaydy existing flow	
 */
void
update_flow (struct flow *fl, int payload)
{	
	fl->pcount++;
	
	struct seq *tmp;

	tmp = NULL;

	tmp = (struct seq *) malloc(sizeof(struct seq));
	if (tmp == NULL) {
		printf("Memory Allocation failed...\n");
		return ;
	}

	tmp->val = payload;
	// inserting at the end
	if (fl->pls == NULL) {
		fl->pls = tmp;
		tmp->next = NULL;
		fl->tail = tmp;
	} else {
		fl->tail->next = tmp;
		fl->tail = tmp;
		fl->tail->next = NULL;
	}
}

void
print_flows (void)
{
	struct flow *tmp;
	int print_count; 
	int max, min;

	tmp = fl_list;
	print_count = 0;
	
	while (tmp!= NULL) {
		max = tmp->pls->val;
		min = tmp->pls->val;
		printf( 
			    "[%s - %s]\n" 
			   "\t#ofPayloads (pkts): %d\n" 
			    "\tPayload Sequence:" , 
			   tmp->ip1, tmp->ip2, tmp->pcount);
		fprintf(pfp_log, "%s...%s\n\t#ofPayloads(pkts): %d\n\tSequence:", tmp->ip1, tmp->ip2, tmp->pcount);
		while (tmp->pls != NULL) {
			if (tmp->pls->val > max)
					max = tmp->pls->val;
			if (tmp->pls->val < min)
					min = tmp->pls->val;
			if (tmp->pls->next == NULL) {
				printf(" %d", tmp->pls->val);
				fprintf(pfp_log, " %d", tmp->pls->val);
			} else {
				if (print_count <= 9) {	
					printf(" %d,", tmp->pls->val);
					fprintf(pfp_log, " %d,", tmp->pls->val);
					print_count++;
				} else {
					printf(" %d\n\t\t", tmp->pls->val);
					fprintf(pfp_log, " %d\n\t\t", tmp->pls->val);
					print_count = 0;
				}
			}
			tmp->pls = tmp->pls->next;
		}
		printf( "\n\tMax payload: %d\n"  "\tMin payload: %d\n", max, min);
		fprintf(pfp_log, "\n\tMax payload: %d\n\tMin payload: %d\n\n", max, min);
		tmp = tmp->next;
	}
}

