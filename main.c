#include "header.h"

int
main (int argc, char *argv[])
{
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

	/* Checking user input */
	while ((opt = getopt(argc, argv, "f:n:o:")) != -1) {
		switch (opt)
		{
		case 'f':
			filter_expression = strdup(optarg);
			break;
		case 'n':
			num_pkts = atoi(optarg);
			break; 
		case 'o':
			filename = strdup(optarg);
			break;
		default:
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