#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct seq {
	int val;
	struct seq *next;
};

struct flow {
	char *ip1;
	char *ip2;
	int pcount;				/* nubmer of payloads in this flow */
	struct seq *pls;		/* sequence of payloads in this flow  */
	struct seq* tail;
	struct flow *next;		
};

struct flow *fl_list = NULL;

FILE *pkt_log;				/* captured packets' logfile */
FILE *pfp_log;				/* per flow payloads */
struct in_addr pkt_addr;	/* used to find src and dst ports inside the callback function */

/* functions */ 
void pkt_handler (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void search_flow (char *ip1, char *ip2, int payload);

void insert_flow (char *ip1, char *ip2, int payload);

void update_flow (struct flow *fl, int payload);

void print_flows(void);
