CC=gcc
HEADER=header.h
SF=sniffer.c
EXEC=./sniffer

sniffer: $(SF) $(HEADER)
	${CC} $^ -o $@ -lpcap
debug: $(SF) $(HEADER)
	${CC} -g $^ -o $@ -lpcap 

tcp_flt:
	sudo $(EXEC) -f tcp
udp_flt:
	sudo $(EXEC) -f udp
ip_flt:
	sudo $(EXEC) -f ip
ipv6_flt:
	sudo $(EXEC) ip6

clean:
	-rm -rf *.pcap
	-rm -rf sniffer
	-rm -rf debug
	-rm -rf pkt_logfile
	-rm -rf pfp_log
