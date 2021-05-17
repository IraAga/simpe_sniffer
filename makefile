CC=gcc
HEADER=header.h
SF=main.c sniffer.c
FLAGS= -Wno-unused-variable

sniffer: $(SF) $(HEADER)
	${CC} $^ -o $@ -lpcap
debug: $(SF) $(HEADER)
	${CC} -g $^ -o $@ -lpcap 

clean:
	-rm -rf *.pcap
	-rm -rf sniffer
	-rm -rf debug
	-rm -rf pkt_logfile
	-rm -rf pfp_log
