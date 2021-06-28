## Description 
   This is my simple sniffer. Makes use of libpcap's provided functionality to read packets from the first available network interface, dumps them to a pcap file and generates all the networks flows from the captured packets. After a successful execution of the sniffer, 2 additional log files are generated.
   
  #### Available Options:
        -f <filter> : Apply a bpf filter while capturing.
        -n <num_of_pkts> : The total number of packets to be captured.
        -o <dumpfile_name> : Specify a name for the dumpfile.
        
   ### Generated Log Files 
   
         pkt_log: Contains specific information, for each packet of the dumpfile
                
         pfp_log: Contains all the network flows and payload size sequences found, in a comma separated format 


## Usage
    > ./sniffer [options]
    
    Options: 
            -n[num_of_pkts]           Specify number of packets to be captured
            -f[filter_expression]     Give a filter expression 
            -o[filename.pcap]         Dumpfile name to save as
