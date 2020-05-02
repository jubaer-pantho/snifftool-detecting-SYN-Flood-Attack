/* meat of the code is in here so read this file */
// credit 1: https://github.com/kdszyubin/minisniff
// credit 2: https://elf11.github.io/2017/01/22/libpcap-in-C.html

// modified by : Md Jubaer Hossain Pantho

#include <capture.h>
#include <buffer.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>

// Daniela
#include <tcp_connection.h>
#include <netinet/tcp.h>

#define PCAP_BUF_SIZE   400000

typedef struct iphdr ip_header;
typedef struct ether_header ethernet_header;

//variable to counte packets
int icmpCount = 0;
int tcpCount = 0;
int udpCount = 0;
int arpCount = 0;

// variable to store syn packet ips and count
int synCount[PCAP_BUF_SIZE];
int synIdx = 0;
char synIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];

// variable to store http count ips and count
int httpCount[PCAP_BUF_SIZE];
int httpIdx = 0;
char httpIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];


// variable to store syn/ack packet ips and count
int synAckCount[PCAP_BUF_SIZE];
int synAckIdx = 0;
char synAckIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
int number_warning = 0;


//main function
int main (int argc, char **argv){
  FILE *fp;

  // file used to store detail information of malicious packet.
  fp = fopen("malicious-packets.txt", "w+");

  if (fp == NULL) {
    fprintf(stderr, "Can't open file");
    exit(1);
  }


  /* variables for network device. This is commented out since we are reading from a offline file */
  //char *dev; /* pointer to network card name, like a file name */

  char errbuf[PCAP_ERRBUF_SIZE]; /* buffer for pcap to send its errors */
  pcap_t *descr; /* file descriptor for the network card */
  
  /* variables for packets we sniff */
  ethernet_header *eptr; /* pointer to the structure that represents ethernet header */
  ip_header *ipptr; /* pointer to the structure that represents ip header */
  unsigned int size_of_ehdr= sizeof(ethernet_header);  /* size of the ethernet header */

  buffer buf; /* that's my linked-list */
  item *tmp; /* an item in the linked-list */
  u_char *ptr, *packet; /* vars to store raw packets */
 
  if (argc != 3){
      fprintf (stderr, "Usage: %s no_packets\nno_packets: number of packets to grab before quit sniffing\n",argv[0]);
      exit(-1);
  }

  //timestamping
  clock_t start, end;
  double cpu_time_used;
     
  start = clock();

  // change it to live if reading network card
  //descr = pcap_open_live (dev, BUFSIZ, 0, -1, errbuf)
  descr = pcap_open_offline(argv[2], errbuf);
  if (descr == NULL) {
      fprintf (stderr, "%s: pcap_open_live: %s\n", argv[0], errbuf);
      exit (-1);
  }

  // uncomment if you are using network card
  //(void) setgid(getgid());
  //(void) setuid(getuid());
  
  create_buffer(&buf, 4096, 2048);

  pcap_loop(descr, atoi(argv[1]), pcap_callback, (void *)&buf);

  end = clock();
  cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("pcap_loop took: %lf seconds to execute \n", cpu_time_used);


  start = clock();
  fprintf(stdout, "\nDetail information about captured packets\n");
  /* just walk the list one item at a time and print some info about the packet */
  tmp= buf.header;
  while(tmp != NULL) {
    const struct tcphdr* tcpHeader;
    const struct ip* ipHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    int synAckCursor= 0;
    int synCursor = 0;

    /* here we want to access the ethernet header of a packet, which looks like this
     *              ------------------------------------------
     *              | ethernet |   ip   | icmp/tcp | payload |
     *              |  header  | header |  header  |         |
     *              ------------------------------------------
     * since we are interested in the ethernet header we do a simple type cast and it gives 
     * us a right amount of bytes, that is, it'll automatically ignore everything beyond
     * ethernet header
     */ 

    packet= tmp->full_packet;
    eptr= (ethernet_header *) packet; /* ethernet header of current packet */

    switch(ntohs(eptr->ether_type)) {
        case (ETHERTYPE_IP):

            ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
            inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

            if (ipHeader->ip_p == IPPROTO_TCP) {
                tcpCount = tcpCount + 1;
                tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                sourcePort = ntohs(tcpHeader->source);
                destPort = ntohs(tcpHeader->dest);
                data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                dataLength = tmp->packet_header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                if (sourcePort == 80 || sourcePort == 443 || destPort == 80 || destPort == 443) {
                    for (int i = 0; i < httpIdx; i++) {
                        if (strcmp(destIP, httpIP[i]) == 0) {
                            httpCount[i] = httpCount[i] + dataLength;
                        }
                    }
                    strcpy(httpIP[httpIdx], destIP);
                    httpCount[httpIdx] = dataLength;
                    httpIdx = httpIdx + 1;
                }
                // Checking whether it is a TCP SYN
                if (tcpHeader->th_flags & TH_SYN && !(tcpHeader->th_flags & TH_ACK)) {

                    // ---------------------scanner checking------------------
                    for (int i = 0; i < synIdx; i++) {
                        if (strcmp(sourceIP, synIP[i]) == 0) {
                                synCursor = synCount[i];
                                break;
                            }
                    }
                    for(int i = 0; i < synAckIdx; i++) {
                        if (strcmp(destIP, synAckIP[i]) == 0) {
                            synAckCursor = synAckCount[i];
                            break;
                        }
                    }

                    if (synCursor > ((3 * synAckCursor) + 3)) {
                        number_warning++;
                        fprintf(stdout, "------warning issued--------\n");
                        fprintf(stdout, "type of packet= IP\n");
                        fprintf(stdout, "source IP : %s\n", sourceIP);
                        fprintf(stdout, "destination IP : %s\n", destIP);


                        fprintf(fp, "------warning issued--------\n");
                        fprintf(fp, "actual length=%d captured length=%d\n", tmp->packet_header->len, tmp->packet_header->caplen);
                        fprintf(fp, "source IP : %s\n", sourceIP);
                        fprintf(fp, "destination IP : %s\n", destIP);

                        ptr = eptr->ether_dhost;
                        fprintf(fp, "destination mac address= ");
                        for (int k = 0; k < ETHER_ADDR_LEN; k++) {
                            if (k != 0) fprintf(fp, ":");
                                fprintf(fp, "%x",*ptr++);
                            }
                        fprintf(fp, "\n");

                        ptr = eptr->ether_shost;
                        fprintf(fp, "source mac address= ");
                        for (int k = 0; k < ETHER_ADDR_LEN; k++) {
                            if (k != 0) fprintf(fp, ":"); 
                                fprintf(fp, "%x",*ptr++);
                            }
                        fprintf(fp, "\n");

                        ipptr= (ip_header *) (packet + size_of_ehdr);
         
    	                fprintf(fp, "information about this IP packet:\n");
        	            fprintf(fp, "length= %d\n", ntohs(ipptr->tot_len));
        	            fprintf(fp, "header length= %d\n", ipptr->ihl );
        	            fprintf(fp, "version= %d\n", ipptr->version);
        	            fprintf(fp, "id= %d\n", ipptr->id);
        	            fprintf(fp, "offset= %d\n", ipptr->frag_off);
        	            fprintf(fp, "ttl= %d\n", ipptr->ttl);
        	            fprintf(fp, "protocol=%d\n", ipptr->protocol);
                        fprintf(stdout, "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
                        fprintf(fp, "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
                    }
                    // -------------------------Checking complete----------------------------

                    for (int i = 0; i < synIdx; i++) {
                        if (strcmp(sourceIP, synIP[i]) == 0) {
                            synCount[i] = synCount[i] + 1;
                            break;
                        }
                    }

                    strcpy(synIP[synIdx], sourceIP);
                    synCount[synIdx] = 1;
                    synIdx = synIdx + 1;
                }

               // Checking wheather it is TCP SYN/ACK 
                if ((tcpHeader->th_flags & TH_SYN) && (tcpHeader->th_flags & TH_ACK)) {
                    for (int i = 0; i < synAckIdx; i++) {
                        if (strcmp(destIP, synAckIP[i]) == 0) {
                            synAckCount[i] = synAckCount[i] + 1;
                            break;
                        }
                    }
                    strcpy(synAckIP[synAckIdx], destIP);
                    synAckCount[synAckIdx] = 1;
                    synAckIdx = synAckIdx + 1;
                
                }

            }
            else if (ipHeader->ip_p == IPPROTO_UDP) {
                udpCount = udpCount + 1;
            }
            else if (ipHeader->ip_p == IPPROTO_ICMP) {
                icmpCount = icmpCount + 1;
            }

            break;

        case (ETHERTYPE_ARP):
            arpCount = arpCount + 1;
	        break;

        case (ETHERTYPE_REVARP):
    	    fprintf(stdout, "RARP Packet\n");
            break;

        case (ETHERTYPE_PUP):
            fprintf(stdout, "Xerox PUP Packet\n");
            break;

        default:
            fprintf(stdout, "Unknown type (%x)\n", ntohs(eptr->ether_type));
            break;
        }
    
    /* next packet please */
    tmp= tmp->next;
  }


int maxCountSyn = 0, maxCountHttp = 0, maxIdxSyn = 0, maxIdxHttp = 0;

    for (int i = 0; i < synIdx; i++) {
        if (maxCountSyn < synCount[i]) {
            maxCountSyn = synCount[i];
            maxIdxSyn = i;
        }
    }

    for (int i = 0; i < httpIdx; i++) {
        if (maxCountHttp < httpCount[i]) {
            maxCountHttp = httpCount[i];
            maxIdxHttp = i;
        }
    }

  end = clock();
  cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("Total: %lf seconds to execute \n", cpu_time_used);

  printf("Packet summary\n");
  printf("Protocol Summary: %d ICMP packets, %d TCP packets, %d UDP packets\n", icmpCount, tcpCount, udpCount); 
  printf("Arp packets: %d packets.\n", arpCount);
  printf("IP address sending most SYN packets: %s\n", synIP[maxIdxSyn]);
  printf("IP address that most HTTP/HTTPS traffic goes to (in terms of bandwidth, NOT packet count): %s\n", httpIP[maxIdxHttp]);
  
  printf("total Number of syn: %d\n", synIdx);
  printf("total number of synAck: %d\n", synAckIdx);
  printf("total number of warnings : %d\n", number_warning);

  fclose(fp);
  return 0;
}
