#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void print_mac(const char* label, u_char* mac)
{
    printf("%s%02x:%02x:%02x:%02x:%02x:%02x\n", label,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    int ip_header_len = ip->iph_ihl * 4;

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    printf("[Ethernet Header]\n");
    print_mac("Src MAC: ", eth->ether_shost);
    print_mac("Dst MAC: ", eth->ether_dhost);

    printf("[IP Header]\n");
    printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip_header_len);
 
    printf("[TCP Header]\n");
    int tcp_header_len = TH_OFF(tcp) * 4;
    printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

    printf("[HTTP Message]\n");
    int ip_total_len = ntohs(ip->iph_len);
    int headers_len = ip_header_len + tcp_header_len;
    int payload_len = ip_total_len - headers_len;
    const u_char* payload = packet + sizeof(struct ethheader) + headers_len;

    if (payload_len > 0) {
        for (int i = 0; i < payload_len; i++) {
            if ((payload[i] >= 32 && payload[i] <= 126) || payload[i] == '\n' || payload[i] == '\r') {
                putchar(payload[i]);
            }
            else {
                putchar('.');
            }
        }
        printf("\n");
    }
    else {
        printf("None Data \n");
    }

  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


