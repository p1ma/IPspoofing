#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <cstdint> // uint16_t
#include <sys/types.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <arpa/inet.h> // inet_addr
#include <sys/socket.h> // socket
#include <netinet/in.h> // socket
#include <netinet/ip.h> // struct ip
#include <netinet/tcp.h> // tcphdr
#include <pcap/pcap.h> // pcap

using namespace std;
/*
  GLOBAL VARIABLE
*/
int raw_socket = 0; // socket
const char *ip_src_addr = "192.168.1.66";
const char *ip_dst_addr = "192.168.1.1";
const uint16_t tcp_src_port = 6666;
const uint16_t tcp_dst_port = 55555;

/*
  METHODS SIGNATURES
*/

// Calc IP header checksum
uint16_t ip_checksum(const uint16_t &header,
		     size_t length);

// Calc TCP header checkum
uint16_t tcp_checksum(const in_addr_t ip_src,
		      const in_addr_t ip_dst,
		      const uint16_t protocol_number,
		      const uint16_t *tcp_header,
		      size_t length);

// 3-way handshake: send SYN
void tcp_syn(int fd);

// 3-way handshake: send SYN-ACK
void tcp_syn_ack(int fd,
		 const uint32_t no_seq);

// Capture TCP segment on a new thread
void * pthread_capture_tcp(void *arg);


/*
  pcap_handler, if the server receives TCP - SYN he will reply a SYN+ACK packet
  so we have to intercept it and get the sequence number
  (See: http://www.tcpdump.org/manpages/pcap_loop.3pcap.html)
*/
void packet_intercepter(u_char *user,
			const struct pcap_pkthdr *h,
			const u_char *bytes);

/*
  Spoof your @IP and send an ping request to your local router
  Compile: make
  Execute: sudo ./spoof
  Clean: make clean
  Infos: 
  https://www.codeproject.com/Articles/800872/Spoofing-an-IP-is-Hard
  http://www.enderunix.org/docs/en/rawipspoof/
*/
int main(int argc, char *argv[]) {
  // Variables
  int status = EXIT_FAILURE;
  const int optval = 1;
  
  cout << "Brace yourself\n\tspoofing is comin'..." << endl;

  // Creates RAW socket
  if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    cerr << "Error: socket().\nTry: sudo " << argv[0] << endl;
    exit(status);
  } else {
    cout << "Success: socket()." << endl;
  }

  // Adds socket option IP_HDRINCL (i.e packet must contain an IP header)
  if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
    cerr << "Error: setsockopt(...IP_HDRINCL...)." << endl;
    exit(status);
  }

  // TCP - 3-way handshake 1rst step: syn
  tcp_syn(raw_socket);

  // Close raw_socket
  if (close(raw_socket) < 0) {
    cerr << "Error: close()." << endl;
    exit(status);
  }
  
  status = EXIT_SUCCESS;
  return status;
}
// Calc IP header checksum
uint16_t ip_checksum(const uint16_t *header, size_t length) {
  const uint16_t *iterator = header;
  uint16_t sum = 0;
  
  while (length > 1) {
    sum += *iterator++;
    if (sum & 0x80000000) sum = (sum & 0xFFFF) + (sum >> 16);
    length -= 2;
  }

  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

  return (~sum);
}

/* Calc TCP header checkum 
   (from: http://minirighi.sourceforge.net/html/tcp_8c-source.html)
*/
uint16_t tcp_checksum(const in_addr_t ip_src,
		      const in_addr_t ip_dst,
		      const uint16_t protocol_number,
		      const uint16_t *tcp_header,
		      size_t length) {

  const uint16_t *buffer = tcp_header,
    *ip_src_ptr = (uint16_t *)&ip_src,
    *ip_dst_ptr = (uint16_t *)&ip_dst;
  uint32_t sum = 0;
  size_t len = length;

  while (length > 1) {
    sum += *buffer++;
    
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    length -= 2;
  }

  if (length & 1) sum += *((uint8_t *)buffer);

  sum += *(ip_src_ptr++);
  sum += *ip_src_ptr;
  sum += *(ip_dst_ptr++);
  sum += *ip_dst_ptr;
  sum += protocol_number;
  sum += len;

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ((uint16_t)(~sum));
}

// 3-way handshake: send SYN
void tcp_syn(int fd) {
  // IP header
  struct ip ip_header;
  memset(&ip_header, 0x0, sizeof(struct ip));

  ip_header.ip_hl = 5; // IPv4 header length
  ip_header.ip_v = 4; // IPv4 version
  ip_header.ip_tos = 0; // IPv4 type of service
  ip_header.ip_len = sizeof(struct ip) + sizeof(struct tcphdr); // IPv4 total length
  ip_header.ip_id = htons(12345); // Ipv4 identification
  ip_header.ip_off = IP_DF; // Ipv4 dont fragment flag
  ip_header.ip_ttl = MAXTTL ; // IPv4 time to live (255)
  ip_header.ip_p = IPPROTO_TCP; // TCP
  ip_header.ip_src.s_addr = inet_addr(ip_src_addr);
  ip_header.ip_dst.s_addr = inet_addr(ip_dst_addr);
  ip_header.ip_sum = ip_checksum((uint16_t *)&ip_header,
				 sizeof(ip_header)); // Ipv4 checksum

  /* TCP header 
     Cf: http://www.propox.com/download/edunet_doc/all/html/structtcphdr.html
  */
  struct tcphdr tcp_header;
  memset(&tcp_header, 0x0, sizeof(struct tcphdr));
  tcp_header.th_sport = htons(tcp_src_port); // TCP source port
  tcp_header.th_dport = htons(tcp_dst_port); // TCP destination port
  tcp_header.th_seq = htonl(0x123456); // Sequence number of first octet in this segment.
  tcp_header.th_off = sizeof(struct tcphdr) / 4;// Unused Data offset.
  tcp_header.th_flags = TH_SYN; // SYN request
  tcp_header.th_win = TCP_MAXWIN; // Number of acceptable octects.
  tcp_header.th_sum = tcp_checksum(ip_header.ip_src.s_addr,
				   ip_header.ip_dst.s_addr,
				   ip_header.ip_p,
				   (uint16_t *)&tcp_header,
				   sizeof(tcp_header));

  // Size of both headers (ip + tcp)
  size_t total_length = sizeof(ip_header) + sizeof(tcp_header);
  char packet[total_length] = { 0 };
  memcpy(packet, &ip_header, sizeof(ip_header));
  memcpy((sizeof(ip_header) + packet), &tcp_header, sizeof(tcp_header));

  struct sockaddr_in receiver;
  memset(&receiver, 0x0, sizeof(struct sockaddr_in));
  // Use struct ip to get @IP dst
  receiver.sin_family = AF_INET;
  receiver.sin_addr.s_addr = ip_header.ip_dst.s_addr;

  if (sendto(fd, packet, total_length, 0, (const struct sockaddr *)&receiver, sizeof(receiver)) < 0) {
    cerr << "Error: sendto()." << endl;
    close(fd);
    exit(EXIT_FAILURE);
  } else {
    cout << "Success: sendto()." << endl;
  }
}

/* 
   3-way handshake: send SYN-ACK.
   Exactly like function tcp_syn except we set the ack number
   and set the flag to ACK
*/
void tcp_syn_ack(int fd, // socket
		 const uint32_t no_seq) {
  // IP header
  struct ip ip_header;
  memset(&ip_header, 0x0, sizeof(struct ip));

  ip_header.ip_hl = 5; // IPv4 header length
  ip_header.ip_v = 4; // IPv4 version
  ip_header.ip_tos = 0; // IPv4 type of service
  ip_header.ip_len = sizeof(struct ip) + sizeof(struct tcphdr); // IPv4 total length
  ip_header.ip_id = htons(12345); // Ipv4 identification
  ip_header.ip_off = IP_DF; // Ipv4 dont fragment flag
  ip_header.ip_ttl = MAXTTL ; // IPv4 time to live (255)
  ip_header.ip_p = IPPROTO_TCP; // TCP
  ip_header.ip_src.s_addr = inet_addr(ip_src_addr);
  ip_header.ip_dst.s_addr = inet_addr(ip_dst_addr);
  ip_header.ip_sum = ip_checksum((uint16_t *)&ip_header,
				 sizeof(ip_header)); // Ipv4 checksum

  /* TCP header 
     Cf: http://www.propox.com/download/edunet_doc/all/html/structtcphdr.html
  */
  struct tcphdr tcp_header;
  memset(&tcp_header, 0x0, sizeof(struct tcphdr));
  tcp_header.th_sport = htons(tcp_src_port); // TCP source port
  tcp_header.th_dport = htons(tcp_dst_port); // TCP destination port
  tcp_header.th_seq = htonl(0x123456 + 1); // Sequence number of first octet in this segment. + 1
  tcp_header.th_ack = htonl(no_seq + 1);
  tcp_header.th_off = sizeof(struct tcphdr) / 4;// Unused Data offset.
  tcp_header.th_flags = TH_SYN; // SYN request
  tcp_header.th_win = TCP_MAXWIN; // Number of acceptable octects.
  tcp_header.th_sum = tcp_checksum(ip_header.ip_src.s_addr,
				   ip_header.ip_dst.s_addr,
				   ip_header.ip_p,
				   (uint16_t *)&tcp_header,
				   sizeof(tcp_header));

  // Size of both headers (ip + tcp)
  size_t total_length = sizeof(ip_header) + sizeof(tcp_header);
  char packet[total_length] = { 0 };
  memcpy(packet, &ip_header, sizeof(ip_header));
  memcpy((sizeof(ip_header) + packet), &tcp_header, sizeof(tcp_header));

  struct sockaddr_in receiver;
  memset(&receiver, 0x0, sizeof(struct sockaddr_in));
  // Use struct ip to get @IP dst
  receiver.sin_family = AF_INET;
  receiver.sin_addr.s_addr = ip_header.ip_dst.s_addr;

  if (sendto(fd, packet, total_length, 0, (const struct sockaddr *)&receiver, sizeof(receiver)) < 0) {
    cerr << "Error: sendto()." << endl;
    close(fd);
    exit(EXIT_FAILURE);
  } else {
    cout << "Success: sendto()." << endl;
  }
}

/*
  pcap_handler, if the server receives TCP - SYN he will reply a SYN+ACK packet
  so we have to intercept it and get the sequence number
  (See: http://www.tcpdump.org/manpages/pcap_loop.3pcap.html)
*/
void packet_intercepter(u_char *user,
			const struct pcap_pkthdr *h,
			const u_char *bytes) {
  uint32_t no_seq = 0x0;
  struct tcphdr *tcp_header = NULL;
  tcp_header = (tcphdr *)(bytes + sizeof(struct ether_header) + sizeof(struct ip));

  no_seq = ntohl(tcp_header->seq);

  tcp_syn_ack(raw_socket, no_seq);
}

// Capture TCP segment on a new thread
void * pthread_capture_tcp(void *arg) {
  pcap_t *open_device = NULL;
  char errbuf[PCAP_ERRBUF_SIZE]; // error buffer
  const char *device = "any"; // Capture from all device available
  stringstream tmp_filter;
  tmp_filter << "dst host " << ip_dst_addr << " and ip";
  const string filter = tmp_filter.str(); // Filters
  const int snaplen = 1514; // specifies the snapshot length to be set on the handle.
  const int promisc = 1; // specifies if the interface is to be put into promiscuous mode.
  const int to_ms = 250; // specifies the read timeout in milliseconds.
  bpf_u_int32 netp; //network number
  bpf_u_int32 maskp; // netmask
  struct bpf_program fp;

  // open a device for capturing
  if ((open_device = pcap_open_live(device, snaplen, promisc, to_ms, errbuf)) == NULL) {
    cerr << "Error: pcap_open_liv().\n\t" << errbuf << endl;
    close(raw_socket);
    exit(EXIT_FAILURE);
  }

  // find the IPv4 network number and netmask for a device
  if ((pcap_lookupnet(device, &netp, &maskp, errbuf)) == -1) {
    cerr << "Error: pcap_lookupnet().\n" << endl;
    close(raw_socket);
    exit(EXIT_FAILURE);
  }

  /*
    compile a filter expression
    fill fp with filter
  */
  if ((pcap_compile(open_device, &fp, filter.c_str(), 0, netp)) == -1) {
    cerr << "Error: pcap_compile().\n" << endl;
    close(raw_socket);
    exit(EXIT_FAILURE);
  }

  // TODO
  
}
