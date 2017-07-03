#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdint> // uint16_t
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h> // inet_addr
#include <sys/socket.h> // socket
#include <netinet/in.h> // socket
#include <netinet/ip.h> // struct ip
#include <netinet/tcp.h> // tcphdr

using namespace std;

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
void tcp_syn(int fd,
	     const char *ip_src_addr,
	     const char *ip_dst_addr,
	     const uint16_t tcp_src_port,
	     const uint16_t tcp_dst_port);

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
  int status = EXIT_FAILURE,
    raw_socket = 0;
  const int optval = 1;
  
  cout << "Hello World" << endl;

  // Creates RAW socket
  if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    cerr << "Error: socket()." << endl;
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
  tcp_syn(raw_socket, "192.168.1.10", "192.168.1.1", 6666, 55555);

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
void tcp_syn(int fd,
	     const char *ip_src_addr,
	     const char *ip_dst_addr,
	     const uint16_t tcp_src_port,
	     const uint16_t tcp_dst_port) {
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
