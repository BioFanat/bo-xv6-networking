//
// ping - ICMP echo request/reply utility with DNS support
//

#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

// DNS configuration
#define DNS_SERVER_IP   0x0A000203  // 10.0.2.3 (QEMU DNS server)
#define DNS_SERVER_PORT 53
#define DNS_LOCAL_PORT  12345

// Encode a hostname into DNS wire format
int encode_dns_name(char *encoded, char *hostname) {
  char *ptr = encoded;
  char *label_start = ptr;
  ptr++;
  
  int i = 0;
  int label_len = 0;
  
  while (hostname[i] != '\0') {
    if (hostname[i] == '.') {
      *label_start = label_len;
      label_start = ptr;
      ptr++;
      label_len = 0;
    } else {
      *ptr = hostname[i];
      ptr++;
      label_len++;
    }
    i++;
  }
  
  *label_start = label_len;
  *ptr = 0;
  ptr++;
  
  return ptr - encoded;
}

// Build a DNS query packet
int build_dns_query(char *buf, char *hostname) {
  uint16 *ptr16 = (uint16 *)buf;
  
  ptr16[0] = htons(0x1234);
  ptr16[1] = htons(0x0100);
  ptr16[2] = htons(1);
  ptr16[3] = htons(0);
  ptr16[4] = htons(0);
  ptr16[5] = htons(0);
  
  char *qname = buf + 12;
  int name_len = encode_dns_name(qname, hostname);
  
  struct dns_question *question = (struct dns_question *)(qname + name_len);
  question->qtype = htons(1);
  question->qclass = htons(1);
  
  return 12 + name_len + sizeof(struct dns_question);
}

// Skip over a DNS name in the response
char *skip_dns_name(char *buf, char *start) {
  while (*buf != 0) {
    if ((*buf & 0xC0) == 0xC0) {
      return buf + 2;
    }
    int len = *buf;
    buf += len + 1;
  }
  return buf + 1;
}

// Parse DNS response and extract IP address
int parse_dns_response(char *buf, int len, uint32 *ip_addr) {
  if (len < 12) {
    return -1;
  }
  
  uint16 *ptr16 = (uint16 *)buf;
  uint16 flags = ntohs(ptr16[1]);
  uint16 qdcount = ntohs(ptr16[2]);
  uint16 ancount = ntohs(ptr16[3]);
  
  if ((flags & 0x8000) == 0) {
    return -1;
  }
  
  if ((flags & 0x000F) != 0) {
    return -1;
  }
  
  if (ancount == 0) {
    return -1;
  }
  
  char *ptr = buf + 12;
  for (int i = 0; i < qdcount; i++) {
    ptr = skip_dns_name(ptr, buf);
    ptr += sizeof(struct dns_question);
  }
  
  for (int i = 0; i < ancount; i++) {
    ptr = skip_dns_name(ptr, buf);
    
    struct dns_data *data = (struct dns_data *)ptr;
    uint16 type = ntohs(data->type);
    uint16 data_len = ntohs(data->len);
    
    ptr += sizeof(struct dns_data);
    
    if (type == 1 && data_len == 4) {
      uint32 addr = *(uint32 *)ptr;
      *ip_addr = ntohl(addr);
      return 0;
    }
    
    ptr += data_len;
  }
  
  return -1;
}

// Resolve hostname to IP address
int resolve_hostname(char *hostname, uint32 *ip_addr) {
  if (bind(DNS_LOCAL_PORT) < 0) {
    return -1;
  }
  
  char query_buf[512];
  int query_len = build_dns_query(query_buf, hostname);
  
  if (send(DNS_LOCAL_PORT, DNS_SERVER_IP, DNS_SERVER_PORT, query_buf, query_len) < 0) {
    return -1;
  }
  
  char response_buf[512];
  uint32 src_ip;
  uint16 src_port;
  
  int response_len = recv(DNS_LOCAL_PORT, &src_ip, &src_port, response_buf, sizeof(response_buf));
  if (response_len < 0) {
    return -1;
  }
  
  return parse_dns_response(response_buf, response_len, ip_addr);
}

// Check if string is a hostname or IP address
int is_ip_address(char *str) {
  int dots = 0;
  for (int i = 0; str[i]; i++) {
    if (str[i] == '.') {
      dots++;
    } else if (str[i] < '0' || str[i] > '9') {
      return 0;  // not an IP
    }
  }
  return dots == 3;
}

// ICMP checksum calculation
static uint16 icmp_checksum(uint16 *addr, int len) {
  uint32 sum = 0;
  uint16 *w = addr;
  int nleft = len;
  
  // sum 16-bit words
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
  
  // mop up odd byte if necessary
  if (nleft == 1) {
    sum += *(uint8 *)w;
  }
  
  // fold 32-bit sum to 16 bits
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  
  return ~sum;
}

// Get high-resolution time using system call (10MHz clock)
static uint64 get_time(void) {
  return gettime();
}

// Convert time units to microseconds (rdtime is 10MHz = 0.1us per tick)
static uint64 time_to_usec(uint64 time_diff) {
  return time_diff / 10;  // 10MHz = 10 ticks per microsecond
}

// Convert time units to milliseconds
static uint64 time_to_msec(uint64 time_diff) {
  return time_diff / 10000;  // 10MHz = 10000 ticks per millisecond
}

// Send ICMP Echo Request
int send_ping(uint32 dst_ip, uint16 id, uint16 seq) {
  char buf[64];
  struct icmp *icmp_hdr = (struct icmp *)buf;
  
  // build ICMP header
  icmp_hdr->type = ICMP_ECHO_REQUEST;
  icmp_hdr->code = 0;
  icmp_hdr->checksum = 0;
  icmp_hdr->id = htons(id);
  icmp_hdr->seq = htons(seq);
  
  // add data: timestamp at start, then pad to 56 bytes total
  uint64 *timestamp = (uint64 *)(buf + sizeof(struct icmp));
  *timestamp = get_time();
  
  // fill rest with pattern (standard ping uses incrementing byte pattern)
  for (int i = sizeof(struct icmp) + sizeof(uint64); i < sizeof(struct icmp) + 56; i++) {
    buf[i] = (i - sizeof(struct icmp)) & 0xFF;
  }
  
  int packet_len = sizeof(struct icmp) + 56;  // 8 + 56 = 64 bytes total
  
  // calculate checksum
  icmp_hdr->checksum = icmp_checksum((uint16 *)buf, packet_len);
  
  // send via raw socket
  return rawsock_send(dst_ip, IPPROTO_ICMP, buf, packet_len);
}

// Receive ICMP Echo Reply
int recv_ping(int sockid, uint32 *src_ip, uint16 *reply_id, uint16 *reply_seq, uint64 *rtt) {
  char buf[512];
  
  // receive IP packet
  int len = rawsock_recv(sockid, src_ip, buf, sizeof(buf));
  if (len < 0) {
    return -1;
  }
  
  // parse IP header
  struct ip *ip_hdr = (struct ip *)buf;
  int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
  
  // check if it's ICMP
  if (ip_hdr->ip_p != IPPROTO_ICMP) {
    return -1;
  }
  
  // parse ICMP header
  struct icmp *icmp_hdr = (struct icmp *)(buf + ip_header_len);
  
  // check if it's an Echo Reply
  if (icmp_hdr->type != ICMP_ECHO_REPLY) {
    return -1;
  }
  
  *reply_id = ntohs(icmp_hdr->id);
  *reply_seq = ntohs(icmp_hdr->seq);
  
  // calculate round-trip time
  uint64 *timestamp = (uint64 *)(buf + ip_header_len + sizeof(struct icmp));
  uint64 now = get_time();
  *rtt = now - *timestamp;
  
  return 0;
}

// Print IP address (without newline)
void print_ip(uint32 ip) {
  printf("%d.%d.%d.%d",
         (ip >> 24) & 0xFF,
         (ip >> 16) & 0xFF,
         (ip >> 8) & 0xFF,
         ip & 0xFF);
}

// Print IP address with newline
void print_ip_ln(uint32 ip) {
  print_ip(ip);
  printf("\n");
}

int main(int argc, char *argv[]) {
  if (argc != 2 && argc != 3) {
    printf("Usage: ping <hostname|ip_address> [count]\n");
    printf("Example: ping google.com\n");
    printf("Example: ping 10.0.2.2\n");
    printf("Example: ping 8.8.8.8 4\n");
    exit(1);
  }
  
  char *target = argv[1];
  uint32 dst_ip;
  
  // check if target is IP address or hostname
  if (is_ip_address(target)) {
    // parse IP address (simple format: a.b.c.d)
    uint32 a = 0, b = 0, c = 0, d = 0;
    int i = 0, num = 0, dots = 0;
    
    while (target[i]) {
      if (target[i] >= '0' && target[i] <= '9') {
        num = num * 10 + (target[i] - '0');
      } else if (target[i] == '.') {
        if (dots == 0) a = num;
        else if (dots == 1) b = num;
        else if (dots == 2) c = num;
        num = 0;
        dots++;
      }
      i++;
    }
    d = num;
    
    if (dots != 3 || a > 255 || b > 255 || c > 255 || d > 255) {
      printf("Invalid IP address format\n");
      exit(1);
    }
    
    dst_ip = (a << 24) | (b << 16) | (c << 8) | d;
  } else {
    // resolve hostname via DNS
    printf("PING %s (", target);
    if (resolve_hostname(target, &dst_ip) < 0) {
      printf("Failed to resolve hostname\n");
      exit(1);
    }
    print_ip(dst_ip);
    printf(")\n");
  }
  
  // parse count (default 10)
  int count = 10;
  if (argc == 3) {
    count = 0;
    for (int j = 0; argv[2][j]; j++) {
      if (argv[2][j] >= '0' && argv[2][j] <= '9') {
        count = count * 10 + (argv[2][j] - '0');
      }
    }
    if (count <= 0) count = 10;
  }
  
  // bind raw socket for ICMP
  int sockid = rawsock_bind(IPPROTO_ICMP);
  if (sockid < 0) {
    printf("Failed to bind ICMP socket\n");
    exit(1);
  }
  
  // print header (unless already printed for hostname)
  if (is_ip_address(target)) {
    printf("PING ");
    print_ip(dst_ip);
    printf(" %d data bytes\n", 56);
  } else {
    printf("%d data bytes\n", 56);
  }
  
  uint16 pid = getpid() & 0xFFFF;
  int received = 0;
  uint64 total_rtt = 0;
  uint64 min_rtt = (uint64)-1; 
  uint64 max_rtt = 0;
  
  for (int seq = 0; seq < count; seq++) {
    // send ping
    if (send_ping(dst_ip, pid, seq) < 0) {
      printf("Failed to send ping %d\n", seq);
      continue;
    }
    
    // wait for reply (with timeout simulation using multiple attempts)
    int timeout = 0;
    while (timeout < 3) {  // try 3 times
      uint32 src_ip;
      uint16 reply_id, reply_seq;
      uint64 rtt;
      
      if (recv_ping(sockid, &src_ip, &reply_id, &reply_seq, &rtt) == 0) {
        // check if reply matches our request
        if (reply_id == pid && reply_seq == seq) {
          received++;
          total_rtt += rtt;
          
          if (rtt < min_rtt) min_rtt = rtt;
          if (rtt > max_rtt) max_rtt = rtt;

          printf("%d bytes from ", 64);
          print_ip(src_ip);
          
          // display time in appropriate units
          uint64 rtt_usec = time_to_usec(rtt);
          if (rtt_usec < 1000) {
            printf(": icmp_seq=%d time=%d usec\n", seq, (int)rtt_usec);
          } else {
            uint64 rtt_msec = time_to_msec(rtt);
            if (rtt_msec < 10) {
              // show as decimal milliseconds for < 10ms
              printf(": icmp_seq=%d time=%d.%d ms\n", seq, 
                     (int)rtt_msec, (int)((rtt_usec % 1000) / 100));
            } else {
              printf(": icmp_seq=%d time=%d ms\n", seq, (int)rtt_msec);
            }
          }
          break;
        }
      }
      timeout++;
    }
    
    if (timeout >= 3) {
      printf("Request timeout for icmp_seq %d\n", seq);
    }
    
    // small delay between pings
    pause(10);
  }
  
  // print statistics
  printf("\n--- ");
  if (is_ip_address(target)) {
    print_ip(dst_ip);
  } else {
    printf("%s", target);
  }
  printf(" ping statistics ---\n");
  printf("%d packets transmitted, %d received, %d%% packet loss\n",
         count, received, (count - received) * 100 / count);
  
  if (received > 0) {
    uint64 avg_rtt = total_rtt / received;
    uint64 min_usec = time_to_usec(min_rtt);
    uint64 avg_usec = time_to_usec(avg_rtt);
    uint64 max_usec = time_to_usec(max_rtt);

    // Display min/avg/max (standard ping format)
    if (max_usec < 1000) {
      // All values under 1ms - show in usec
      printf("rtt min/avg/max = %d/%d/%d usec\n",
             (int)min_usec, (int)avg_usec, (int)max_usec);
    } else {
      // Some values over 1ms - show in ms with decimal
      uint64 min_msec = time_to_msec(min_rtt);
      uint64 avg_msec = time_to_msec(avg_rtt);
      uint64 max_msec = time_to_msec(max_rtt);
      printf("rtt min/avg/max = %d.%d/%d.%d/%d.%d ms\n",
             (int)min_msec, (int)((min_usec % 1000) / 100),
             (int)avg_msec, (int)((avg_usec % 1000) / 100),
             (int)max_msec, (int)((max_usec % 1000) / 100));
    }
  }
  
  exit(0);
}

