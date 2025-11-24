#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

// DNS server address
#define DNS_SERVER_IP   0x0A000203  // 10.0.2.3
#define DNS_SERVER_PORT 53
#define DNS_LOCAL_PORT  12345

// DNS header flags
#define DNS_RD 0x0100  // Recursion Desired

int encode_dns_name(char *encoded, char *hostname) {
  char *ptr = encoded;
  char *label_start = ptr;
  ptr++;
  
  int i = 0;
  int label_len = 0;
  
  while (hostname[i] != '\0') {
    if (hostname[i] == '.') {
      // write the label length
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
  
  // write the last label length
  *label_start = label_len;
  
  // null terminator
  *ptr = 0;
  ptr++;
  
  return ptr - encoded;
}

int build_dns_query(char *buf, char *hostname) {
  uint16 *ptr16 = (uint16 *)buf;
  
  // dns header (12 bytes)
  ptr16[0] = htons(0x1234);  // transaction id
  ptr16[1] = htons(0x0100);  // flags: standard query, recursion desired
  ptr16[2] = htons(1);       // qdcount: 1 question
  ptr16[3] = htons(0);       // ancount: 0 answers
  ptr16[4] = htons(0);       // nscount: 0 authority records
  ptr16[5] = htons(0);       // arcount: 0 additional records
  
  // encode the hostname
  char *qname = buf + 12;  // after 12-byte dns header
  int name_len = encode_dns_name(qname, hostname);
  
  // add question type (A record) and class (IN)
  struct dns_question *question = (struct dns_question *)(qname + name_len);
  question->qtype = htons(1);   // a record
  question->qclass = htons(1);  // in (internet)
  
  return 12 + name_len + sizeof(struct dns_question);
}

// skip over a dns name in the response
char *skip_dns_name(char *buf, char *start) {
  while (*buf != 0) {
    if ((*buf & 0xC0) == 0xC0) {
      // compression pointer (2 bytes)
      return buf + 2;
    }
    // regular label: skip length + label
    int len = *buf;
    buf += len + 1;
  }
  return buf + 1; // skip final 0
}

// parse dns response and extract ip address
int parse_dns_response(char *buf, int len, uint32 *ip_addr) {
  if (len < 12) {  // min dns header size
    printf("DNS response too short\n");
    return -1;
  }
  
  // parse dns header manually
  uint16 *ptr16 = (uint16 *)buf;
  uint16 flags = ntohs(ptr16[1]);
  uint16 qdcount = ntohs(ptr16[2]);
  uint16 ancount = ntohs(ptr16[3]);
  
  // check if response (qr bit set)
  if ((flags & 0x8000) == 0) {
    printf("Not a DNS response\n");
    return -1;
  }
  
  // check resp code
  if ((flags & 0x000F) != 0) {
    printf("DNS error, RCODE = %d\n", flags & 0x000F);
    return -1;
  }
  
  if (ancount == 0) {
    printf("No answers in DNS response\n");
    return -1;
  }
  
  // skip over question section
  char *ptr = buf + 12;  // after 12-byte dns header
  for (int i = 0; i < qdcount; i++) {
    ptr = skip_dns_name(ptr, buf);
    ptr += sizeof(struct dns_question);
  }
  
  // parse answer section
  for (int i = 0; i < ancount; i++) {
    // skip name
    ptr = skip_dns_name(ptr, buf);
    
    // read type, class, ttl, and data length
    struct dns_data *data = (struct dns_data *)ptr;
    uint16 type = ntohs(data->type);
    uint16 data_len = ntohs(data->len);
    
    ptr += sizeof(struct dns_data);
    
    // check if an a record (type 1)
    if (type == 1 && data_len == 4) {
      // Extract the IP address (4 bytes)
      uint32 addr = *(uint32 *)ptr;
      *ip_addr = ntohl(addr);
      return 0;
    }
    
    // skip to next record
    ptr += data_len;
  }
  
  printf("No A record found in DNS response\n");
  return -1;
}

// print an ip address in dotted decimal notation
void print_ip(uint32 ip) {
  printf("%d.%d.%d.%d\n",
         (ip >> 24) & 0xFF,
         (ip >> 16) & 0xFF,
         (ip >> 8) & 0xFF,
         ip & 0xFF);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: host <hostname>\n");
    printf("Example: host google.com\n");
    exit(1);
  }
  
  char *hostname = argv[1];
  
  // bind  local port for receiving response
  if (bind(DNS_LOCAL_PORT) < 0) {
    printf("bind() failed\n");
    exit(1);
  }
  
  // build dns query packet
  char query_buf[512];
  int query_len = build_dns_query(query_buf, hostname);
  
  // send dns query
  printf("Querying DNS for %s...\n", hostname);
  if (send(DNS_LOCAL_PORT, DNS_SERVER_IP, DNS_SERVER_PORT, query_buf, query_len) < 0) {
    printf("send() failed\n");
    exit(1);
  }
  
  // receive dns response
  char response_buf[512];
  uint32 src_ip;
  uint16 src_port;
  
  int response_len = recv(DNS_LOCAL_PORT, &src_ip, &src_port, response_buf, sizeof(response_buf));
  if (response_len < 0) {
    printf("recv() failed\n");
    exit(1);
  }
  
  // parse dns response
  uint32 ip_addr;
  if (parse_dns_response(response_buf, response_len, &ip_addr) < 0) {
    printf("Failed to parse DNS response\n");
    exit(1);
  }
  
  // print result
  printf("%s has address ", hostname);
  print_ip(ip_addr);
  
  exit(0);
}

