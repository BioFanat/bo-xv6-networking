#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

static uint64 get_time(void) {
  return gettime();
}

static uint64 time_to_usec(uint64 time_diff) {
  return time_diff / 10;  // 10MHz = 10 ticks per microsecond
}

static uint64 time_to_msec(uint64 time_diff) {
  return time_diff / 10000;  // 10MHz = 10000 ticks per millisecond
}

#define DNS_SERVER_IP   0x0A000203  // 10.0.2.3
#define DNS_SERVER_PORT 53
#define DNS_LOCAL_PORT  12345

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
  
  *label_start = label_len;
  
  *ptr = 0;
  ptr++;
  
  return ptr - encoded;
}

int build_dns_query(char *buf, char *hostname) {
  uint16 *ptr16 = (uint16 *)buf;
  
  ptr16[0] = htons(0x1234);  // transaction id
  ptr16[1] = htons(0x0100);  // flags: standard query, recursion desired
  ptr16[2] = htons(1);       // qdcount: 1 question
  ptr16[3] = htons(0);       // ancount: 0 answers
  ptr16[4] = htons(0);       // nscount: 0 authority records
  ptr16[5] = htons(0);       // arcount: 0 additional records
  
  char *qname = buf + 12;
  int name_len = encode_dns_name(qname, hostname);
  
  struct dns_question *question = (struct dns_question *)(qname + name_len);
  question->qtype = htons(1);   // a record
  question->qclass = htons(1);  // in (internet)
  
  return 12 + name_len + sizeof(struct dns_question);
}

char *skip_dns_name(char *buf, char *start) {
  while (*buf != 0) {
    if ((*buf & 0xC0) == 0xC0) {
      // compression pointer (2 bytes)
      return buf + 2;
    }
    int len = *buf;
    buf += len + 1;
  }
  return buf + 1; // skip final 0
}

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
  
  char *ptr = buf + 12;
  for (int i = 0; i < qdcount; i++) {
    ptr = skip_dns_name(ptr, buf);
    ptr += sizeof(struct dns_question);
  }
  
  // parse answer section
  for (int i = 0; i < ancount; i++) {
    ptr = skip_dns_name(ptr, buf);
    
    struct dns_data *data = (struct dns_data *)ptr;
    uint16 type = ntohs(data->type);
    uint16 data_len = ntohs(data->len);
    
    ptr += sizeof(struct dns_data);
    
    // check if an a record (type 1)
    if (type == 1 && data_len == 4) {
      uint32 addr = *(uint32 *)ptr;
      *ip_addr = ntohl(addr);
      return 0;
    }
    
    ptr += data_len;
  }
  
  printf("No A record found in DNS response\n");
  return -1;
}

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
  
  uint64 start_time = get_time();

  printf("Querying DNS for %s...\n", hostname);
  if (send(DNS_LOCAL_PORT, DNS_SERVER_IP, DNS_SERVER_PORT, query_buf, query_len) < 0) {
    printf("send() failed\n");
    exit(1);
  }
  
  char response_buf[512];
  uint32 src_ip;
  uint16 src_port;
  
  int response_len = recv(DNS_LOCAL_PORT, &src_ip, &src_port, response_buf, sizeof(response_buf));
  if (response_len < 0) {
    printf("recv() failed\n");
    exit(1);
  }
  
  uint32 ip_addr;
  if (parse_dns_response(response_buf, response_len, &ip_addr) < 0) {
    printf("Failed to parse DNS response\n");
    exit(1);
  }


  uint64 end_time = get_time();
  uint64 dns_latency = end_time - start_time;

  printf("%s has address ", hostname);
  print_ip(ip_addr);

  uint64 latency_usec = time_to_usec(dns_latency);
  uint64 latency_msec = time_to_msec(dns_latency);

  if (latency_usec < 1000) {
    printf(" (query time: %d usec)\n", (int)latency_usec);
  } else {
    printf(" (query time: %d.%d ms)\n",
           (int)latency_msec, (int)((latency_usec % 1000) / 100));
  }

  exit(0);
}

