//
// HTTP client for xv6
// Simple HTTP/1.0 GET client using TCP
//

#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

#define DNS_SERVER_IP   0x0A000203  // 10.0.2.3 (QEMU DNS server)
#define DNS_SERVER_PORT 53
#define DNS_LOCAL_PORT  12346

// DNS helper functions (reused from ping.c pattern)

int
encode_dns_name(char *encoded, char *hostname)
{
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

int
build_dns_query(char *buf, char *hostname)
{
  uint16 *ptr16 = (uint16 *)buf;

  ptr16[0] = htons(0x1234);  // transaction id
  ptr16[1] = htons(0x0100);  // flags: standard query, recursion desired
  ptr16[2] = htons(1);       // qdcount: 1 question
  ptr16[3] = htons(0);       // ancount
  ptr16[4] = htons(0);       // nscount
  ptr16[5] = htons(0);       // arcount

  char *qname = buf + 12;
  int name_len = encode_dns_name(qname, hostname);

  struct dns_question *question = (struct dns_question *)(qname + name_len);
  question->qtype = htons(1);   // A record
  question->qclass = htons(1);  // IN (internet)

  return 12 + name_len + sizeof(struct dns_question);
}

char *
skip_dns_name(char *buf, char *start)
{
  while (*buf != 0) {
    if ((*buf & 0xC0) == 0xC0) {
      return buf + 2;
    }
    int len = *buf;
    buf += len + 1;
  }
  return buf + 1;
}

int
parse_dns_response(char *buf, int len, uint32 *ip_addr)
{
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

int
resolve_hostname(char *hostname, uint32 *ip_addr)
{
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

int
is_ip_address(char *str)
{
  int dots = 0;
  for (int i = 0; str[i]; i++) {
    if (str[i] == '.') {
      dots++;
    } else if (str[i] < '0' || str[i] > '9') {
      return 0;
    }
  }
  return dots == 3;
}

uint32
parse_ip(char *str)
{
  uint32 a = 0, b = 0, c = 0, d = 0;
  int i = 0, num = 0, dots = 0;

  while (str[i]) {
    if (str[i] >= '0' && str[i] <= '9') {
      num = num * 10 + (str[i] - '0');
    } else if (str[i] == '.') {
      if (dots == 0) a = num;
      else if (dots == 1) b = num;
      else if (dots == 2) c = num;
      num = 0;
      dots++;
    }
    i++;
  }
  d = num;

  return (a << 24) | (b << 16) | (c << 8) | d;
}

// URL parsing: http://host:port/path or http://host/path
int
parse_url(char *url, char *host, int *port, char *path)
{
  // Skip "http://" if present
  if (url[0] == 'h' && url[1] == 't' && url[2] == 't' && url[3] == 'p' &&
      url[4] == ':' && url[5] == '/' && url[6] == '/') {
    url += 7;
  }

  // Find end of host (: or / or end of string)
  int i = 0;
  while (url[i] && url[i] != ':' && url[i] != '/') {
    host[i] = url[i];
    i++;
  }
  host[i] = '\0';

  // Parse port if present
  *port = 80;  // default
  if (url[i] == ':') {
    i++;
    *port = 0;
    while (url[i] >= '0' && url[i] <= '9') {
      *port = *port * 10 + (url[i] - '0');
      i++;
    }
  }

  // Copy path
  if (url[i] == '/') {
    strcpy(path, url + i);
  } else {
    path[0] = '/';
    path[1] = '\0';
  }

  return 0;
}

void
print_ip(uint32 ip)
{
  printf("%d.%d.%d.%d",
         (ip >> 24) & 0xFF,
         (ip >> 16) & 0xFF,
         (ip >> 8) & 0xFF,
         ip & 0xFF);
}

int
main(int argc, char *argv[])
{
  if (argc != 2) {
    printf("Usage: http <url>\n");
    printf("Example: http http://example.com/index.html\n");
    printf("         http http://10.0.2.2:8080/test\n");
    exit(1);
  }

  char host[128];
  char path[256];
  int port;

  if (parse_url(argv[1], host, &port, path) < 0) {
    printf("Invalid URL\n");
    exit(1);
  }

  printf("Host: %s, Port: %d, Path: %s\n", host, port, path);

  // Resolve host to IP
  uint32 ip;
  if (is_ip_address(host)) {
    ip = parse_ip(host);
  } else {
    printf("Resolving %s...\n", host);
    if (resolve_hostname(host, &ip) < 0) {
      printf("Failed to resolve hostname\n");
      exit(1);
    }
    printf("Resolved to ");
    print_ip(ip);
    printf("\n");
  }

  // Connect via TCP
  printf("Connecting to ");
  print_ip(ip);
  printf(":%d...\n", port);

  int sock = tcp_connect(ip, port);
  if (sock < 0) {
    printf("tcp_connect failed\n");
    exit(1);
  }
  printf("Connected!\n");

  // Build HTTP request
  char request[512];
  char *p = request;

  // GET /path HTTP/1.0\r\n
  strcpy(p, "GET ");
  p += 4;
  strcpy(p, path);
  p += strlen(path);
  strcpy(p, " HTTP/1.0\r\n");
  p += 11;

  // Host: hostname\r\n
  strcpy(p, "Host: ");
  p += 6;
  strcpy(p, host);
  p += strlen(host);
  strcpy(p, "\r\n");
  p += 2;

  // Connection: close\r\n
  strcpy(p, "Connection: close\r\n");
  p += 19;

  // \r\n (end of headers)
  strcpy(p, "\r\n");
  p += 2;

  int request_len = p - request;

  printf("Sending request (%d bytes)...\n", request_len);
  if (tcp_send(sock, request, request_len) < 0) {
    printf("tcp_send failed\n");
    tcp_close(sock);
    exit(1);
  }

  // Receive response
  printf("\n--- Response ---\n");
  char buf[1024];
  int n;
  int total = 0;
  while ((n = tcp_recv(sock, buf, sizeof(buf) - 1)) > 0) {
    buf[n] = '\0';
    printf("%s", buf);
    total += n;
  }
  printf("\n--- End (%d bytes received) ---\n", total);

  tcp_close(sock);
  exit(0);
}
