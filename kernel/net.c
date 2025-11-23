#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };

static struct spinlock netlock;

// UDP receive queue structures
#define NPORT 16        // max number of bound ports
#define NPACKET 16      // max packets queued per port

struct packet {
  char *buf;            // packet buffer
  uint32 src_ip;        // source IP address (host byte order)
  uint16 src_port;      // source port (host byte order)
  uint16 len;           // payload length
};

struct port {
  int bound;            // is this port bound?
  uint16 port;          // port number (host byte order)
  struct packet packets[NPACKET];  // packet queue
  int head;             // queue head index
  int tail;             // queue tail index
  int count;            // number of packets in queue
};

static struct port ports[NPORT];

void
netinit(void)
{
  initlock(&netlock, "netlock");
  
  // initialize port structures
  for(int i = 0; i < NPORT; i++) {
    ports[i].bound = 0;
    ports[i].port = 0;
    ports[i].head = 0;
    ports[i].tail = 0;
    ports[i].count = 0;
  }
}


//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64
sys_bind(void)
{
  int port;
  argint(0, &port);
  
  acquire(&netlock);
  
  // check if port is already bound
  for(int i = 0; i < NPORT; i++) {
    if(ports[i].bound && ports[i].port == port) {
      release(&netlock);
      return 0;  // already bound, success
    }
  }
  
  // find a free port structure
  for(int i = 0; i < NPORT; i++) {
    if(!ports[i].bound) {
      ports[i].bound = 1;
      ports[i].port = port;
      ports[i].head = 0;
      ports[i].tail = 0;
      ports[i].count = 0;
      release(&netlock);
      return 0;
    }
  }
  
  release(&netlock);
  return -1;  // no free port structures
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void)
{
  //
  // Optional: Your code here.
  //

  return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64
sys_recv(void)
{
  struct proc *p = myproc();
  int dport;
  uint64 src_addr, sport_addr, buf_addr;
  int maxlen;
  
  argint(0, &dport);
  argaddr(1, &src_addr);
  argaddr(2, &sport_addr);
  argaddr(3, &buf_addr);
  argint(4, &maxlen);
  
  acquire(&netlock);
  
  // find the bound port
  int port_idx = -1;
  for(int i = 0; i < NPORT; i++) {
    if(ports[i].bound && ports[i].port == dport) {
      port_idx = i;
      break;
    }
  }
  
  // if port not bound, error
  if(port_idx == -1) {
    release(&netlock);
    return -1;
  }
  
  // wait for a packet to arrive
  while(ports[port_idx].count == 0) {
    sleep(&ports[port_idx], &netlock);
  }
  
  // get packet from head of queue
  int head = ports[port_idx].head;
  struct packet *pkt = &ports[port_idx].packets[head];
  
  uint32 src_ip = pkt->src_ip;
  uint16 src_port = pkt->src_port;
  uint16 pkt_len = pkt->len;
  char *pkt_buf = pkt->buf;
  
  // update queue
  ports[port_idx].head = (head + 1) % NPACKET;
  ports[port_idx].count--;
  
  release(&netlock);
  
  // copy data to user space
  int copy_len = pkt_len < maxlen ? pkt_len : maxlen;
  
  if(copyout(p->pagetable, buf_addr, pkt_buf, copy_len) < 0) {
    kfree(pkt_buf);
    return -1;
  }
  
  // copy source IP and port to user space
  if(copyout(p->pagetable, src_addr, (char *)&src_ip, sizeof(src_ip)) < 0) {
    kfree(pkt_buf);
    return -1;
  }
  
  if(copyout(p->pagetable, sport_addr, (char *)&src_port, sizeof(src_port)) < 0) {
    kfree(pkt_buf);
    return -1;
  }
  
  // free the packet buffer
  kfree(pkt_buf);
  
  return copy_len;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if(total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if(buf == 0){
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if(copyin(p->pagetable, payload, bufaddr, len) < 0){
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  e1000_transmit(buf, total);

  return 0;
}

void
ip_rx(char *buf, int len)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if(seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  // parse packet headers
  struct eth *eth = (struct eth *)buf;
  struct ip *ip = (struct ip *)(eth + 1);
  struct udp *udp = (struct udp *)(ip + 1);
  
  // check if it's a UDP packet
  if(ip->ip_p != IPPROTO_UDP) {
    kfree(buf);
    return;
  }
  
  // check minimum length for UDP
  if(len < sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp)) {
    kfree(buf);
    return;
  }
  
  // extract UDP info (convert from network to host byte order)
  uint16 dport = ntohs(udp->dport);
  uint16 sport = ntohs(udp->sport);
  uint32 src_ip = ntohl(ip->ip_src);
  uint16 udp_len = ntohs(udp->ulen);
  
  // calculate payload length
  uint16 payload_len = udp_len - sizeof(struct udp);
  
  acquire(&netlock);
  
  // find the bound port
  int port_idx = -1;
  for(int i = 0; i < NPORT; i++) {
    if(ports[i].bound && ports[i].port == dport) {
      port_idx = i;
      break;
    }
  }
  
  // if port not bound, drop packet
  if(port_idx == -1) {
    release(&netlock);
    kfree(buf);
    return;
  }
  
  // if queue is full (16 packets), drop packet
  if(ports[port_idx].count >= NPACKET) {
    release(&netlock);
    kfree(buf);
    return;
  }
  
  // allocate a new buffer for the payload
  char *payload_buf = kalloc();
  if(payload_buf == 0) {
    release(&netlock);
    kfree(buf);
    return;
  }
  
  // copy UDP payload
  char *payload = (char *)(udp + 1);
  memmove(payload_buf, payload, payload_len);
  
  // add packet to queue
  int tail = ports[port_idx].tail;
  ports[port_idx].packets[tail].buf = payload_buf;
  ports[port_idx].packets[tail].src_ip = src_ip;
  ports[port_idx].packets[tail].src_port = sport;
  ports[port_idx].packets[tail].len = payload_len;
  
  ports[port_idx].tail = (tail + 1) % NPACKET;
  ports[port_idx].count++;
  
  // wake up any process waiting for packets on this port
  wakeup(&ports[port_idx]);
  
  release(&netlock);
  
  // free the original buffer (we've copied the payload)
  kfree(buf);
}

//
// send an ARP reply packet to tell qemu to map
// xv6's ip address to its ethernet address.
// this is the bare minimum needed to persuade
// qemu to send IP packets to xv6; the real ARP
// protocol is more complex.
//
void
arp_rx(char *inbuf)
{
  static int seen_arp = 0;

  if(seen_arp){
    kfree(inbuf);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct eth *ineth = (struct eth *) inbuf;
  struct arp *inarp = (struct arp *) (ineth + 1);

  char *buf = kalloc();
  if(buf == 0)
    panic("send_arp_reply");
  
  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN); // ethernet destination = query source
  memmove(eth->shost, local_mac, ETHADDR_LEN); // ethernet source = xv6's ethernet address
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void
net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;

  if(len >= sizeof(struct eth) + sizeof(struct arp) &&
     ntohs(eth->type) == ETHTYPE_ARP){
    arp_rx(buf);
  } else if(len >= sizeof(struct eth) + sizeof(struct ip) &&
     ntohs(eth->type) == ETHTYPE_IP){
    ip_rx(buf, len);
  } else {
    kfree(buf);
  }
}
