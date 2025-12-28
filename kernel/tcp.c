//
// TCP protocol implementation for xv6
// Client-only with basic retransmission
//

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "net.h"

// External network configuration from net.c
extern uint8 local_mac[6];
extern uint8 host_mac[6];
extern uint32 local_ip;
extern struct spinlock netlock;

// TCP connection table
static struct tcp_conn tcp_conns[NTCP];
static uint16 tcp_next_port = 49152;  // ephemeral port range start

// Forward declarations
static int tcp_send_segment(struct tcp_conn *conn, uint8 flags, char *data, int data_len);
static void tcp_free_conn(struct tcp_conn *conn);

//
// TCP checksum calculation with pseudo-header
//
static uint16
tcp_checksum(uint32 src_ip, uint32 dst_ip, struct tcp *tcp_hdr,
             char *data, int data_len)
{
  uint32 sum = 0;
  int tcp_total_len = sizeof(struct tcp) + data_len;

  // Add pseudo-header fields (in network byte order)
  uint32 src_n = htonl(src_ip);
  uint32 dst_n = htonl(dst_ip);
  sum += (src_n >> 16) & 0xFFFF;
  sum += src_n & 0xFFFF;
  sum += (dst_n >> 16) & 0xFFFF;
  sum += dst_n & 0xFFFF;
  sum += htons(IPPROTO_TCP);
  sum += htons(tcp_total_len);

  // Add TCP header
  uint16 *ptr = (uint16 *)tcp_hdr;
  int len = sizeof(struct tcp);
  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }

  // Add data
  ptr = (uint16 *)data;
  len = data_len;
  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }
  if (len == 1) {
    sum += *(uint8 *)ptr;
  }

  // Fold 32-bit sum to 16 bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ~sum;
}

//
// IP header checksum (same as in net.c)
//
static uint16
ip_checksum(unsigned char *addr, int len)
{
  int nleft = len;
  const uint16 *w = (const uint16 *)addr;
  uint32 sum = 0;
  uint16 answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);

  answer = ~sum;
  return answer;
}

//
// Allocate ephemeral port
//
static uint16
tcp_alloc_port(void)
{
  uint16 port = tcp_next_port++;
  if (tcp_next_port > 65535)
    tcp_next_port = 49152;
  return port;
}

//
// Generate initial sequence number
//
static uint32
tcp_gen_iss(void)
{
  return (uint32)(r_time() & 0xFFFFFFFF);
}

//
// Allocate a connection slot
//
static struct tcp_conn *
tcp_alloc_conn(void)
{
  for (int i = 0; i < NTCP; i++) {
    if (!tcp_conns[i].used) {
      struct tcp_conn *conn = &tcp_conns[i];
      memset(conn, 0, sizeof(*conn));
      conn->used = 1;
      conn->state = TCP_CLOSED;
      conn->snd_buf = kalloc();
      conn->rcv_buf = kalloc();
      if (!conn->snd_buf || !conn->rcv_buf) {
        if (conn->snd_buf) kfree(conn->snd_buf);
        if (conn->rcv_buf) kfree(conn->rcv_buf);
        conn->used = 0;
        return 0;
      }
      memset(conn->snd_buf, 0, TCP_BUFSIZE);
      memset(conn->rcv_buf, 0, TCP_BUFSIZE);
      return conn;
    }
  }
  return 0;
}

//
// Free a connection slot
//
static void
tcp_free_conn(struct tcp_conn *conn)
{
  if (conn->snd_buf) {
    kfree(conn->snd_buf);
    conn->snd_buf = 0;
  }
  if (conn->rcv_buf) {
    kfree(conn->rcv_buf);
    conn->rcv_buf = 0;
  }
  conn->used = 0;
  conn->state = TCP_CLOSED;
}

//
// Send a TCP segment
//
static int
tcp_send_segment(struct tcp_conn *conn, uint8 flags, char *data, int data_len)
{
  int total = sizeof(struct eth) + sizeof(struct ip) +
              sizeof(struct tcp) + data_len;
  if (total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if (buf == 0)
    return -1;
  memset(buf, 0, PGSIZE);

  // Build Ethernet header
  struct eth *eth = (struct eth *)buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  // Build IP header
  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45;  // version 4, header length 20 bytes
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcp) + data_len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 64;
  ip->ip_p = IPPROTO_TCP;
  ip->ip_src = htonl(conn->local_ip);
  ip->ip_dst = htonl(conn->remote_ip);
  ip->ip_sum = 0;
  ip->ip_sum = ip_checksum((unsigned char *)ip, sizeof(*ip));

  // Build TCP header
  struct tcp *tcp = (struct tcp *)(ip + 1);
  tcp->sport = htons(conn->local_port);
  tcp->dport = htons(conn->remote_port);
  tcp->seq = htonl(conn->snd_nxt);
  tcp->ack = htonl(conn->rcv_nxt);
  tcp->off = (sizeof(struct tcp) / 4) << 4;  // 5 << 4 = 0x50
  tcp->flags = flags;
  tcp->win = htons(conn->rcv_wnd);
  tcp->urp = 0;

  // Copy data if present
  if (data_len > 0 && data != 0) {
    memmove((char *)(tcp + 1), data, data_len);
  }

  // Calculate TCP checksum
  tcp->sum = 0;
  tcp->sum = tcp_checksum(conn->local_ip, conn->remote_ip, tcp,
                          (char *)(tcp + 1), data_len);

  e1000_transmit(buf, total);
  return 0;
}

//
// Retransmit unacknowledged segment
//
static void
tcp_retransmit(struct tcp_conn *conn)
{
  if (conn->state == TCP_SYN_SENT) {
    // Retransmit SYN
    uint32 saved_nxt = conn->snd_nxt;
    conn->snd_nxt = conn->iss;
    tcp_send_segment(conn, TCP_SYN, 0, 0);
    conn->snd_nxt = saved_nxt;
  } else if (conn->snd_buf_len > 0) {
    // Retransmit data from send buffer
    int to_send = conn->snd_buf_len < TCP_MSS ? conn->snd_buf_len : TCP_MSS;
    char temp[TCP_MSS];

    // Extract from circular buffer
    int to_end = TCP_BUFSIZE - conn->snd_buf_start;
    if (to_send <= to_end) {
      memmove(temp, conn->snd_buf + conn->snd_buf_start, to_send);
    } else {
      memmove(temp, conn->snd_buf + conn->snd_buf_start, to_end);
      memmove(temp + to_end, conn->snd_buf, to_send - to_end);
    }

    // Retransmit from snd_una
    uint32 saved_nxt = conn->snd_nxt;
    conn->snd_nxt = conn->snd_una;
    tcp_send_segment(conn, TCP_PSH | TCP_ACK, temp, to_send);
    conn->snd_nxt = saved_nxt;
  } else if (conn->state == TCP_FIN_WAIT_1 || conn->state == TCP_LAST_ACK) {
    // Retransmit FIN
    uint32 saved_nxt = conn->snd_nxt;
    conn->snd_nxt = conn->snd_una;
    tcp_send_segment(conn, TCP_FIN | TCP_ACK, 0, 0);
    conn->snd_nxt = saved_nxt;
  }
}

//
// TCP timer check - called periodically from clockintr
//
void
tcp_timer_check(void)
{
  uint current_ticks;
  acquire(&tickslock);
  current_ticks = ticks;
  release(&tickslock);

  acquire(&netlock);

  for (int i = 0; i < NTCP; i++) {
    struct tcp_conn *conn = &tcp_conns[i];
    if (!conn->used)
      continue;

    // Retransmission timeout
    if (conn->rto_deadline != 0 && current_ticks >= conn->rto_deadline) {
      if (conn->retries >= TCP_MAX_RETRIES) {
        // Too many retries, give up
        conn->state = TCP_CLOSED;
        wakeup(conn);
        continue;
      }

      conn->retries++;
      tcp_retransmit(conn);

      // Exponential backoff (capped at reasonable value)
      int backoff = TCP_TIMEOUT_TICKS << conn->retries;
      if (backoff > 600)  // cap at ~60 seconds
        backoff = 600;
      conn->rto_deadline = current_ticks + backoff;
    }

    // TIME_WAIT timeout
    if (conn->state == TCP_TIME_WAIT &&
        conn->timewait_deadline != 0 &&
        current_ticks >= conn->timewait_deadline) {
      conn->state = TCP_CLOSED;
      tcp_free_conn(conn);
    }
  }

  release(&netlock);
}

//
// TCP packet reception - called from ip_rx when protocol=6
//
void
tcp_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *)buf;
  struct ip *ip = (struct ip *)(eth + 1);
  struct tcp *tcp = (struct tcp *)(ip + 1);

  uint32 src_ip = ntohl(ip->ip_src);
  uint16 src_port = ntohs(tcp->sport);
  uint16 dst_port = ntohs(tcp->dport);
  uint32 seq = ntohl(tcp->seq);
  uint32 ack = ntohl(tcp->ack);
  uint8 flags = tcp->flags;
  uint16 window = ntohs(tcp->win);

  int tcp_hdr_len = (tcp->off >> 4) * 4;
  int ip_total_len = ntohs(ip->ip_len);
  int data_len = ip_total_len - sizeof(struct ip) - tcp_hdr_len;
  char *data = (char *)tcp + tcp_hdr_len;

  if (data_len < 0)
    data_len = 0;

  acquire(&netlock);

  // Find matching connection by 4-tuple
  struct tcp_conn *conn = 0;
  for (int i = 0; i < NTCP; i++) {
    if (tcp_conns[i].used &&
        tcp_conns[i].remote_ip == src_ip &&
        tcp_conns[i].remote_port == src_port &&
        tcp_conns[i].local_port == dst_port) {
      conn = &tcp_conns[i];
      break;
    }
  }

  if (!conn) {
    // No matching connection - could send RST but we'll just drop
    release(&netlock);
    kfree(buf);
    return;
  }

  // Reset retransmission timer on valid packet
  conn->retries = 0;

  // Process based on state
  switch (conn->state) {
    case TCP_SYN_SENT:
      if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
        // SYN-ACK received
        if (ack == conn->snd_nxt) {
          conn->irs = seq;
          conn->rcv_nxt = seq + 1;
          conn->snd_una = ack;
          conn->snd_wnd = window;
          conn->state = TCP_ESTABLISHED;
          conn->rto_deadline = 0;  // clear timer

          // Send ACK
          tcp_send_segment(conn, TCP_ACK, 0, 0);
          wakeup(conn);
        }
      } else if (flags & TCP_RST) {
        conn->state = TCP_CLOSED;
        wakeup(conn);
      }
      break;

    case TCP_ESTABLISHED:
      // Handle ACK
      if (flags & TCP_ACK) {
        if (ack > conn->snd_una && ack <= conn->snd_nxt) {
          int acked = ack - conn->snd_una;
          conn->snd_una = ack;

          // Remove acked data from send buffer
          if (acked <= (int)conn->snd_buf_len) {
            conn->snd_buf_start = (conn->snd_buf_start + acked) % TCP_BUFSIZE;
            conn->snd_buf_len -= acked;
          } else {
            conn->snd_buf_len = 0;
          }

          conn->snd_wnd = window;

          // Clear retransmission timer if all data acked
          if (conn->snd_una == conn->snd_nxt) {
            conn->rto_deadline = 0;
          }
          wakeup(conn);  // Wake senders waiting for buffer space
        }
      }

      // Handle in-order data
      if (data_len > 0 && seq == conn->rcv_nxt) {
        int buf_space = TCP_BUFSIZE - conn->rcv_buf_len;
        int to_copy = data_len < buf_space ? data_len : buf_space;

        if (to_copy > 0) {
          int buf_end = (conn->rcv_buf_start + conn->rcv_buf_len) % TCP_BUFSIZE;
          int to_end = TCP_BUFSIZE - buf_end;
          if (to_copy <= to_end) {
            memmove(conn->rcv_buf + buf_end, data, to_copy);
          } else {
            memmove(conn->rcv_buf + buf_end, data, to_end);
            memmove(conn->rcv_buf, data + to_end, to_copy - to_end);
          }
          conn->rcv_buf_len += to_copy;
          conn->rcv_nxt += to_copy;
          conn->rcv_wnd = TCP_BUFSIZE - conn->rcv_buf_len;
        }

        // Send ACK
        tcp_send_segment(conn, TCP_ACK, 0, 0);
        wakeup(conn);  // Wake receivers
      } else if (data_len > 0) {
        // Out-of-order data, send duplicate ACK
        tcp_send_segment(conn, TCP_ACK, 0, 0);
      }

      // Handle FIN (server initiating close)
      if (flags & TCP_FIN) {
        conn->rcv_nxt = seq + data_len + 1;  // FIN consumes one seq number
        tcp_send_segment(conn, TCP_ACK, 0, 0);
        conn->state = TCP_CLOSE_WAIT;
        wakeup(conn);
      }
      break;

    case TCP_FIN_WAIT_1:
      if (flags & TCP_ACK) {
        if (ack == conn->snd_nxt) {
          conn->state = TCP_FIN_WAIT_2;
          conn->rto_deadline = 0;
        }
      }
      if (flags & TCP_FIN) {
        conn->rcv_nxt = seq + 1;
        tcp_send_segment(conn, TCP_ACK, 0, 0);
        if (conn->state == TCP_FIN_WAIT_2 ||
            (flags & TCP_ACK && ack == conn->snd_nxt)) {
          conn->state = TCP_TIME_WAIT;
          acquire(&tickslock);
          conn->timewait_deadline = ticks + TCP_TIME_WAIT_TICKS;
          release(&tickslock);
        } else {
          // Simultaneous close
          conn->state = TCP_TIME_WAIT;
          acquire(&tickslock);
          conn->timewait_deadline = ticks + TCP_TIME_WAIT_TICKS;
          release(&tickslock);
        }
        wakeup(conn);
      }
      break;

    case TCP_FIN_WAIT_2:
      // Receive any remaining data
      if (data_len > 0 && seq == conn->rcv_nxt) {
        int buf_space = TCP_BUFSIZE - conn->rcv_buf_len;
        int to_copy = data_len < buf_space ? data_len : buf_space;
        if (to_copy > 0) {
          int buf_end = (conn->rcv_buf_start + conn->rcv_buf_len) % TCP_BUFSIZE;
          int to_end = TCP_BUFSIZE - buf_end;
          if (to_copy <= to_end) {
            memmove(conn->rcv_buf + buf_end, data, to_copy);
          } else {
            memmove(conn->rcv_buf + buf_end, data, to_end);
            memmove(conn->rcv_buf, data + to_end, to_copy - to_end);
          }
          conn->rcv_buf_len += to_copy;
          conn->rcv_nxt += to_copy;
        }
        tcp_send_segment(conn, TCP_ACK, 0, 0);
        wakeup(conn);
      }

      if (flags & TCP_FIN) {
        conn->rcv_nxt = seq + data_len + 1;
        tcp_send_segment(conn, TCP_ACK, 0, 0);
        conn->state = TCP_TIME_WAIT;
        acquire(&tickslock);
        conn->timewait_deadline = ticks + TCP_TIME_WAIT_TICKS;
        release(&tickslock);
        wakeup(conn);
      }
      break;

    case TCP_LAST_ACK:
      if ((flags & TCP_ACK) && ack == conn->snd_nxt) {
        conn->state = TCP_CLOSED;
        tcp_free_conn(conn);
        wakeup(conn);
      }
      break;

    case TCP_CLOSE_WAIT:
      // Just waiting for user to call close
      break;

    case TCP_TIME_WAIT:
      // Retransmit ACK if we receive FIN again
      if (flags & TCP_FIN) {
        tcp_send_segment(conn, TCP_ACK, 0, 0);
      }
      break;

    default:
      break;
  }

  release(&netlock);
  kfree(buf);
}

//
// sys_tcp_connect - Establish TCP connection to remote host
//
uint64
sys_tcp_connect(void)
{
  int dst_ip, dst_port;
  argint(0, &dst_ip);
  argint(1, &dst_port);

  acquire(&netlock);

  struct tcp_conn *conn = tcp_alloc_conn();
  if (!conn) {
    release(&netlock);
    return -1;
  }

  // Initialize connection
  conn->local_ip = local_ip;
  conn->local_port = tcp_alloc_port();
  conn->remote_ip = dst_ip;
  conn->remote_port = dst_port;
  conn->iss = tcp_gen_iss();
  conn->snd_una = conn->iss;
  conn->snd_nxt = conn->iss;
  conn->rcv_wnd = TCP_BUFSIZE;
  conn->state = TCP_SYN_SENT;

  // Send SYN
  tcp_send_segment(conn, TCP_SYN, 0, 0);
  conn->snd_nxt++;  // SYN consumes one sequence number

  // Set retransmission timer
  acquire(&tickslock);
  conn->rto_deadline = ticks + TCP_TIMEOUT_TICKS;
  release(&tickslock);

  // Wait for connection establishment
  while (conn->state == TCP_SYN_SENT) {
    if (killed(myproc())) {
      tcp_free_conn(conn);
      release(&netlock);
      return -1;
    }
    sleep(conn, &netlock);
  }

  if (conn->state != TCP_ESTABLISHED) {
    tcp_free_conn(conn);
    release(&netlock);
    return -1;
  }

  // Return connection ID
  int connid = conn - tcp_conns;
  release(&netlock);
  return connid;
}

//
// sys_tcp_send - Send data over TCP connection
//
uint64
sys_tcp_send(void)
{
  struct proc *p = myproc();
  int sockid;
  uint64 bufaddr;
  int len;

  argint(0, &sockid);
  argaddr(1, &bufaddr);
  argint(2, &len);

  if (sockid < 0 || sockid >= NTCP || len <= 0)
    return -1;

  acquire(&netlock);

  struct tcp_conn *conn = &tcp_conns[sockid];
  if (!conn->used || conn->state != TCP_ESTABLISHED) {
    release(&netlock);
    return -1;
  }

  // Limit send size
  if (len > TCP_BUFSIZE - 100)
    len = TCP_BUFSIZE - 100;

  // Copy data from user space
  char *data = kalloc();
  if (!data) {
    release(&netlock);
    return -1;
  }

  if (copyin(p->pagetable, data, bufaddr, len) < 0) {
    kfree(data);
    release(&netlock);
    return -1;
  }

  // Send in MSS-sized chunks
  int sent = 0;
  while (sent < len) {
    // Wait for buffer space
    while (conn->snd_buf_len >= TCP_BUFSIZE - TCP_MSS) {
      if (killed(myproc()) || conn->state != TCP_ESTABLISHED) {
        kfree(data);
        release(&netlock);
        return sent > 0 ? sent : -1;
      }
      sleep(conn, &netlock);
    }

    int chunk = len - sent;
    if (chunk > TCP_MSS)
      chunk = TCP_MSS;

    int buf_space = TCP_BUFSIZE - conn->snd_buf_len;
    if (chunk > buf_space)
      chunk = buf_space;

    if (chunk == 0)
      continue;

    // Copy to send buffer (circular)
    int buf_end = (conn->snd_buf_start + conn->snd_buf_len) % TCP_BUFSIZE;
    int to_end = TCP_BUFSIZE - buf_end;
    if (chunk <= to_end) {
      memmove(conn->snd_buf + buf_end, data + sent, chunk);
    } else {
      memmove(conn->snd_buf + buf_end, data + sent, to_end);
      memmove(conn->snd_buf, data + sent + to_end, chunk - to_end);
    }
    conn->snd_buf_len += chunk;

    // Send segment with PSH+ACK
    tcp_send_segment(conn, TCP_PSH | TCP_ACK, data + sent, chunk);
    conn->snd_nxt += chunk;

    // Set/reset retransmission timer
    acquire(&tickslock);
    conn->rto_deadline = ticks + TCP_TIMEOUT_TICKS;
    release(&tickslock);

    sent += chunk;
  }

  kfree(data);
  release(&netlock);
  return sent;
}

//
// sys_tcp_recv - Receive data from TCP connection
//
uint64
sys_tcp_recv(void)
{
  struct proc *p = myproc();
  int sockid;
  uint64 bufaddr;
  int maxlen;

  argint(0, &sockid);
  argaddr(1, &bufaddr);
  argint(2, &maxlen);

  if (sockid < 0 || sockid >= NTCP || maxlen <= 0)
    return -1;

  acquire(&netlock);

  struct tcp_conn *conn = &tcp_conns[sockid];
  if (!conn->used) {
    release(&netlock);
    return -1;
  }

  // Wait for data or connection close
  while (conn->rcv_buf_len == 0) {
    // Check if connection is closed or closing
    if (conn->state == TCP_CLOSE_WAIT ||
        conn->state == TCP_CLOSED ||
        conn->state == TCP_TIME_WAIT ||
        conn->state == TCP_FIN_WAIT_2 ||
        conn->state == TCP_LAST_ACK) {
      // Return 0 for EOF if no more data
      release(&netlock);
      return 0;
    }

    if (killed(myproc())) {
      release(&netlock);
      return -1;
    }

    sleep(conn, &netlock);
  }

  // Copy data to user space
  int to_copy = conn->rcv_buf_len < maxlen ? conn->rcv_buf_len : maxlen;

  // Allocate temp buffer for copyout
  char *temp = kalloc();
  if (!temp) {
    release(&netlock);
    return -1;
  }

  // Handle circular buffer
  int to_end = TCP_BUFSIZE - conn->rcv_buf_start;
  if (to_copy <= to_end) {
    memmove(temp, conn->rcv_buf + conn->rcv_buf_start, to_copy);
  } else {
    memmove(temp, conn->rcv_buf + conn->rcv_buf_start, to_end);
    memmove(temp + to_end, conn->rcv_buf, to_copy - to_end);
  }

  conn->rcv_buf_start = (conn->rcv_buf_start + to_copy) % TCP_BUFSIZE;
  conn->rcv_buf_len -= to_copy;
  conn->rcv_wnd = TCP_BUFSIZE - conn->rcv_buf_len;

  release(&netlock);

  if (copyout(p->pagetable, bufaddr, temp, to_copy) < 0) {
    kfree(temp);
    return -1;
  }

  kfree(temp);
  return to_copy;
}

//
// sys_tcp_close - Close TCP connection
//
uint64
sys_tcp_close(void)
{
  int sockid;
  argint(0, &sockid);

  if (sockid < 0 || sockid >= NTCP)
    return -1;

  acquire(&netlock);

  struct tcp_conn *conn = &tcp_conns[sockid];
  if (!conn->used) {
    release(&netlock);
    return -1;
  }

  switch (conn->state) {
    case TCP_ESTABLISHED:
      // Initiate active close
      tcp_send_segment(conn, TCP_FIN | TCP_ACK, 0, 0);
      conn->snd_nxt++;  // FIN consumes one sequence number
      conn->state = TCP_FIN_WAIT_1;

      // Set timer
      acquire(&tickslock);
      conn->rto_deadline = ticks + TCP_TIMEOUT_TICKS;
      release(&tickslock);
      break;

    case TCP_CLOSE_WAIT:
      // Respond to passive close
      tcp_send_segment(conn, TCP_FIN | TCP_ACK, 0, 0);
      conn->snd_nxt++;
      conn->state = TCP_LAST_ACK;

      acquire(&tickslock);
      conn->rto_deadline = ticks + TCP_TIMEOUT_TICKS;
      release(&tickslock);
      break;

    case TCP_SYN_SENT:
      // Connection never established, just close
      tcp_free_conn(conn);
      release(&netlock);
      return 0;

    default:
      // Already closing or closed
      break;
  }

  // Wait for connection to fully close (with timeout)
  int wait_count = 0;
  while (conn->state != TCP_CLOSED && conn->state != TCP_TIME_WAIT) {
    if (killed(myproc()) || wait_count++ > 100) {
      // Force close after timeout
      tcp_free_conn(conn);
      release(&netlock);
      return 0;
    }
    sleep(conn, &netlock);
  }

  // Clean up if CLOSED
  if (conn->state == TCP_CLOSED) {
    tcp_free_conn(conn);
  }
  // TIME_WAIT will be cleaned up by timer

  release(&netlock);
  return 0;
}

//
// Initialize TCP subsystem
//
void
tcp_init(void)
{
  for (int i = 0; i < NTCP; i++) {
    tcp_conns[i].used = 0;
    tcp_conns[i].state = TCP_CLOSED;
    tcp_conns[i].snd_buf = 0;
    tcp_conns[i].rcv_buf = 0;
  }
}
