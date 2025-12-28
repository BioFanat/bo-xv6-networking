//
// endianness support
//

static inline uint16 bswaps(uint16 val)
{
  return (((val & 0x00ffU) << 8) |
          ((val & 0xff00U) >> 8));
}

static inline uint32 bswapl(uint32 val)
{
  return (((val & 0x000000ffUL) << 24) |
          ((val & 0x0000ff00UL) << 8) |
          ((val & 0x00ff0000UL) >> 8) |
          ((val & 0xff000000UL) >> 24));
}

// Use these macros to convert network bytes to the native byte order.
// Note that Risc-V uses little endian while network order is big endian.
#define ntohs bswaps
#define ntohl bswapl
#define htons bswaps
#define htonl bswapl


//
// useful networking headers
//

#define ETHADDR_LEN 6

// an Ethernet packet header (start of the packet).
struct eth {
  uint8  dhost[ETHADDR_LEN];
  uint8  shost[ETHADDR_LEN];
  uint16 type;
} __attribute__((packed));

#define ETHTYPE_IP  0x0800 // Internet protocol
#define ETHTYPE_ARP 0x0806 // Address resolution protocol

// an IP packet header (comes after an Ethernet header).
struct ip {
  uint8  ip_vhl; // version << 4 | header length >> 2
  uint8  ip_tos; // type of service
  uint16 ip_len; // total length, including this IP header
  uint16 ip_id;  // identification
  uint16 ip_off; // fragment offset field
  uint8  ip_ttl; // time to live
  uint8  ip_p;   // protocol
  uint16 ip_sum; // checksum, covers just IP header
  uint32 ip_src, ip_dst;
};

#define IPPROTO_ICMP 1  // Control message protocol
#define IPPROTO_TCP  6  // Transmission control protocol
#define IPPROTO_UDP  17 // User datagram protocol

#define MAKE_IP_ADDR(a, b, c, d)           \
  (((uint32)a << 24) | ((uint32)b << 16) | \
   ((uint32)c << 8) | (uint32)d)

// a UDP packet header (comes after an IP header).
struct udp {
  uint16 sport; // source port
  uint16 dport; // destination port
  uint16 ulen;  // length, including udp header, not including IP header
  uint16 sum;   // checksum
};

// ICMP packet header (comes after an IP header).
struct icmp {
  uint8  type;     // ICMP type
  uint8  code;     // ICMP code
  uint16 checksum; // ICMP checksum
  uint16 id;       // identifier (for echo request/reply)
  uint16 seq;      // sequence number (for echo request/reply)
} __attribute__((packed));

// ICMP types
#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8

// a TCP packet header (comes after an IP header).
struct tcp {
  uint16 sport;    // source port
  uint16 dport;    // destination port
  uint32 seq;      // sequence number
  uint32 ack;      // acknowledgment number
  uint8  off;      // data offset (header length in 32-bit words) << 4
  uint8  flags;    // TCP flags
  uint16 win;      // window size
  uint16 sum;      // checksum
  uint16 urp;      // urgent pointer
} __attribute__((packed));

// TCP flags
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

// TCP states (client-only subset)
enum tcp_state {
  TCP_CLOSED,
  TCP_SYN_SENT,
  TCP_ESTABLISHED,
  TCP_FIN_WAIT_1,
  TCP_FIN_WAIT_2,
  TCP_TIME_WAIT,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK
};

// TCP configuration constants
#define NTCP              8       // max concurrent TCP connections
#define TCP_BUFSIZE       4096    // send/receive buffer size (1 page)
#define TCP_MSS           1460    // max segment size (ETH MTU - IP - TCP headers)
#define TCP_TIMEOUT_TICKS 5       // retransmission timeout (~500ms)
#define TCP_TIME_WAIT_TICKS 600   // TIME_WAIT duration (~60 seconds)
#define TCP_MAX_RETRIES   5       // max retransmission attempts

// TCP connection structure
struct tcp_conn {
  int used;                       // is this connection slot in use?
  enum tcp_state state;           // TCP state machine state

  // Connection 4-tuple
  uint32 local_ip;                // local IP address
  uint16 local_port;              // local port (host byte order)
  uint32 remote_ip;               // remote IP address (host byte order)
  uint16 remote_port;             // remote port (host byte order)

  // Sequence numbers
  uint32 snd_una;                 // send unacknowledged
  uint32 snd_nxt;                 // send next
  uint32 rcv_nxt;                 // receive next (expected)
  uint32 iss;                     // initial send sequence number
  uint32 irs;                     // initial receive sequence number

  // Window sizes
  uint16 snd_wnd;                 // send window (from remote)
  uint16 rcv_wnd;                 // receive window (our advertised)

  // Send buffer (unacknowledged data for retransmission)
  char *snd_buf;                  // page-sized send buffer
  uint32 snd_buf_start;           // start offset in buffer
  uint32 snd_buf_len;             // bytes of unacked data in buffer

  // Receive buffer (reassembled data waiting for user)
  char *rcv_buf;                  // page-sized receive buffer
  uint32 rcv_buf_start;           // start offset in buffer
  uint32 rcv_buf_len;             // bytes of data available

  // Retransmission timer
  uint64 rto_deadline;            // next retransmit time (in ticks)
  int retries;                    // number of retransmission attempts

  // TIME_WAIT timer
  uint64 timewait_deadline;       // when to close from TIME_WAIT
};

// an ARP packet (comes after an Ethernet header).
struct arp {
  uint16 hrd; // format of hardware address
  uint16 pro; // format of protocol address
  uint8  hln; // length of hardware address
  uint8  pln; // length of protocol address
  uint16 op;  // operation

  char   sha[ETHADDR_LEN]; // sender hardware address
  uint32 sip;              // sender IP address
  char   tha[ETHADDR_LEN]; // target hardware address
  uint32 tip;              // target IP address
} __attribute__((packed));

#define ARP_HRD_ETHER 1 // Ethernet

enum {
  ARP_OP_REQUEST = 1, // requests hw addr given protocol addr
  ARP_OP_REPLY = 2,   // replies with the hw addr of the protocol addr
};

// an DNS packet (comes after an UDP header).
struct dns {
  uint16 id;  // request ID

  uint8 rd: 1;  // recursion desired
  uint8 tc: 1;  // truncated
  uint8 aa: 1;  // authoritive
  uint8 opcode: 4; 
  uint8 qr: 1;  // query/response
  uint8 rcode: 4; // response code
  uint8 cd: 1;  // checking disabled
  uint8 ad: 1;  // authenticated data
  uint8 z:  1;  
  uint8 ra: 1;  // recursion available
  
  uint16 qdcount; // number of question entries
  uint16 ancount; // number of resource records in answer section
  uint16 nscount; // number of NS resource records in authority section
  uint16 arcount; // number of resource records in additional records
} __attribute__((packed));

struct dns_question {
  uint16 qtype;
  uint16 qclass;
} __attribute__((packed));
  
#define ARECORD (0x0001)
#define QCLASS  (0x0001)

struct dns_data {
  uint16 type;
  uint16 class;
  uint32 ttl;
  uint16 len;
} __attribute__((packed));

struct netstats {
  uint64 rx_packets;            // packets in ring
  uint64 rx_bytes;              // bytes of those packets
  uint64 rx_ring_empty;         // recv found empty ring
  uint64 rx_interrupts;         // number of receive interrupts
  uint64 last_irq_time;         // last interrupt
  uint64 min_irq_delta;         // closest rx interrupt
  uint64 max_irq_delta;         // furthest rx interrupt
  uint64 last_recv_time;        // last receive time

  uint64 udp_queued;            // queued in port
  uint64 udp_dropped_unbound;   // dropped due to an unbound port
  uint64 udp_dropped_full;      // dropped due to full queue
  uint64 udp_returned;          // successfully delivered to recv

  uint64 irq_entry_time;        // number of interrupt handler entries

  // time to receive (from interrupt to userspace return)
  uint64 ttr_sum;
  uint64 ttr_count;
  uint64 min_ttr;
  uint64 max_ttr;

  // time to queue (from interrupt to being queued in port)
  uint64 ttq_sum;
  uint64 ttq_count;
  uint64 min_ttq;
  uint64 max_ttq;
};
