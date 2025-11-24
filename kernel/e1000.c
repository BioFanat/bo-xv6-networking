#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "e1000_dev.h"
#include "net.h"

#define TX_RING_SIZE 16
static struct tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));

#define RX_RING_SIZE 16
static struct rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));

// remember where the e1000's registers live.
static volatile uint32 *regs;

struct spinlock e1000_lock;
extern struct netstats netstats;

// called by pci_init().
// xregs is the memory address at which the
// e1000's registers are mapped.
// this code loosely follows the initialization directions
// in Chapter 14 of Intel's Software Developer's Manual.
void
e1000_init(uint32 *xregs)
{
  int i;

  initlock(&e1000_lock, "e1000");

  regs = xregs;

  // Reset the device
  regs[E1000_IMS] = 0; // disable interrupts
  regs[E1000_CTL] |= E1000_CTL_RST;
  regs[E1000_IMS] = 0; // redisable interrupts
  __sync_synchronize();

  // [E1000 14.5] Transmit initialization
  memset(tx_ring, 0, sizeof(tx_ring));
  for (i = 0; i < TX_RING_SIZE; i++) {
    tx_ring[i].status = E1000_TXD_STAT_DD;
    tx_ring[i].addr = 0;
  }
  regs[E1000_TDBAL] = (uint64) tx_ring;
  if(sizeof(tx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_TDLEN] = sizeof(tx_ring);
  regs[E1000_TDH] = regs[E1000_TDT] = 0;
  
  // [E1000 14.4] Receive initialization
  memset(rx_ring, 0, sizeof(rx_ring));
  for (i = 0; i < RX_RING_SIZE; i++) {
    rx_ring[i].addr = (uint64) kalloc();
    if (!rx_ring[i].addr)
      panic("e1000");
  }
  regs[E1000_RDBAL] = (uint64) rx_ring;
  if(sizeof(rx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_RDH] = 0;
  regs[E1000_RDT] = RX_RING_SIZE - 1;
  regs[E1000_RDLEN] = sizeof(rx_ring);

  // filter by qemu's MAC address, 52:54:00:12:34:56
  regs[E1000_RA] = 0x12005452;
  regs[E1000_RA+1] = 0x5634 | (1<<31);
  // multicast table
  for (int i = 0; i < 4096/32; i++)
    regs[E1000_MTA + i] = 0;

  // transmitter control bits.
  regs[E1000_TCTL] = E1000_TCTL_EN |  // enable
    E1000_TCTL_PSP |                  // pad short packets
    (0x10 << E1000_TCTL_CT_SHIFT) |   // collision stuff
    (0x40 << E1000_TCTL_COLD_SHIFT);
  regs[E1000_TIPG] = 10 | (8<<10) | (6<<20); // inter-pkt gap

  // receiver control bits.
  regs[E1000_RCTL] = E1000_RCTL_EN | // enable receiver
    E1000_RCTL_BAM |                 // enable broadcast
    E1000_RCTL_SZ_2048 |             // 2048-byte rx buffers
    E1000_RCTL_SECRC;                // strip CRC
  
  // ask e1000 for receive interrupts.
  regs[E1000_RDTR] = 0; // interrupt after every received packet (no timer)
  regs[E1000_RADV] = 0; // interrupt after every packet (no timer)
  regs[E1000_IMS] = (1 << 7); // RXDW -- Receiver Descriptor Write Back
}

int
e1000_transmit(char *buf, int len)
{
  acquire(&e1000_lock);
  
  // get next TX ring index
  uint32 tdt = regs[E1000_TDT];
  
  // check if descriptor is available (DD bit must be set)
  if((tx_ring[tdt].status & E1000_TXD_STAT_DD) == 0) {
    // ring is full, descriptor not yet processed
    release(&e1000_lock);
    return -1;
  }
  
  // free old buffer if it exists
  if(tx_ring[tdt].addr != 0) {
    kfree((void *)tx_ring[tdt].addr);
  }
  
  // fill in descriptor
  tx_ring[tdt].addr = (uint64)buf;
  tx_ring[tdt].length = len;
  tx_ring[tdt].cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS;
  tx_ring[tdt].status = 0;
  
  // update tail pointer
  regs[E1000_TDT] = (tdt + 1) % TX_RING_SIZE;
  
  release(&e1000_lock);
  return 0;
}

static void
e1000_recv(void)
{
  acquire(&e1000_lock);
  
  // loop to handle multiple packets
  while(1) {
    // get next RX ring index
    uint32 rdt = (regs[E1000_RDT] + 1) % RX_RING_SIZE;
    
    if((rx_ring[rdt].status & E1000_RXD_STAT_DD) == 0) {
      // No more packets ready
      netstats.rx_ring_empty++;
      break;
    }
    
    // get packet buffer and length
    char *buf = (char *)rx_ring[rdt].addr;
    uint16 len = rx_ring[rdt].length;
    netstats.rx_packets++;
    netstats.rx_bytes += len;
    netstats.last_recv_time = r_time();
    
    // allocate new buffer for descriptor before releasing lock
    char *newbuf = (char *)kalloc();
    if(newbuf == 0) panic("e1000_recv: kalloc failed");
    
    // update descriptor
    rx_ring[rdt].addr = (uint64)newbuf;
    rx_ring[rdt].status = 0;
    
    // update tail pointer
    regs[E1000_RDT] = rdt;
    
    // release the lock before calling net_rx() to avoid deadlock
    release(&e1000_lock);
    
    // deliver the packet to network stack 
    net_rx(buf, len);
    
    // re-acquire the lock for next iteration
    acquire(&e1000_lock);
  }
  
  release(&e1000_lock); // make sure we release this
}

void
e1000_intr(void)
{
  // tell the e1000 we've seen this interrupt;
  // without this the e1000 won't raise any
  // further interrupts.
  regs[E1000_ICR] = 0xffffffff;

  // Track interrupt timing.
  acquire(&e1000_lock);
  uint64 now = r_time();
  netstats.rx_interrupts++;
  if(netstats.last_irq_time != 0) {
    uint64 delta = now - netstats.last_irq_time;
    if(netstats.min_irq_delta == (uint64)-1 || delta < netstats.min_irq_delta)
      netstats.min_irq_delta = delta;
    if(delta > netstats.max_irq_delta)
      netstats.max_irq_delta = delta;
  }
  netstats.last_irq_time = now;
  netstats.irq_entry_time = now;
  release(&e1000_lock);

  e1000_recv();
}
