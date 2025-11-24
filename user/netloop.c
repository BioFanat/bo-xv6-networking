#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

static void
usage(void)
{
  printf("usage: netloop [port] [report_ms]\n");
  exit(1);
}

int
main(int argc, char *argv[])
{
  int port = 2000;
  int report_ms = 1000; // how often to print stats

  if(argc > 3)
    usage();
  if(argc >= 2)
    port = atoi(argv[1]);
  if(argc == 3)
    report_ms = atoi(argv[2]);
  if(port <= 0 || report_ms <= 0)
    usage();

  if(bind(port) < 0){
    printf("netloop: bind %d failed\n", port);
    exit(1);
  }

  uint64 total_pkts = 0;
  uint64 total_bytes = 0;
  uint ticks_prev = uptime();
  uint64 prev_pkts = 0;
  uint64 prev_bytes = 0;

  printf("netloop: bound to %d, reporting every %d ms\n", port, report_ms);

  for(;;){
    char buf[1500];
    uint32 src;
    uint16 sport;
    int cc = recv(port, &src, &sport, buf, sizeof(buf));
    if(cc < 0){
      printf("netloop: recv failed\n");
      exit(1);
    }
    total_pkts++;
    total_bytes += cc;

    uint ticks_now = uptime();
    int elapsed = ticks_now - ticks_prev;
    if(elapsed >= report_ms){
      uint64 dpkts = total_pkts - prev_pkts;
      uint64 dbytes = total_bytes - prev_bytes;
      uint pps = (elapsed > 0) ? (dpkts * 1000 / elapsed) : 0;
      uint kbps = (elapsed > 0) ? (dbytes * 1000 / elapsed) : 0;
      printf("t=%u ms pkts=%lu bytes=%lu (+%lu, +%luB) pps~%u Bps~%u\n",
             ticks_now, total_pkts, total_bytes, dpkts, dbytes, pps, kbps);
      ticks_prev = ticks_now;
      prev_pkts = total_pkts;
      prev_bytes = total_bytes;
    }
  }
}
