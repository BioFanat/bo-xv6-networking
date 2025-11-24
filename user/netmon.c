#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

static void
usage(void)
{
  printf("usage: netmon [interval_ms] [count]\n");
  exit(1);
}

int
main(int argc, char *argv[])
{
  int interval = 1000; // default 1s between samples
  int count = -1;      // run until killed if negative

  if(argc > 3)
    usage();
  if(argc >= 2)
    interval = atoi(argv[1]);
  if(argc == 3)
    count = atoi(argv[2]);
  if(interval <= 0)
    interval = 1000;

  if(netreset() < 0){
    printf("netmon: netreset failed\n");
    exit(1);
  }

  printf("t(ms) rx_pkts rx_bytes udp_q udp_drop_full udp_drop_unbound udp_ret irq min_irq_dt max_irq_dt last_rx\n");

  int iter = 0;
  while(count < 0 || iter < count){
    struct netstats s;
    if(netstats(&s) < 0){
      printf("netmon: netstats failed\n");
      exit(1);
    }

    // Cast to int for simple printing; durations are in rdtime ticks.
    printf("%d %d %d %d %d %d %d %d %d %d %d\n",
           uptime(),
           (int)s.rx_packets,
           (int)s.rx_bytes,
           (int)s.udp_queued,
           (int)s.udp_dropped_full,
           (int)s.udp_dropped_unbound,
           (int)s.udp_returned,
           (int)s.rx_interrupts,
           (int)s.min_irq_delta,
           (int)s.max_irq_delta,
           (int)s.last_recv_time);

    iter++;
    pause(interval);
  }

  exit(0);
}
