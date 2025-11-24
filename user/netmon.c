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

  uint64 start_time = get_time();

  printf("t(ms) rx_pkts rx_bytes udp_q udp_drop_full udp_drop_unbound udp_ret irq min_irq_dt max_irq_dt last_rx k_lat_avg k_lat_min k_lat_max k_samples\n");

  int iter = 0;
  while(count < 0 || iter < count){
    struct netstats s;
    if(netstats(&s) < 0){
      printf("netmon: netstats failed\n");
      exit(1);
    }

    uint64 now = get_time();
    uint64 elapsed_ms = time_to_msec(now - start_time);

    uint64 avg_klat = 0;
    if(s.kernel_latency_count > 0)
      avg_klat = s.kernel_latency_sum / s.kernel_latency_count;

    // convert timing units
    uint64 min_irq_dt = time_to_usec(s.min_irq_delta);
    uint64 max_irq_dt = time_to_usec(s.max_irq_delta);
    uint64 last_rx = time_to_msec(s.last_recv_time);
    uint64 k_lat_avg = time_to_usec(avg_klat);
    uint64 k_lat_min = time_to_usec(s.min_kernel_latency);
    uint64 k_lat_max = time_to_usec(s.max_kernel_latency);

    printf("%lu %d %d %d %d %d %d %d %lu %lu %lu %lu %lu %lu %d\n",
           elapsed_ms,
           (int)s.rx_packets,
           (int)s.rx_bytes,
           (int)s.udp_queued,
           (int)s.udp_dropped_full,
           (int)s.udp_dropped_unbound,
           (int)s.udp_returned,
           (int)s.rx_interrupts,
           min_irq_dt,
           max_irq_dt,
           last_rx,
           k_lat_avg,
           k_lat_min,
           k_lat_max,
           (int)s.kernel_latency_count);

    iter++;
    // note - 1 tick roughly 100ms
    int sleep_ticks = (interval + 99) / 100; 
    if(sleep_ticks < 1) sleep_ticks = 1;
    pause(sleep_ticks);
  }

  exit(0);
}
