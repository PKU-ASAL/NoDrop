#ifndef _H_TSC
#define _H_TSC

#ifndef __KERNEL__

#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// shoule be consistent with the your default CPU frequency
#define TSC_CPUFREQ_GHZ 2.25
#define TSC_CPUFREQ_MHZ (TSC_CPUFREQ_GHZ * 1e3)
#define TSC_CPUFREQ_HZ (TSC_CPUFREQ_GHZ * 1e9)

/*
 * 1.
 * 如果你的cpuinfo里面没有constant_tsc的flag，建议老老实实用clock_gettime吧，或者换台支持constant_tsc的机器
 * 2.
 * 如果你的cpuinfo里面有constant_tsc的flag，那么在同一处理器的不同核心之间可以放心使用TSC，跨处理器的不同核之间，尽量避免使用，可能会有未知的问题
 * 3.
 * 如果不是对性能极其敏感，尽量使用RDTSCP代替RDTSC，前者略慢，但能避免CPU乱序执行问题。RDTSCP指令也是需要平台支持的，是否支持可以使用cat
 * /proc/cpuinfo | grep
 * rdtscp命令查看，RDTSCP指令比RDTSC多耗费10个指令周期左右，慢不到1倍
 */

#define to_ns(ts) ((uint64_t)(ts)->tv_sec * 1000000000 + (ts)->tv_nsec)

static inline uint64_t __rdtsc(void) {
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc(void) {
  uint64_t r;
  // 加入内存屏障，防止乱序执行影响精度(3)
  __asm__ __volatile__("" : : : "memory");
  r = __rdtsc();
  __asm__ __volatile__("" : : : "memory");
  return r;
}

static inline uint64_t get_nsec(void) {
  struct timespec tv;
  syscall(SYS_clock_gettime, 1, &tv);
  return to_ns(&tv);
}

static inline uint64_t tsc_to_nsec(uint64_t duration) {
  return duration / TSC_CPUFREQ_GHZ;
}

static void test_ticks_per_ns(int sleeps, uint64_t *elapsed_ticks,
                              uint64_t *elapsed_ns) {
  struct timespec clock_start, clock_end;
  uint64_t tsc1, tsc2, tsc_start, tsc_end;

  tsc1 = rdtsc();
  clock_gettime(CLOCK_REALTIME, &clock_start);
  tsc2 = rdtsc();
  tsc_start = (tsc1 + tsc2) / 2;

  sleep(sleeps);

  tsc1 = rdtsc();
  clock_gettime(CLOCK_REALTIME, &clock_end);
  tsc2 = rdtsc();
  tsc_end = (tsc1 + tsc2) / 2;

  *elapsed_ticks = tsc_end - tsc_start;
  *elapsed_ns = to_ns(&clock_end) - to_ns(&clock_start);
}

#endif // __KERNEL__

#endif //_H_TSC
