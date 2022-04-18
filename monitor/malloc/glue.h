#ifndef MALLOC_GLUE_H
#define MALLOC_GLUE_H

#include <stdint.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include "atomic.h"
#include "syscall.h"
#include "lock.h"
#include "dynlink.h"

extern __attribute__((__visibility__("hidden")))
struct __libc {
	char can_do_threads;
	char threaded;
	char secure;
	volatile signed char need_locks;
	int threads_minus_1;
	size_t *auxv;
	struct tls_module *tls_head;
	size_t tls_size, tls_align, tls_cnt;
	size_t page_size;
	struct __locale_struct global_locale;
} __libc;
#define libc __libc

#ifndef PAGE_SIZE
#define PAGE_SIZE libc.page_size
#endif

// use macros to appropriately namespace these.
#define size_classes __malloc_size_classes
#define ctx __malloc_context
#define alloc_meta __malloc_alloc_meta
#define is_allzero __malloc_allzerop
#define dump_heap __dump_heap

#if USE_REAL_ASSERT
#include <assert.h>
#else
#undef assert
#define assert(x) do { if (!(x)) a_crash(); } while(0)
#endif

#define brk(p) ((uintptr_t)__syscall(SYS_brk, p))

#define DISABLE_ALIGNED_ALLOC (__malloc_replaced && !__aligned_alloc_replaced)

static inline uint64_t get_random_secret()
{
	uint64_t secret = (uintptr_t)&secret * 1103515245;
	for (size_t i=0; libc.auxv[i]; i+=2)
		if (libc.auxv[i]==AT_RANDOM)
			memcpy(&secret, (char *)libc.auxv[i+1]+8, sizeof secret);
	return secret;
}

#ifndef PAGESIZE
#define PAGESIZE PAGE_SIZE
#endif

#define MT (libc.need_locks)

#define RDLOCK_IS_EXCLUSIVE 1

__attribute__((__visibility__("hidden")))
extern int __malloc_lock[1];

#define LOCK_OBJ_DEF \
int __malloc_lock[1]; \
void __malloc_atfork(int who) { malloc_atfork(who); }

static inline void rdlock()
{
	if (MT) LOCK(__malloc_lock);
}
static inline void wrlock()
{
	if (MT) LOCK(__malloc_lock);
}
static inline void unlock()
{
	UNLOCK(__malloc_lock);
}
static inline void upgradelock()
{
}
static inline void resetlock()
{
	__malloc_lock[0] = 0;
}

static inline void malloc_atfork(int who)
{
	if (who<0) rdlock();
	else if (who>0) resetlock();
	else unlock();
}

#endif
