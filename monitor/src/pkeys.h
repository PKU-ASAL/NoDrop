#include <unistd.h>
#include <sys/syscall.h>

#define PKEY_DISABLE_ACCESS 0x1
#define PKEY_DISABLE_WRITE  0x2

static inline void
wrpkru(unsigned int pkru)
{
    unsigned int eax = pkru;
    unsigned int ecx = 0;
    unsigned int edx = 0;

    asm volatile(".byte 0x0f,0x01,0xef\n\t"
                : : "a" (eax), "c" (ecx), "d" (edx));
}

static inline unsigned int
rdpkru(void)
{
    unsigned int eax = 0;
    unsigned int ecx = 0;

    asm volatile(".byte 0x0f,0x01,0xee\n\t"
                : "=a"(eax) : "c" (ecx));

    return eax;
}

static inline int
pkey_set(int pkey, unsigned long rights)
{
    if (pkey < 0 || pkey > 15 || rights > 3) {
        return -1;
    }

    unsigned int mask = 3 << (2 * pkey);
    unsigned int pkru = rdpkru();

    pkru = (pkru & ~mask) | (rights << (2 * pkey));
    wrpkru(pkru);

    return 0;
}

static inline int
pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot,
                unsigned long pkey)
{
    return syscall(SYS_pkey_mprotect, ptr, size, orig_prot, pkey);
}

static inline int
pkey_alloc(void)
{
    return syscall(SYS_pkey_alloc, 0, 0);
}

static inline int
pkey_free(unsigned long pkey)
{
    return syscall(SYS_pkey_free, pkey);
}