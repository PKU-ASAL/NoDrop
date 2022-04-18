#ifndef LOCK_H
#define LOCK_H

__attribute__((__visibility__("hidden"))) void __lock(volatile int *);
__attribute__((__visibility__("hidden"))) void __unlock(volatile int *);
#define LOCK(x) __lock(x)
#define UNLOCK(x) __unlock(x)

#endif
