#include <linux/compat.h>
#include <linux/cdev.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/compat.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/quota.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/audit.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#include "syscall.h"
#else
#include <asm/syscall.h>
#endif

#include "nodrop.h"
#include "fillers.h"
#include "flags.h"

#include "common.h"
#include "events.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
#include <linux/bpf.h>
#endif

/*
 * The kernel patched with grsecurity makes the default access_ok trigger a
 * might_sleep(), so if present we use the one defined by them
 */
#ifdef access_ok_noprefault
#define nod_access_ok access_ok_noprefault
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0))
#define nod_access_ok(type, addr, size)	access_ok(addr, size)
#else
#define nod_access_ok(type, addr, size)	access_ok(type, addr, size)
#endif
#endif

#define INVALID_USER_MEMORY \
    do{\
        len = (int)strlcpy(args->buf_ptr + args->arg_data_offset, \
            "(INVAL)", \
            max_arg_size); \
        if (++len > (int)max_arg_size) \
            len = max_arg_size;	\
    } while(0)

#define merge_64(hi, lo) ((((unsigned long long)(hi)) << 32) + ((lo) & 0xffffffffUL))

static struct pid_namespace *pid_ns_for_children(struct task_struct *task)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
	return task->nsproxy->pid_ns;
#else
	return task->nsproxy->pid_ns_for_children;
#endif
}

inline void nod_syscall_get_arguments(struct task_struct *task, struct pt_regs *regs, unsigned long *args)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0))
    syscall_get_arguments(task, regs, 0, 6, args);
#else
    syscall_get_arguments(task, regs, args);
#endif
}

/*
 * What this function does is basically a special memcpy
 * so that, if the page fault handler detects the address is invalid,
 * won't kill the process but will return a positive number
 * Plus, this doesn't sleep.
 * The risk is that if the buffer is partially paged out, we get an error.
 * Returns the number of bytes NOT read.
 */
unsigned long nod_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long res = n;

    pagefault_disable();

    if (likely(nod_access_ok(VERIFY_READ, from, n)))
        res = __copy_from_user_inatomic(to, from, n);

    pagefault_enable();

    return res;
}


/*
 * On some kernels (e.g. 2.6.39), even with preemption disabled, the strncpy_from_user,
 * instead of returning -1 after a page fault, schedules the process, so we drop events
 * because of the preemption. This function reads the user buffer in atomic chunks, and
 * returns when there's an error or the terminator is found
 */
long nod_strncpy_from_user(char *to, const char __user *from, unsigned long n)
{
    long string_length = 0;
    long res = -1;
    unsigned long bytes_to_read = 4;
    int j;

    pagefault_disable();

    while (n) {
        /*
         * Read bytes_to_read bytes at a time, and look for the terminator. Should be fast
         * since the copy_from_user is optimized for the processor
         */
        if (n < bytes_to_read)
            bytes_to_read = n;

        if (!nod_access_ok(VERIFY_READ, from, bytes_to_read)) {
            res = -1;
            goto strncpy_end;
        }

        if (__copy_from_user_inatomic(to, from, bytes_to_read)) {
            /*
             * Page fault
             */
            res = -1;
            goto strncpy_end;
        }

        n -= bytes_to_read;
        from += bytes_to_read;

        for (j = 0; j < bytes_to_read; ++j) {
            ++string_length;

            if (!*to) {
                res = string_length;
                goto strncpy_end;
            }

            ++to;
        }
    }

strncpy_end:
    pagefault_enable();
    return res;
}

/* Takes in a NULL-terminated array of pointers to strings in userspace, and
 * concatenates them to a single \0-separated string. Return the length of this
 * string, or <0 on error */
static int accumulate_argv_or_env(const char __user * __user *argv,
				  char *str_storage,
				  int available)
{
	int len = 0;
	int n_bytes_copied;

	if (argv == NULL)
		return len;

	for (;;) {
		const char __user *p;

		if (unlikely(nod_get_user(p, argv)))
			return NOD_FAILURE_INVALID_USER_MEMORY;

		if (p == NULL)
			break;

		/* need at least enough space for a \0 */
		if (available < 1)
			return NOD_FAILURE_BUFFER_FULL;

		n_bytes_copied = nod_strncpy_from_user(&str_storage[len], p,
						       available);

		/* nod_strncpy_from_user includes the trailing \0 in its return
		 * count. I want to pretend it was strncpy_from_user() so I
		 * subtract off the 1 */
		n_bytes_copied--;

		if (n_bytes_copied < 0)
			return NOD_FAILURE_INVALID_USER_MEMORY;

		if (n_bytes_copied >= available)
			return NOD_FAILURE_BUFFER_FULL;

		/* update buffer. I want to keep the trailing \0, so I +1 */
		available   -= n_bytes_copied+1;
		len         += n_bytes_copied+1;

		argv++;
	}

	return len;
}

/*
 * get_mm_counter was not inline and exported between 3.0 and 3.4
 * https://github.com/torvalds/linux/commit/69c978232aaa99476f9bd002c2a29a84fa3779b5
 * Hence the crap in these two functions
 */
unsigned long nod_get_mm_counter(struct mm_struct *mm, int member)
{
	long val = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	val = get_mm_counter(mm, member);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	val = atomic_long_read(&mm->rss_stat.count[member]);

	if (val < 0)
		val = 0;
#endif

	return val;
}


static unsigned long nod_get_mm_rss(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	return get_mm_rss(mm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return nod_get_mm_counter(mm, MM_FILEPAGES) +
		nod_get_mm_counter(mm, MM_ANONPAGES);
#else
	return get_mm_rss(mm);
#endif
	return 0;
}

static unsigned long nod_get_mm_swap(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return nod_get_mm_counter(mm, MM_SWAPENTS);
#endif
	return 0;
}

struct file *nod_get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
	rcu_read_unlock();
#else
	/* We need mmap_sem to protect against races with removal of
	 * VM_EXECUTABLE vmas */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
#endif

	return exe_file;
}

static int sock_getname(struct socket* sock, struct sockaddr* sock_address, int peer)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	int ret = sock->ops->getname(sock, sock_address, peer);
	if (ret >= 0)
		ret = 0;
	return ret;
#else
	int sockaddr_len;
	return sock->ops->getname(sock, sock_address, &sockaddr_len, peer);
#endif
}

/*
 * Convert a sockaddr into our address representation and copy it to
 * targetbuf
 */
static u16 pack_addr(struct sockaddr *usrsockaddr,
    int ulen,
    char *targetbuf,
    u16 targetbufsize)
{
    u32 ip;
    u16 port;
    sa_family_t family = usrsockaddr->sa_family;
    struct sockaddr_in *usrsockaddr_in;
    struct sockaddr_in6 *usrsockaddr_in6;
    struct sockaddr_un *usrsockaddr_un;
    u16 size;
    char *dest;

    switch (family) {
    case AF_INET:
        /*
         * Map the user-provided address to a sockaddr_in
         */
        usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

        /*
         * Retrieve the src address
         */
        ip = usrsockaddr_in->sin_addr.s_addr;
        port = ntohs(usrsockaddr_in->sin_port);

        /*
         * Pack the tuple info in the temporary buffer
         */
        size = 1 + 4 + 2; /* family + ip + port */

        *targetbuf = socket_family_to_scap((u8)family);
        *(u32 *)(targetbuf + 1) = ip;
        *(u16 *)(targetbuf + 5) = port;

        break;
    case AF_INET6:
        /*
         * Map the user-provided address to a sockaddr_in
         */
        usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

        /*
         * Retrieve the src address
         */
        port = ntohs(usrsockaddr_in6->sin6_port);

        /*
         * Pack the tuple info in the temporary buffer
         */
        size = 1 + 16 + 2; /* family + ip + port */

        *targetbuf = socket_family_to_scap((u8)family);
        memcpy(targetbuf + 1,
            usrsockaddr_in6->sin6_addr.s6_addr,
            16);
        *(u16 *)(targetbuf + 17) = port;

        break;
    case AF_UNIX:
        /*
         * Map the user-provided address to a sockaddr_in
         */
        usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

        /*
         * Put a 0 at the end of struct sockaddr_un because
         * the user might not have considered it in the length
         */
        if (ulen == sizeof(struct sockaddr_storage))
            *(((char *)usrsockaddr_un) + ulen - 1) = 0;
        else
            *(((char *)usrsockaddr_un) + ulen) = 0;

        /*
         * Pack the data into the target buffer
         */
        size = 1;

        *targetbuf = socket_family_to_scap((u8)family);
        dest = strncpy(targetbuf + 1,
                    usrsockaddr_un->sun_path,
                    UNIX_PATH_MAX);	/* we assume this will be smaller than (targetbufsize - (1 + 8 + 8)) */

        dest[UNIX_PATH_MAX - 1] = 0;
        size += (u16)strlen(dest) + 1;

        break;
    default:
        size = 0;
        break;
    }

    return size;
}

static int addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr)
{
    if (unlikely(ulen < 0 || ulen > sizeof(struct sockaddr_storage)))
        return -EINVAL;

    if (unlikely(ulen == 0))
        return 0;

    if (unlikely(nod_copy_from_user(kaddr, uaddr, ulen)))
        return -EFAULT;

    return 0;
}

static inline uint32_t get_fd_dev(int64_t fd)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    struct inode *inode;
    struct super_block *sb;
    uint32_t dev = 0;

    if (fd < 0)
        return dev;

    files = current->files;
    if (unlikely(!files))
        return dev;

    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    if (unlikely(fd > fdt->max_fds))
        goto out_unlock;

    file = fdt->fd[fd];
    if (unlikely(!file))
        goto out_unlock;

    inode = file_inode(file);
    if (unlikely(!inode))
        goto out_unlock;

    sb = inode->i_sb;
    if (unlikely(!sb))
        goto out_unlock;

    dev = new_encode_dev(sb->s_dev);

out_unlock:
    spin_unlock(&files->file_lock);
    return dev;
}

/*
 * Convert a connection tuple into our tuple representation and copy it to
 * targetbuf
 */
static u16 fd_to_socktuple(int fd,
    struct sockaddr *usrsockaddr,
    int ulen,
    bool use_userdata,
    bool is_inbound,
    char *targetbuf,
    u16 targetbufsize)
{
    int err = 0;
    sa_family_t family;
    u32 sip;
    u32 dip;
    u8 *sip6;
    u8 *dip6;
    u16 sport;
    u16 dport;
    struct sockaddr_in *usrsockaddr_in;
    struct sockaddr_in6 *usrsockaddr_in6;
    u16 size;
    struct sockaddr_storage sock_address;
    struct sockaddr_storage peer_address;
    struct socket *sock;
    char *dest;
    struct unix_sock *us;
    char *us_name;
    struct sock *speer;
    struct sockaddr_un *usrsockaddr_un;

    /*
     * Get the socket from the fd
     * NOTE: sockfd_lookup() locks the socket, so we don't need to worry when we dig in it
     */
    sock = sockfd_lookup(fd, &err);

    if (unlikely(!sock || !(sock->sk))) {
        /*
         * This usually happens if the call failed without being able to establish a connection,
         * i.e. if it didn't return something like SE_EINPROGRESS.
         */
        if (sock)
            sockfd_put(sock);
        return 0;
    }

    err = sock_getname(sock, (struct sockaddr *)&sock_address, 0);
    ASSERT(err == 0);

    family = sock->sk->sk_family;

    /*
     * Extract and pack the info, based on the family
     */
    switch (family) {
    case AF_INET:
        if (!use_userdata) {
            err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
            if (err == 0) {
                if (is_inbound) {
                    sip = ((struct sockaddr_in *) &peer_address)->sin_addr.s_addr;
                    sport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
                    dip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
                    dport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
                } else {
                    sip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
                    sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
                    dip = ((struct sockaddr_in *) &peer_address)->sin_addr.s_addr;
                    dport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
                }
            } else {
                sip = 0;
                sport = 0;
                dip = 0;
                dport = 0;
            }
        } else {
            /*
             * Map the user-provided address to a sockaddr_in
             */
            usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

            if (is_inbound) {
                sip = usrsockaddr_in->sin_addr.s_addr;
                sport = ntohs(usrsockaddr_in->sin_port);
                dip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
                dport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
            } else {
                sip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
                sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
                dip = usrsockaddr_in->sin_addr.s_addr;
                dport = ntohs(usrsockaddr_in->sin_port);
            }
        }

        /*
         * Pack the tuple info in the temporary buffer
         */
        size = 1 + 4 + 4 + 2 + 2; /* family + sip + dip + sport + dport */

        *targetbuf = socket_family_to_scap((u8)family);
        *(u32 *)(targetbuf + 1) = sip;
        *(u16 *)(targetbuf + 5) = sport;
        *(u32 *)(targetbuf + 7) = dip;
        *(u16 *)(targetbuf + 11) = dport;

        break;
    case AF_INET6:
        if (!use_userdata) {
            err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
            ASSERT(err == 0);

            if (is_inbound) {
                sip6 = ((struct sockaddr_in6 *) &peer_address)->sin6_addr.s6_addr;
                sport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
                dip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
                dport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
            } else {
                sip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
                sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
                dip6 = ((struct sockaddr_in6 *) &peer_address)->sin6_addr.s6_addr;
                dport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
            }
        } else {
            /*
             * Map the user-provided address to a sockaddr_in6
             */
            usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

            if (is_inbound) {
                sip6 = usrsockaddr_in6->sin6_addr.s6_addr;
                sport = ntohs(usrsockaddr_in6->sin6_port);
                dip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
                dport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
            } else {
                sip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
                sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
                dip6 = usrsockaddr_in6->sin6_addr.s6_addr;
                dport = ntohs(usrsockaddr_in6->sin6_port);
            }
        }

        /*
         * Pack the tuple info in the temporary buffer
         */
        size = 1 + 16 + 16 + 2 + 2; /* family + sip + dip + sport + dport */

        *targetbuf = socket_family_to_scap((u8)family);
        memcpy(targetbuf + 1,
            sip6,
            16);
        *(u16 *)(targetbuf + 17) = sport;
        memcpy(targetbuf + 19,
            dip6,
            16);
        *(u16 *)(targetbuf + 35) = dport;

        break;
    case AF_UNIX:
        /*
         * Retrieve the addresses
         */
        us = unix_sk(sock->sk);
        speer = us->peer;

        *targetbuf = socket_family_to_scap(family);

        if (is_inbound) {
            *(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)us;
            *(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)speer;
        } else {
            *(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)speer;
            *(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)us;
        }

        /*
         * Pack the data into the target buffer
         */
        size = 1 + 8 + 8;

        if (!use_userdata) {
            if (is_inbound) {
                us_name = ((struct sockaddr_un *) &sock_address)->sun_path;
            } else {
                err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
                ASSERT(err == 0);

                us_name = ((struct sockaddr_un *) &peer_address)->sun_path;
            }
        } else {
            /*
             * Map the user-provided address to a sockaddr_in
             */
            usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

            /*
             * Put a 0 at the end of struct sockaddr_un because
             * the user might not have considered it in the length
             */
            if (ulen == sizeof(struct sockaddr_storage))
                *(((char *)usrsockaddr_un) + ulen - 1) = 0;
            else
                *(((char *)usrsockaddr_un) + ulen) = 0;

            if (is_inbound)
                us_name = ((struct sockaddr_un *) &sock_address)->sun_path;
            else
                us_name = usrsockaddr_un->sun_path;
        }

        ASSERT(us_name);
        dest = strncpy(targetbuf + 1 + 8 + 8,
                    (char *)us_name,
                    UNIX_PATH_MAX);	/* we assume this will be smaller than (targetbufsize - (1 + 8 + 8)) */

        dest[UNIX_PATH_MAX - 1] = 0;
        size += strlen(dest) + 1;
        break;
    default:
        size = 0;
        break;
    }

    /*
     * Digging finished. We can release the fd.
     */
    sockfd_put(sock);

    return size;
}

static int val_to_ring(struct event_filler_arguments *args, uint64_t val, u32 val_len, bool fromuser, u8 dyn_idx)
{
    const struct nod_param_info *param_info;
    int len = -1;
    u16 *psize = (u16 *)(args->buf_ptr + args->curarg * sizeof(u16));
    u32 max_arg_size = args->arg_data_size;

    if (unlikely(args->curarg >= args->nargs)) {
        pr_err("(%u)val_to_ring: too many arguments for event #%llu, type=%u, curarg=%u, nargs=%u tid:%u\n",
            smp_processor_id(),
            args->nevents,
            (u32)args->event_type,
            args->curarg,
            args->nargs,
            current->pid);
        memory_dump(args->buf_ptr - sizeof(struct nod_event_hdr), 32);
        return NOD_FAILURE_BUG;
    }

    if (unlikely(args->arg_data_size == 0))
        return NOD_FAILURE_BUFFER_FULL;

    if (max_arg_size > NOD_MAX_ARG_SIZE)
        max_arg_size = NOD_MAX_ARG_SIZE;

    param_info = &(g_event_info[args->event_type].params[args->curarg]);
    if (param_info->type == PT_DYN && param_info->info != NULL) {
        const struct nod_param_info *dyn_params;

        if (unlikely(dyn_idx >= param_info->ninfo)) {
            return NOD_FAILURE_BUG;
        }

        dyn_params = (const struct nod_param_info *)param_info->info;

        param_info = &dyn_params[dyn_idx];
        if (likely(max_arg_size >= sizeof(u8)))	{
            *(u8 *)(args->buf_ptr + args->arg_data_offset) = dyn_idx;
            len = sizeof(u8);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }
        args->arg_data_offset += len;
        args->arg_data_size -= len;
        max_arg_size -= len;
        *psize = (u16)len;
    } else {
        *psize = 0;
    }

    switch (param_info->type) {
    case PT_CHARBUF:
    case PT_FSPATH:
    case PT_FSRELPATH:
        if (likely(val != 0)) {
            if (fromuser) {
                len = nod_strncpy_from_user(args->buf_ptr + args->arg_data_offset,
                    (const char __user *)(syscall_arg_t)val, max_arg_size);

                if (unlikely(len < 0)) {
                    INVALID_USER_MEMORY;
                }
            } else {
                len = (int)strlcpy(args->buf_ptr + args->arg_data_offset,
                                (const char *)(syscall_arg_t)val,
                                max_arg_size);

                if (++len > (int)max_arg_size)
                    len = max_arg_size;
            }
        } else {
            /*
             * Handle NULL pointers
             */
            len = (int)strlcpy(args->buf_ptr + args->arg_data_offset,
                "(NULL)",
                max_arg_size);

            if (++len > (int)max_arg_size)
                len = max_arg_size;
        }

        break;
    case PT_BYTEBUF:
        if (likely(val != 0)) {
            if (fromuser) {
                /*
                 * Copy the lookahead portion of the buffer that we will use DPI-based
                 * snaplen calculation
                 */
                u32 dpi_lookahead_size = 16; //temporary MAGIC number

                if (dpi_lookahead_size > val_len)
                    dpi_lookahead_size = val_len;

                if (unlikely(dpi_lookahead_size >= max_arg_size))
                    return NOD_FAILURE_BUFFER_FULL;

                len = (int)nod_copy_from_user(args->buf_ptr + args->arg_data_offset,
                        (const void __user *)(syscall_arg_t)val,
                        dpi_lookahead_size);

                if (unlikely(len != 0)) {
                    INVALID_USER_MEMORY;
                    break;
                }

                /*
                 * Check if there's more to copy
                 */
                if (likely((dpi_lookahead_size != val_len))) {
                    /*
                     * Calculate the snaplen
                     */
                    if (likely(args->snaplen > 0)) {
                        u32 sl = args->snaplen;

                        if (val_len > sl)
                            val_len = sl;
                    }

                    if (unlikely((val_len) >= max_arg_size))
                        val_len = max_arg_size;

                    if (val_len > dpi_lookahead_size) {
                        len = (int)nod_copy_from_user(args->buf_ptr + args->arg_data_offset + dpi_lookahead_size,
                                (const uint8_t __user *)(syscall_arg_t)val + dpi_lookahead_size,
                                val_len - dpi_lookahead_size);

                        if (unlikely(len != 0)) {
                            INVALID_USER_MEMORY;
                        }
                    }
                }

                len = val_len;
            } else {
                if (likely(args->snaplen > 0)) {
                    u32 sl = args->snaplen;

                    if (val_len > sl)
                        val_len = sl;
                }

                if (unlikely(val_len >= max_arg_size))
                    return NOD_FAILURE_BUFFER_FULL;

                memcpy(args->buf_ptr + args->arg_data_offset,
                    (void *)(syscall_arg_t)val, val_len);

                len = val_len;
            }
        } else {
            /*
             * Handle NULL pointers
             */
            len = 0;
        }

        break;
    case PT_SOCKADDR:
    case PT_SOCKTUPLE:
    case PT_FDLIST:
        if (likely(val != 0)) {
            if (unlikely(val_len >= max_arg_size))
                return NOD_FAILURE_BUFFER_FULL;

            if (fromuser) {
                len = (int)nod_copy_from_user(args->buf_ptr + args->arg_data_offset,
                        (const void __user *)(syscall_arg_t)val,
                        val_len);

                if (unlikely(len != 0)) {
                    INVALID_USER_MEMORY;
                } else {
                    len = val_len;
                }

            } else {
                memcpy(args->buf_ptr + args->arg_data_offset,
                    (void *)(syscall_arg_t)val, val_len);

                len = val_len;
            }
        } else {
            /*
             * Handle NULL pointers
             */
            len = 0;
        }

        break;
    case PT_FLAGS8:
    case PT_UINT8:
    case PT_SIGTYPE:
        if (likely(max_arg_size >= sizeof(u8)))	{
            *(u8 *)(args->buf_ptr + args->arg_data_offset) = (u8)val;
            len = sizeof(u8);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    case PT_FLAGS16:
    case PT_UINT16:
    case PT_SYSCALLID:
        if (likely(max_arg_size >= sizeof(u16))) {
            *(u16 *)(args->buf_ptr + args->arg_data_offset) = (u16)val;
            len = sizeof(u16);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    case PT_FLAGS32:
    case PT_UINT32:
    case PT_MODE:
    case PT_UID:
    case PT_GID:
    case PT_SIGSET:
        if (likely(max_arg_size >= sizeof(u32))) {
            *(u32 *)(args->buf_ptr + args->arg_data_offset) = (u32)val;
            len = sizeof(u32);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    case PT_RELTIME:
    case PT_ABSTIME:
    case PT_UINT64:
        if (likely(max_arg_size >= sizeof(u64))) {
            *(u64 *)(args->buf_ptr + args->arg_data_offset) = (u64)val;
            len = sizeof(u64);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    case PT_INT8:
        if (likely(max_arg_size >= sizeof(s8))) {
            *(s8 *)(args->buf_ptr + args->arg_data_offset) = (s8)(long)val;
            len = sizeof(s8);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    case PT_INT16:
        if (likely(max_arg_size >= sizeof(s16))) {
            *(s16 *)(args->buf_ptr + args->arg_data_offset) = (s16)(long)val;
            len = sizeof(s16);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    case PT_INT32:
        if (likely(max_arg_size >= sizeof(s32))) {
            *(s32 *)(args->buf_ptr + args->arg_data_offset) = (s32)(long)val;
            len = sizeof(s32);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    case PT_INT64:
    case PT_ERRNO:
    case PT_FD:
    case PT_PID:
        if (likely(max_arg_size >= sizeof(s64))) {
            *(s64 *)(args->buf_ptr + args->arg_data_offset) = (s64)(long)val;
            len = sizeof(s64);
        } else {
            return NOD_FAILURE_BUFFER_FULL;
        }

        break;
    default:
        pr_err("val_to_ring: invalid argument type %d. Event %u (%s) might have less parameters than what has been declared in nargs\n",
            (int)g_event_info[args->event_type].params[args->curarg].type,
            (u32)args->event_type,
            g_event_info[args->event_type].name);
        return NOD_FAILURE_BUG;
    }

    ASSERT(len <= NOD_MAX_ARG_SIZE); \
    ASSERT(len <= (int)max_arg_size); \
    *psize += (u16)len; \
    args->curarg++; \
    args->arg_data_offset += len; \
    args->arg_data_size -= len;

    return NOD_SUCCESS;
}

static int parse_sockopt(struct event_filler_arguments *args, int level, int optname, const void __user *optval, int optlen)
{
    union {
        uint32_t val32;
        uint64_t val64;
        struct timeval tv;
    } u;
    nanoseconds ns = 0;

    if (level == SOL_SOCKET) {
        switch (optname) {
#ifdef SO_ERROR
            case SO_ERROR:
                if (unlikely(nod_copy_from_user(&u.val32, optval, sizeof(u.val32))))
                    return NOD_FAILURE_INVALID_USER_MEMORY;
                return val_to_ring(args, -(int)u.val32, 0, false, NOD_SOCKOPT_IDX_ERRNO);
#endif

#ifdef SO_RCVTIMEO
            case SO_RCVTIMEO:
#endif
#ifdef SO_SNDTIMEO
            case SO_SNDTIMEO:
#endif
                if (unlikely(nod_copy_from_user(&u.tv, optval, sizeof(u.tv))))
                    return NOD_FAILURE_INVALID_USER_MEMORY;
                ns = u.tv.tv_sec * SECOND_IN_NS + u.tv.tv_usec * 1000;
                return val_to_ring(args, ns, 0, false, NOD_SOCKOPT_IDX_TIMEVAL);

#ifdef SO_COOKIE
            case SO_COOKIE:
                if (unlikely(nod_copy_from_user(&u.val64, optval, sizeof(u.val64))))
                    return NOD_FAILURE_INVALID_USER_MEMORY;
                return val_to_ring(args, u.val64, 0, false, NOD_SOCKOPT_IDX_UINT64);
#endif

#ifdef SO_DEBUG
            case SO_DEBUG:
#endif
#ifdef SO_REUSEADDR
            case SO_REUSEADDR:
#endif
#ifdef SO_TYPE
            case SO_TYPE:
#endif
#ifdef SO_DONTROUTE
            case SO_DONTROUTE:
#endif
#ifdef SO_BROADCAST
            case SO_BROADCAST:
#endif
#ifdef SO_SNDBUF
            case SO_SNDBUF:
#endif
#ifdef SO_RCVBUF
            case SO_RCVBUF:
#endif
#ifdef SO_SNDBUFFORCE
            case SO_SNDBUFFORCE:
#endif
#ifdef SO_RCVBUFFORCE
            case SO_RCVBUFFORCE:
#endif
#ifdef SO_KEEPALIVE
            case SO_KEEPALIVE:
#endif
#ifdef SO_OOBINLINE
            case SO_OOBINLINE:
#endif
#ifdef SO_NO_CHECK
            case SO_NO_CHECK:
#endif
#ifdef SO_PRIORITY
            case SO_PRIORITY:
#endif
#ifdef SO_BSDCOMPAT
            case SO_BSDCOMPAT:
#endif
#ifdef SO_REUSEPORT
            case SO_REUSEPORT:
#endif
#ifdef SO_PASSCRED
            case SO_PASSCRED:
#endif
#ifdef SO_RCVLOWAT
            case SO_RCVLOWAT:
#endif
#ifdef SO_SNDLOWAT
            case SO_SNDLOWAT:
#endif
#ifdef SO_SECURITY_AUTHENTICATION
            case SO_SECURITY_AUTHENTICATION:
#endif
#ifdef SO_SECURITY_ENCRYPTION_TRANSPORT
            case SO_SECURITY_ENCRYPTION_TRANSPORT:
#endif
#ifdef SO_SECURITY_ENCRYPTION_NETWORK
            case SO_SECURITY_ENCRYPTION_NETWORK:
#endif
#ifdef SO_BINDTODEVICE
            case SO_BINDTODEVICE:
#endif
#ifdef SO_DETACH_FILTER
            case SO_DETACH_FILTER:
#endif
#ifdef SO_TIMESTAMP
            case SO_TIMESTAMP:
#endif
#ifdef SO_ACCEPTCONN
            case SO_ACCEPTCONN:
#endif
#ifdef SO_PEERSEC
            case SO_PEERSEC:
#endif
#ifdef SO_PASSSEC
            case SO_PASSSEC:
#endif
#ifdef SO_TIMESTAMPNS
            case SO_TIMESTAMPNS:
#endif
#ifdef SO_MARK
            case SO_MARK:
#endif
#ifdef SO_TIMESTAMPING
            case SO_TIMESTAMPING:
#endif
#ifdef SO_PROTOCOL
            case SO_PROTOCOL:
#endif
#ifdef SO_DOMAIN
            case SO_DOMAIN:
#endif
#ifdef SO_RXQ_OVFL
            case SO_RXQ_OVFL:
#endif
#ifdef SO_WIFI_STATUS
            case SO_WIFI_STATUS:
#endif
#ifdef SO_PEEK_OFF
            case SO_PEEK_OFF:
#endif
#ifdef SO_NOFCS
            case SO_NOFCS:
#endif
#ifdef SO_LOCK_FILTER
            case SO_LOCK_FILTER:
#endif
#ifdef SO_SELECT_ERR_QUEUE
            case SO_SELECT_ERR_QUEUE:
#endif
#ifdef SO_BUSY_POLL
            case SO_BUSY_POLL:
#endif
#ifdef SO_MAX_PACING_RATE
            case SO_MAX_PACING_RATE:
#endif
#ifdef SO_BPF_EXTENSIONS
            case SO_BPF_EXTENSIONS:
#endif
#ifdef SO_INCOMING_CPU
            case SO_INCOMING_CPU:
#endif
                if (unlikely(nod_copy_from_user(&u.val32, optval, sizeof(u.val32))))
                    return NOD_FAILURE_INVALID_USER_MEMORY;
                return val_to_ring(args, u.val32, 0, false, NOD_SOCKOPT_IDX_UINT32);

            default:
                return val_to_ring(args, (unsigned long)optval, optlen, true, NOD_SOCKOPT_IDX_UNKNOWN);
        }
    } else {
        return val_to_ring(args, (unsigned long)optval, optlen, true, NOD_SOCKOPT_IDX_UNKNOWN);
    }
}

static int32_t parse_readv_writev_bufs(struct event_filler_arguments *args, const struct iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags)
{
	int32_t res;
	const struct iovec *iov;
	u64 copylen;
	u32 j;
	u64 size = 0;
	unsigned long bufsize;
	char *targetbuf = args->str_storage;
	u32 targetbuflen = STR_STORAGE_SIZE;
	unsigned long syscall_args[6] = {};
	unsigned long val;
	u32 notcopied_len;
	size_t tocopy_len;

	copylen = iovcnt * sizeof(struct iovec);

	if (unlikely(iovcnt >= 0xffffffff))
		return NOD_FAILURE_BUFFER_FULL;

	if (unlikely(copylen >= STR_STORAGE_SIZE))
		return NOD_FAILURE_BUFFER_FULL;

	if (unlikely(nod_copy_from_user(args->str_storage, iovsrc, copylen)))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct iovec *)(args->str_storage);

	targetbuf += copylen;
	targetbuflen -= copylen;

	/*
	 * Size
	 */
	if (flags & PRB_FLAG_PUSH_SIZE) {
		for (j = 0; j < iovcnt; j++)
			size += iov[j].iov_len;

		/*
		 * Size is the total size of the buffers provided by the user. The number of
		 * received bytes can be smaller
		 */
		if ((flags & PRB_FLAG_IS_WRITE) == 0)
			if (size > retval)
				size = retval;

		res = val_to_ring(args, size, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	/*
	 * data
	 */
	if (flags & PRB_FLAG_PUSH_DATA) {
		if (retval > 0 && iovcnt > 0) {
			/*
			 * Retrieve the FD. It will be used for dynamic snaplen calculation.
			 */
            nod_syscall_get_arguments(current, args->regs, syscall_args);
            val = syscall_args[0];

			/*
			 * Merge the buffers
			 */
			bufsize = 0;

			for (j = 0; j < iovcnt; j++) {
				if ((flags & PRB_FLAG_IS_WRITE) == 0) {
					if (bufsize >= retval) {
						ASSERT(bufsize >= retval);

						/*
						 * Copied all the data even if we haven't reached the
						 * end of the buffer.
						 * Copy must stop here.
						 */
						break;
					}

					tocopy_len = min(iov[j].iov_len, (size_t)retval - bufsize);
					tocopy_len = min(tocopy_len, (size_t)targetbuflen - bufsize - 1);
				} else {
					tocopy_len = min(iov[j].iov_len, targetbuflen - bufsize - 1);
				}

				notcopied_len = (int)nod_copy_from_user(targetbuf + bufsize,
						iov[j].iov_base,
						tocopy_len);

				if (unlikely(notcopied_len != 0)) {
					/*
					 * This means we had a page fault. Skip this event.
					 */
					return NOD_FAILURE_INVALID_USER_MEMORY;
				}

				bufsize += tocopy_len;

				if (tocopy_len != iov[j].iov_len) {
					/*
					 * No space left in the args->str_storage buffer.
					 * Copy must stop here.
					 */
					break;
				}
			}

			res = val_to_ring(args,
				(unsigned long)targetbuf,
				bufsize,
				false,
				0);
			if (unlikely(res != NOD_SUCCESS))
				return res;
		} else {
			res = val_to_ring(args, 0, 0, false, 0);
			if (unlikely(res != NOD_SUCCESS))
				return res;
		}
	}

	return NOD_SUCCESS;
}

static inline int parse_ptrace_addr(struct event_filler_arguments *args, u16 request)
{
	unsigned long val;
	uint64_t dst;
	u8 idx;

	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	switch (request) {
	default:
		idx = NOD_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

static inline int parse_ptrace_data(struct event_filler_arguments *args, u16 request)
{
	unsigned long val;
	unsigned long len;
	uint64_t dst;
	u8 idx;

	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	switch (request) {
	case NOD_PTRACE_PEEKTEXT:
	case NOD_PTRACE_PEEKDATA:
	case NOD_PTRACE_PEEKUSR:
		idx = NOD_PTRACE_IDX_UINT64;
		len = nod_copy_from_user(&dst, (const void __user *)val, sizeof(long));
		if (unlikely(len != 0))
			return NOD_FAILURE_INVALID_USER_MEMORY;

		break;
	case NOD_PTRACE_CONT:
	case NOD_PTRACE_SINGLESTEP:
	case NOD_PTRACE_DETACH:
	case NOD_PTRACE_SYSCALL:
		idx = NOD_PTRACE_IDX_SIGTYPE;
		dst = (uint64_t)val;
		break;
	case NOD_PTRACE_ATTACH:
	case NOD_PTRACE_TRACEME:
	case NOD_PTRACE_POKETEXT:
	case NOD_PTRACE_POKEDATA:
	case NOD_PTRACE_POKEUSR:
	default:
		idx = NOD_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
		break;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

static int poll_parse_fds(struct event_filler_arguments *args, bool enter_event)
{
	struct pollfd *fds;
	char *targetbuf;
	unsigned long val;
	unsigned long nfds;
	unsigned long fds_count;
	u32 j;
	u32 pos;
	u16 flags;

	/*
	 * fds
	 *
	 * Get the number of fds
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &nfds);

	/*
	 * Check if we have enough space to store both the fd list
	 * from user space and the temporary buffer to serialize to the ring
	 */
	if (unlikely(sizeof(struct pollfd) * nfds + 2 + 10 * nfds > STR_STORAGE_SIZE))
		return NOD_FAILURE_BUFFER_FULL;

	/* Get the fds pointer */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	fds = (struct pollfd *)args->str_storage;

		if (unlikely(nod_copy_from_user(fds, (const void __user *)val, nfds * sizeof(struct pollfd))))
			return NOD_FAILURE_INVALID_USER_MEMORY;


	pos = 2;
	targetbuf = args->str_storage + nfds * sizeof(struct pollfd) + pos;
	fds_count = 0;

	/* Copy each fd into the temporary buffer */
	for (j = 0; j < nfds; j++) {
		if (enter_event) {
			flags = poll_events_to_scap(fds[j].events);
		} else {
			/*
			 * If it's an exit event, we copy only the fds that
			 * returned something
			 */
			if (!fds[j].revents)
				continue;

			flags = poll_events_to_scap(fds[j].revents);
		}

		*(int64_t *)(targetbuf + pos) = fds[j].fd;
		*(int16_t *)(targetbuf + pos + 8) = flags;
		pos += 10;
		++fds_count;
	}

	*(u16 *)(targetbuf) = (u16)fds_count;

	return val_to_ring(args, (uint64_t)(unsigned long)targetbuf, pos, false, 0);
}

static int nod_get_tty(void)
{
	/* Locking of the signal structures seems too complicated across
	 * multiple kernel versions to get it right, so simply do protected
	 * memory accesses, and in the worst case we get some garbage,
	 * which is not the end of the world. In the vast majority of accesses,
	 * we'll be just fine.
	 */
	struct signal_struct *sig;
	struct tty_struct *tty;
	struct tty_driver *driver;
	int major;
	int minor_start;
	int index;
	int tty_nr = 0;

	sig = current->signal;
	if (!sig)
		return 0;

	if (unlikely(copy_from_kernel_nofault(&tty, &sig->tty, sizeof(tty))))
		return 0;

	if (!tty)
		return 0;

	if (unlikely(copy_from_kernel_nofault(&index, &tty->index, sizeof(index))))
		return 0;

	if (unlikely(copy_from_kernel_nofault(&driver, &tty->driver, sizeof(driver))))
		return 0;

	if (!driver)
		return 0;

	if (unlikely(copy_from_kernel_nofault(&major, &driver->major, sizeof(major))))
		return 0;

	if (unlikely(copy_from_kernel_nofault(&minor_start, &driver->minor_start, sizeof(minor_start))))
		return 0;

	tty_nr = new_encode_dev(MKDEV(major, minor_start) + index);

	return tty_nr;
}

static int timespec_parse(struct event_filler_arguments *args, unsigned long val)
{
	uint64_t longtime;
	char *targetbuf = args->str_storage;
	struct timespec *tts = (struct timespec *)targetbuf;
	int cfulen;

	/*
	 * interval
	 * We copy the timespec structure and then convert it to a 64bit relative time
	 */

		cfulen = (int)nod_copy_from_user(targetbuf, (void __user *)val, sizeof(*tts));
		if (unlikely(cfulen != 0))
			return NOD_FAILURE_INVALID_USER_MEMORY;

		longtime = ((uint64_t)tts->tv_sec) * 1000000000 + tts->tv_nsec;


	return val_to_ring(args, longtime, 0, false, 0);
}

#ifdef CONFIG_CGROUPS
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
static int nod_cgroup_path(const struct cgroup *cgrp, char *buf, int buflen)
{
	char *start;
	struct dentry *dentry = rcu_dereference(cgrp->dentry);

	if (!dentry) {
		/*
		 * Inactive subsystems have no dentry for their root
		 * cgroup
		 */
		strcpy(buf, "/");
		return 0;
	}

	start = buf + buflen;

	*--start = '\0';
	for (;;) {
		int len = dentry->d_name.len;

		start -= len;
		if (start < buf)
			return -ENAMETOOLONG;
		memcpy(start, cgrp->dentry->d_name.name, len);
		cgrp = cgrp->parent;
		if (!cgrp)
			break;
		dentry = rcu_dereference(cgrp->dentry);
		if (!cgrp->parent)
			continue;
		if (--start < buf)
			return -ENAMETOOLONG;
		*start = '/';
	}
	memmove(buf, start, buf + buflen - start);
	return 0;
}
#endif

static int append_cgroup(const char *subsys_name, int subsys_id, char *buf, int *available)
{
	int pathlen;
	int subsys_len;
	char *path;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) || LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	int res;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	struct cgroup_subsys_state *css = task_css(current, subsys_id);
#else
	struct cgroup_subsys_state *css = task_subsys_state(current, subsys_id);
#endif

	if (!css) {
		ASSERT(false);
		return 1;
	}

	if (!css->cgroup) {
		ASSERT(false);
		return 1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	// According to https://github.com/torvalds/linux/commit/4c737b41de7f4eef2a593803bad1b918dd718b10
	// cgroup_path now returns an int again
	res = cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	path = cgroup_path(css->cgroup, buf, *available);
	if (!path) {
		ASSERT(false);
		path = "NA";
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	res = cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#else
	res = nod_cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#endif

	pathlen = strlen(path);
	subsys_len = strlen(subsys_name);
	if (subsys_len + 1 + pathlen + 1 > *available)
		return 1;

	memmove(buf + subsys_len + 1, path, pathlen);
	memcpy(buf, subsys_name, subsys_len);
	buf += subsys_len;
	*buf++ = '=';
	buf += pathlen;
	*buf++ = 0;
	*available -= (subsys_len + 1 + pathlen + 1);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _cgrp_id, args->str_storage + STR_STORAGE_SIZE - available, &available))	\
	goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define IS_SUBSYS_ENABLED(option) IS_BUILTIN(option)
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define IS_SUBSYS_ENABLED(option) IS_ENABLED(option)
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#else
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#endif

#endif

static int nod_autofill(struct event_filler_arguments *args, int start_index, int end_index)
{
	int res;
	syscall_arg_t syscall_args[6] = {0};
	syscall_arg_t val;
	u32 j;
	int64_t retval;

	const struct nod_event_entry *evinfo = &g_nod_events[args->event_type];
	ASSERT(evinfo->n_autofill_args <= NOD_MAX_AUTOFILL_ARGS && 
        start_index >= 0 && end_index <= evinfo->n_autofill_args);

	for (j = start_index; j < end_index; j++) {
		if (evinfo->autofill_args[j].id >= 0) {
#ifdef _HAS_SOCKETCALL
			if (args->is_socketcall && evinfo->paramtype == APT_SOCK) {
				val = args->socketcall_args[evinfo->autofill_args[j].id];
			} else
#endif
			{
				/*
				 * Regular argument
				 */
				nod_syscall_get_arguments(current, args->regs, syscall_args);
				val = syscall_args[evinfo->autofill_args[j].id];
			}

			res = val_to_ring(args, val, 0, true, 0);
			if (unlikely(res != NOD_SUCCESS))
				return res;
		} else if (evinfo->autofill_args[j].id == AF_ID_RETVAL) {
			/*
			 * Return value
			 */
			retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
			res = val_to_ring(args, retval, 0, false, 0);
			if (unlikely(res != NOD_SUCCESS))
				return res;
		} else if (evinfo->autofill_args[j].id == AF_ID_USEDEFAULT) {
			/*
			 * Default Value
			 */
			res = val_to_ring(args, evinfo->autofill_args[j].default_val, 0, false, 0);
			if (unlikely(res != NOD_SUCCESS))
				return res;
		} else {
			ASSERT(false);
		}
	}

	return NOD_SUCCESS;
}


int nod_filler_callback(struct event_filler_arguments *args)
{
    int event_type;
    int start_index, end_index;
    int i, cbret;
    const struct nod_event_entry *evinfo;

    event_type = args->event_type;
    if (event_type < 0 || event_type >= NODE_EVENT_MAX) {
        pr_err("corrupted event type %d: out of bound\n", event_type);
        return NOD_FAILURE_BUG;
    }
    if (!g_nod_events[event_type].filler_callback) {
        pr_err("corrupted event type %d: NULL callback\n", event_type);
        return NOD_FAILURE_BUG;
    }

    evinfo = &g_nod_events[args->event_type];

    if (evinfo->n_autofill_args == 0) {
        cbret = g_nod_events[event_type].filler_callback(args);
    } else {
        start_index = 0;
        end_index = evinfo->n_autofill_args;
        
        for (i = 0; i < evinfo->n_autofill_args; i++) {
            if (evinfo->autofill_args[i].id < 0) {
                end_index = i;
                break;
            }
        }

        cbret = nod_autofill(args, start_index, end_index);
        if (unlikely(cbret != NOD_SUCCESS))
            return cbret;

        cbret = g_nod_events[event_type].filler_callback(args);
        if (unlikely(cbret != NOD_SUCCESS))
            return cbret;

        cbret = nod_autofill(args, end_index, evinfo->n_autofill_args);
    }

    return cbret;
}

int f_proc_startupdate(struct event_filler_arguments *args)
{
	unsigned long val;
	int res = 0;
	unsigned int exe_len = 0;  /* the length of the executable string */
	int args_len = 0; /*the combined length of the arguments string + executable string */
	struct mm_struct *mm = current->mm;
	int64_t retval;
	int ptid;
	char *spwd = "";
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	int available = STR_STORAGE_SIZE;

#ifdef __NR_clone3
	struct clone_args cl_args;
#endif

	/*
	 * Make sure the operation was successful
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	if (unlikely(retval < 0 &&
		     args->event_type != NODE_SYSCALL_EXECVE_19 &&
			 args->event_type != NODE_SYSCALL_EXECVEAT)) {

		/* The call failed, but this syscall has no exe, args
		 * anyway, so I report empty ones */
		*args->str_storage = 0;

		/*
		 * exe
		 */
		res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * Args
		 */
		res = val_to_ring(args, (int64_t)(long)args->str_storage, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {

		if (likely(retval >= 0)) {
			/*
			 * The call succeeded. Get exe, args from the current
			 * process; put one \0-separated exe-args string into
			 * str_storage
			 */

			if (unlikely(!mm)) {
				args->str_storage[0] = 0;
				pr_info("f_proc_startupdate drop, mm=NULL\n");
				return NOD_FAILURE_BUG;
			}

			if (unlikely(!mm->arg_end)) {
				args->str_storage[0] = 0;
				pr_info("f_proc_startupdate drop, mm->arg_end=NULL\n");
				return NOD_FAILURE_BUG;
			}

			args_len = mm->arg_end - mm->arg_start;

			if (args_len) {
				if (args_len > PAGE_SIZE)
					args_len = PAGE_SIZE;

				if (unlikely(nod_copy_from_user(args->str_storage, (const void __user *)mm->arg_start, args_len)))
					args_len = 0;
				else
					args->str_storage[args_len - 1] = 0;
			}
		} else {

			/*
			 * The execve or execveat call failed. I get exe, args from the
			 * input args; put one \0-separated exe-args string into
			 * str_storage
			 */
			args->str_storage[0] = 0;

			switch (args->event_type)
			{
			case NODE_SYSCALL_EXECVE_19:
				syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
				break;
			
			case NODE_SYSCALL_EXECVEAT:
				syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
				break;

			default:
				val = 0;
				break;
			}

				args_len = accumulate_argv_or_env((const char __user * __user *)val,
							   args->str_storage, available);

			if (unlikely(args_len < 0))
				args_len = 0;
		}

		if (args_len == 0)
			*args->str_storage = 0;

		exe_len = strnlen(args->str_storage, args_len);
		if (exe_len < args_len)
			++exe_len;

		/*
		 * exe
		 */
		res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * Args
		 */
		res = val_to_ring(args, (int64_t)(long)args->str_storage + exe_len, args_len - exe_len, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}


	/*
	 * tid
	 */
	res = val_to_ring(args, (int64_t)current->pid, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * pid
	 */
	res = val_to_ring(args, (int64_t)current->tgid, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * ptid
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	if (current->real_parent)
		ptid = current->real_parent->pid;
#else
	if (current->parent)
		ptid = current->parent->pid;
#endif
	else
		ptid = 0;

	res = val_to_ring(args, (int64_t)ptid, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * cwd, pushed empty to avoid breaking compatibility
	 * with the older event format
	 */
	res = val_to_ring(args, (uint64_t)(long)spwd, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * fdlimit
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	res = val_to_ring(args, (int64_t)rlimit(RLIMIT_NOFILE), 0, false, 0);
#else
	res = val_to_ring(args, (int64_t)0, 0, false, 0);
#endif
	if (res != NOD_SUCCESS)
		return res;

	/*
	 * pgft_maj
	 */
	res = val_to_ring(args, current->maj_flt, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * pgft_min
	 */
	res = val_to_ring(args, current->min_flt, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = nod_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = nod_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * comm
	 */
	res = val_to_ring(args, (uint64_t)current->comm, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * cgroups
	 */
	args->str_storage[0] = 0;
#ifdef CONFIG_CGROUPS
	rcu_read_lock();
#include <linux/cgroup_subsys.h>
cgroups_error:
	rcu_read_unlock();
#endif

	res = val_to_ring(args, (int64_t)(long)args->str_storage, STR_STORAGE_SIZE - available, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	if (args->event_type == NODE_SYSCALL_CLONE_20 ||
		args->event_type == NODE_SYSCALL_FORK_20 ||
		args->event_type == NODE_SYSCALL_VFORK_20 ||
		args->event_type == NODE_SYSCALL_CLONE3) 
		{
		/*
		 * clone-only parameters
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		uint64_t euid = from_kuid_munged(current_user_ns(), current_euid());
		uint64_t egid = from_kgid_munged(current_user_ns(), current_egid());
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		uint64_t euid = current_euid();
		uint64_t egid = current_egid();
#else
		uint64_t euid = current->euid;
		uint64_t egid = current->egid;
#endif
		int64_t in_pidns = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		struct pid_namespace *pidns = task_active_pid_ns(current);
#endif

		/*
		 * flags
		 */
		switch (args->event_type)
		{
		case NODE_SYSCALL_CLONE_20:
#ifdef CONFIG_S390
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
#else
			syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
#endif
			break;

		case NODE_SYSCALL_CLONE3:
#ifdef __NR_clone3
			syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
			res = nod_copy_from_user(&cl_args, (void *)val, sizeof(struct clone_args));
			if (unlikely(res != 0))
			{
				return NOD_FAILURE_INVALID_USER_MEMORY;
			}
			val = cl_args.flags;
#else
			val = 0;
#endif
			break;
		
		default:
			val = 0;
			break;
		}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		if(pidns != &init_pid_ns || pid_ns_for_children(current) != pidns)
			in_pidns = NOD_CL_CHILD_IN_PIDNS;
#endif
		res = val_to_ring(args, (uint64_t)clone_flags_to_scap(val) | in_pidns, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * uid
		 */
		res = val_to_ring(args, euid, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * gid
		 */
		res = val_to_ring(args, egid, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * vtid
		 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		res = val_to_ring(args, task_pid_vnr(current), 0, false, 0);
#else
		/* Not relevant in old kernels */
		res = val_to_ring(args, 0, 0, false, 0);
#endif
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * vpid
		 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		res = val_to_ring(args, task_tgid_vnr(current), 0, false, 0);
#else
		/* Not relevant in old kernels */
		res = val_to_ring(args, 0, 0, false, 0);
#endif
		if (unlikely(res != NOD_SUCCESS))
			return res;

	} else if (args->event_type == NODE_SYSCALL_EXECVE_19 || 
			   args->event_type == NODE_SYSCALL_EXECVEAT) {
		/*
		 * execve family parameters.
		 */
		long env_len = 0;
		int tty_nr = 0;
		bool exe_writable = false;
		struct file *exe_file = NULL;
		uint32_t flags = 0; // execve additional flags

		if (likely(retval >= 0)) {
			/*
			 * Already checked for mm validity
			 */
			env_len = mm->env_end - mm->env_start;

			if (env_len) {
				if (env_len > PAGE_SIZE)
					env_len = PAGE_SIZE;

				if (unlikely(nod_copy_from_user(args->str_storage, (const void __user *)mm->env_start, env_len)))
					env_len = 0;
				else
					args->str_storage[env_len - 1] = 0;
			}
		} else {
			/*
			 * The call failed, so get the env from the arguments
			 */
			switch (args->event_type)
			{
			case NODE_SYSCALL_EXECVE_19:
				syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
				break;
			
			case NODE_SYSCALL_EXECVEAT:
				syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
				break;

			default:
				val = 0;
				break;
			} 
			
			env_len = accumulate_argv_or_env((const char __user * __user *)val,
							  args->str_storage, available);

			if (unlikely(env_len < 0))
				env_len = 0;
		}

		if (env_len == 0)
			*args->str_storage = 0;

		/*
		 * environ
		 */
		res = val_to_ring(args, (int64_t)(long)args->str_storage, env_len, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * tty
		 */
		tty_nr = nod_get_tty();
		res = val_to_ring(args, tty_nr, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * pgid
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
		res = val_to_ring(args, (int64_t)task_pgrp_nr_ns(current, task_active_pid_ns(current)), 0, false, 0);
#else
		res = val_to_ring(args, (int64_t)process_group(current), 0, false, 0);
#endif
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
	 	* loginuid
	 	*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		val = from_kuid(current_user_ns(), audit_get_loginuid(current));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		val = audit_get_loginuid(current);
#else
		val = audit_get_loginuid(current->audit_context);
#endif
		res = val_to_ring(args, val, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/*
		 * exe_writable flag
		 */

		exe_file = nod_get_mm_exe_file(mm);

		if (exe_file != NULL) {
			if (file_inode(exe_file) != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
				exe_writable |= (inode_permission(current_user_ns(), file_inode(exe_file), MAY_WRITE) == 0);
				exe_writable |= inode_owner_or_capable(current_user_ns(), file_inode(exe_file));
#else
				exe_writable |= (inode_permission(file_inode(exe_file), MAY_WRITE) == 0);
				exe_writable |= inode_owner_or_capable(file_inode(exe_file));
#endif
			}
			fput(exe_file);
		}

		if (exe_writable) {
			flags |= NOD_EXE_WRITABLE;
		}

		// write all the additional flags for execve family here...

		/*
		 * flags
		 */

		res = val_to_ring(args, flags, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	return NOD_SUCCESS;
}

int f_sys_empty(struct event_filler_arguments *args)
{
	return NOD_SUCCESS;
}

int f_sys_generic(struct event_filler_arguments *args)
{
    int res;
    long table_index = args->syscall_nr;

    if (table_index >= 0 &&
        table_index < SYSCALL_TABLE_SIZE) {
		res = val_to_ring(args, table_index, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
                return res;
	} else {
		ASSERT(false);
		res = val_to_ring(args, (u64)"<out of bound>", 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}
    return NOD_SUCCESS;
}

int f_sys_open(struct event_filler_arguments *args)
{
	syscall_arg_t val;
	syscall_arg_t flags;
	syscall_arg_t modes;
	int res;
	int64_t retval;

	/*
	 * fd
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;


	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the nod portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &flags);
	res = val_to_ring(args, open_flags_to_scap(flags), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dev
	 */
	res = val_to_ring(args, get_fd_dev(retval), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_CLOSE: autofill only */

int f_sys_read(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	/*
	 * Copy the buffer
	 */
	// args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_write(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);

	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * data
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	bufsize = val;

	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_BRK_1: auto fill only */
/* NODE_SYSCALL_EXIT: auto fill only */
/* NODE_SYSCALL_EXIT_GROUP: auto fill only */

int f_sys_execve(struct event_filler_arguments *args)
{
	int res;
	syscall_arg_t val;

	/*
	 * filename
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (res == NOD_FAILURE_INVALID_USER_MEMORY)
		res = val_to_ring(args, (unsigned long)"<NA>", 0, false, 0);

	if (unlikely(res != NOD_SUCCESS))
		return res;

	return f_proc_startupdate(args);
}

int f_sys_execveat(struct event_filler_arguments *args)
{
	int res;
	syscall_arg_t val;
	unsigned long flags;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
	{
		val = NOD_AT_FDCWD;
	}

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
	{
		return res;
	}

	/*
	 * pathname
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res == NOD_FAILURE_INVALID_USER_MEMORY))
	{
		res = val_to_ring(args, (unsigned long)"<NA>", 0, false, 0);
	}
	if (unlikely(res != NOD_SUCCESS))
	{
		return res;
	}

	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	flags = execveat_flags_to_scap(val);

	res = val_to_ring(args, flags, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
	{
		return res;
	}

	return f_proc_startupdate(args);
}

/* NODE_SYSCALL_SOCKET_SOCKET: auto fill only */

int f_sys_socket_bind(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	int err = 0;
	u16 size = 0;
	struct sockaddr __user *usrsockaddr;
	syscall_arg_t val;
	struct sockaddr_storage address;
	char *targetbuf = args->str_storage;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);

	/*
	 * addr
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];

	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	else
		val = args->socketcall_args[2];

	if (usrsockaddr != NULL && val != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = pack_addr((struct sockaddr *)&address,
				val,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_connect(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	int err = 0;
	int fd;
	struct sockaddr __user *usrsockaddr;
	u16 size = 0;
	char *targetbuf = args->str_storage;
	struct sockaddr_storage address;
	syscall_arg_t val;

	/*
	 * Push the result
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);

	/*
	 * Retrieve the fd and push it to the ring.
	 * Note that, even if we are in the exit callback, the arguments are still
	 * in the stack, and therefore we can consume them.
	 */
	if (!args->is_socketcall) {
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
		fd = (int)val;
	}
	else
		fd = (int)args->socketcall_args[0];

	if (fd >= 0) {
		/*
		 * Get the address
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
		else
			val = args->socketcall_args[1];

		usrsockaddr = (struct sockaddr __user *)val;

		/*
		 * Get the address len
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
		else
			val = args->socketcall_args[2];

		if (usrsockaddr != NULL && val != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					val,
					true,
					false,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_send_e_common(struct event_filler_arguments *args, int *fd)
{
	int res;
	unsigned long size;
	unsigned long val;

	/*
	 * fd
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
#ifndef UDIG
	else
		val = args->socketcall_args[0];
#endif

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	*fd = val;

	/*
	 * size
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 2, 1, &size);
#ifndef UDIG
	else
		size = args->socketcall_args[2];
#endif

	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_send_x_common(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[0];

	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
		else
			val = args->socketcall_args[1];

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	//args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_send(struct event_filler_arguments *args)
{
	int res;
	int fd;

	res = f_sys_send_e_common(args, &fd);
	if (unlikely(res != NOD_SUCCESS))
		return res;

    return f_sys_send_x_common(args);
}

int f_sys_sendto(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u16 size = 0;
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	int err = 0;

	*targetbuf = 250;

	/*
	 * Push the common params to the ring
	 */
	res = f_sys_send_e_common(args, &fd);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Get the address
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	else
		val = args->socketcall_args[4];

	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 5, 1, &val);
	else
		val = args->socketcall_args[5];

	if (usrsockaddr != NULL && val != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
				(struct sockaddr *)&address,
				val,
				true,
				false,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return f_sys_send_x_common(args);
}

int f_sys_recv_common(struct event_filler_arguments *args, int64_t *retval)
{
	int res;
	unsigned long val;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[1];

	args->fd = (int)val;

	/*
	 * res
	 */
	*retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, *retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (*retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
		else
			val = args->socketcall_args[1];

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = *retval;
	}

	//args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_recv(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;

	res = f_sys_recv_common(args, &retval);
	if (unlikely(res != NOD_SUCCESS))
		return res;

    return NOD_SUCCESS; 
}

int f_sys_recvfrom(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u16 size = 0;
	int64_t retval;
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	int addrlen;
	int err = 0;

	/*
	 * Push the common params to the ring
	 */
	res = f_sys_recv_common(args, &retval);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	if (retval >= 0) {
		/*
		 * Get the fd
		 */
		if (!args->is_socketcall) {
			syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
			fd = (int)val;
		} 
		else
			fd = (int)args->socketcall_args[0];

		/*
		 * Get the address
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
		else
			val = args->socketcall_args[4];
		usrsockaddr = (struct sockaddr __user *)val;

		/*
		 * Get the address len
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 5, 1, &val);
		else
			val = args->socketcall_args[5];
		if (usrsockaddr != NULL && val != 0) {

				if (unlikely(nod_copy_from_user(&addrlen, (const void __user *)val, sizeof(addrlen))))
					return NOD_FAILURE_INVALID_USER_MEMORY;


			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					addrlen,
					true,
					true,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_shutdown(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * fd
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[0];

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * how
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];

	res = val_to_ring(args, (unsigned long)shutdown_how_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SOCKET_GETSOCKNAME: empty */
/* NODE_SOCKET_GETPEERNAME: empty */

int f_sys_socketpair(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	int err;
	struct socket *sock;
	struct unix_sock *us;
	struct sock *speer;

	/*
	 * retval
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * If the call was successful, copy the FDs
	 */
	if (likely(retval >= 0)) {
		/*
		 * fds
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
		else
			val = args->socketcall_args[3];

		if (unlikely(nod_copy_from_user(fds, (const void __user *)val, sizeof(fds))))
			return NOD_FAILURE_INVALID_USER_MEMORY;


		res = val_to_ring(args, fds[0], 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		res = val_to_ring(args, fds[1], 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		/* get socket source and peer address */
		sock = sockfd_lookup(fds[0], &err);
		if (likely(sock != NULL)) {
			us = unix_sk(sock->sk);
			speer = us->peer;
			res = val_to_ring(args, (unsigned long)us, 0, false, 0);
			if (unlikely(res != NOD_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			res = val_to_ring(args, (unsigned long)speer, 0, false, 0);
			if (unlikely(res != NOD_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			sockfd_put(sock);
		} else {
			return err;
		}
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	return NOD_SUCCESS;
}

int f_sys_setsockopt(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	syscall_arg_t val[5] = {0};

	syscall_get_arguments_deprecated(current, args->regs, 0, 5, val);
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);

	/* retval */
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* fd */
	res = val_to_ring(args, val[0], 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* level */
	res = val_to_ring(args, sockopt_level_to_scap(val[1]), 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* optname */
	res = val_to_ring(args, sockopt_optname_to_scap(val[1], val[2]), 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* optval */
	res = parse_sockopt(args, val[1], val[2], (const void __user*)val[3], val[4]);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* optlen */
	res = val_to_ring(args, val[4], 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_getsockopt(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	uint32_t optlen;
	syscall_arg_t val[5] = {0};

	syscall_get_arguments_deprecated(current, args->regs, 0, 5, val);
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);

	/* retval */
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* fd */
	res = val_to_ring(args, val[0], 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* level */
	res = val_to_ring(args, sockopt_level_to_scap(val[1]), 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* optname */
	res = val_to_ring(args, sockopt_optname_to_scap(val[1], val[2]), 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	if (unlikely(nod_copy_from_user(&optlen, (const void __user*)val[4], sizeof(optlen))))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	/* optval */
	res = parse_sockopt(args, val[1], val[2], (const void __user*)val[3], optlen);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/* optlen */
	res = val_to_ring(args, optlen, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_sendmsg(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
	int64_t retval;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	char *targetbuf = args->str_storage;
	const struct iovec __user *iov;
	unsigned long iovcnt;
	int fd;
	u16 size = 0;
	int addrlen;
	int err = 0;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;

	/*
	 * fd
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[0];

	fd = val;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];


	if (unlikely(nod_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	/*
	* size
	*/
	iov = (const struct iovec __user *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, args->snaplen, PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);


	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	* tuple
	*/
	usrsockaddr = (struct sockaddr __user *)mh.msg_name;
	addrlen = mh.msg_namelen;


	if (usrsockaddr != NULL && addrlen != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
				(struct sockaddr *)&address,
				addrlen,
				true,
				false,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != NOD_SUCCESS))
		return res;



	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];

	/*
	 * data
	 */
	if (unlikely(nod_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct iovec __user *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, args->snaplen, PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_recvmsg(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
	int64_t retval;
	const struct iovec __user *iov;
	unsigned long iovcnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	u16 size = 0;
	int addrlen;
	int err = 0;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];


	if (unlikely(nod_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	/*
	* data and size
	*/
	iov = (const struct iovec __user *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * tuple
	 */
	if (retval >= 0) {
		/*
		 * Get the fd
		 */
		if (!args->is_socketcall) {
			syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
			fd = (int)val;
		} 
		else
			fd = (int)args->socketcall_args[0];

		/*
		 * Get the address
		 */
		usrsockaddr = (struct sockaddr __user *)mh.msg_name;
		addrlen = mh.msg_namelen;

		if (usrsockaddr != NULL && addrlen != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					addrlen,
					true,
					true,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_creat(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long modes;
	int res;
	int64_t retval;

	/*
	 * fd
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(O_CREAT, modes), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dev
	 */
	res = val_to_ring(args, get_fd_dev(retval), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_pipe(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	struct file *file;

	/*
	 * retval
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * fds
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);


		if (unlikely(nod_copy_from_user(fds, (const void __user *)val, sizeof(fds))))
			return NOD_FAILURE_INVALID_USER_MEMORY;


	res = val_to_ring(args, fds[0], 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	res = val_to_ring(args, fds[1], 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	val = 0;
	file = fget(fds[0]);
	if (likely(file != NULL)) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		val = file->f_path.dentry->d_inode->i_ino;
#else
		val = file->f_dentry->d_inode->i_ino;
#endif
		fput(file);
	}

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_eventfd(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * initval
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * flags
	 * XXX not implemented yet
	 */
	/* syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val); */
	val = 0;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_futex(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * op
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, (unsigned long)futex_op_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * val
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_STAT: auto fill only */
/* NODE_SYSCALL_LSTAT: auto fill only */
/* NODE_SYSCALL_FSTAT: auto fill only */
/* NODE_SYSCALL_STAT64: auto fill only */
/* NODE_SYSCALL_LSTAT64: auto fill only */
/* NODE_SYSCALL_FSTAT64: auto fill only */
/* NODE_SYSCALL_EPOLLWAIT: auto fill only */

static int f_sys_poll_x_common(struct event_filler_arguments *args)
{
    int64_t retval;
    int res;

    retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	res = poll_parse_fds(args, false);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_poll(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	int res;

	res = poll_parse_fds(args, true);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * timeout
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	res = poll_parse_fds(args, false);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_SELECT: auto fill only */

int f_sys_lseek(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * whence
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_llseek(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	unsigned long oh;
	unsigned long ol;
	uint64_t offset;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * offset
	 * We build it by combining the offset_high and offset_low system call arguments
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &oh);
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &ol);
	offset = (((uint64_t)oh) << 32) + ((uint64_t)ol);
	res = val_to_ring(args, offset, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * whence
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_GETCWD: auto fill only */
/* NODE_SYSCALL_CHDIR: auto fill only */
/* NODE_SYSCALL_FCHDIR: auto fill only */
/* NODE_SYSCALL_UNLINK: auto fill only */
/* NODE_SYSCALL_UNLINKAT: auto fill only */

#ifndef _64BIT_ARGS_SINGLE_REGISTER
int f_sys_pread(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long size;
	int res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * pos
	 */
#if defined CONFIG_X86
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);
#elif defined CONFIG_ARM && CONFIG_AEABI
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 5, 1, &pos1);
#else
 #error This architecture/abi not yet supported
#endif

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return f_sys_read(args);
}
#endif /* _64BIT_ARGS_SINGLE_REGISTER */

#ifndef _64BIT_ARGS_SINGLE_REGISTER
int f_sys_pwrite(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long size;
	int res;
#ifndef _64BIT_ARGS_SINGLE_REGISTER
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * pos
	 * NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	 * separate registers that we need to merge.
	 */
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;
#else
 #if defined CONFIG_X86
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);
 #elif defined CONFIG_ARM && CONFIG_AEABI
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 5, 1, &pos1);
 #else
  #error This architecture/abi not yet supported
 #endif

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;
#endif

	return f_sys_write(args);
}
#endif

int f_sys_readv_preadv(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	int res;
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * data and size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);


	
		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_writev_pwritev(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * data and size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);


	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

	
		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, args->snaplen, PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_writev(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);

	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, args->snaplen,
									  PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	

	if (unlikely(res != NOD_SUCCESS))
		return res;

	return f_sys_writev_pwritev(args);
}

#ifndef _64BIT_ARGS_SINGLE_REGISTER
int f_sys_preadv(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * pos
	 */

	/*
	 * Note that in preadv and pwritev have NO 64-bit arguments in the
	 * syscall (despite having one in the userspace API), so no alignment
	 * requirements apply here. For an overly-detailed discussion about
	 * this, see https://lwn.net/Articles/311630/
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return f_sys_readv_preadv(args);
}
#endif /* _64BIT_ARGS_SINGLE_REGISTER */

int f_sys_pwritev(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
#ifndef _64BIT_ARGS_SINGLE_REGISTER
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);

	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, args->snaplen,
									  PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * pos
	 * NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	 * separate registers that we need to merge.
	 */
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;
#else
	/*
	 * Note that in preadv and pwritev have NO 64-bit arguments in the
	 * syscall (despite having one in the userspace API), so no alignment
	 * requirements apply here. For an overly-detailed discussion about
	 * this, see https://lwn.net/Articles/311630/
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;
#endif

	return f_sys_writev_pwritev(args);
}

/* NODE_SYSCALL_DUP: auto fill only */
/* NODE_SYSCALL_SIGNALFD: auto fill only */
/* NODE_SYSCALL_KILL: auto fill only */
/* NODE_SYSCALL_TKILL: auto fill only */
/* NODE_SYSCALL_TGKILL: auto fill only */

int f_sys_nanosleep(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = timespec_parse(args, val);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_TIERFD_CREATE: auto fill only */
/* NODE_SYSCALL_INOTIFY_INIT: auto fill only */

int f_sys_getrlimit_setrlrimit(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl;
	int64_t cur;
	int64_t max;

    u8 nod_resource;

	/*
	 * resource
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	nod_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)nod_resource, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0 || args->event_type == NODE_SYSCALL_SETRLIMIT) {
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);


			if (unlikely(nod_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit))))
				return NOD_FAILURE_INVALID_USER_MEMORY;
			cur = rl.rlim_cur;
			max = rl.rlim_max;

	} else {
		cur = -1;
		max = -1;
	}

	/*
	 * cur
	 */
	res = val_to_ring(args, cur, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * max
	 */
	res = val_to_ring(args, max, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_prlimit(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl;
	int64_t newcur;
	int64_t newmax;
	int64_t oldcur;
	int64_t oldmax;

    u8 nod_resource;

	/*
	 * pid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * resource
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

	nod_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)nod_resource, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0) {
		syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);


			if (unlikely(nod_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
				newcur = -1;
				newmax = -1;
			} else {
				newcur = rl.rlim_cur;
				newmax = rl.rlim_max;
			}
	} else {
		newcur = -1;
		newmax = -1;
	}

	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);


		if (unlikely(nod_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
			oldcur = -1;
			oldmax = -1;
		} else {
			oldcur = rl.rlim_cur;
			oldmax = rl.rlim_max;
		}

	/*
	 * newcur
	 */
	res = val_to_ring(args, newcur, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newmax
	 */
	res = val_to_ring(args, newmax, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * oldcur
	 */
	res = val_to_ring(args, oldcur, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * oldmax
	 */
	res = val_to_ring(args, oldmax, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_fcntl(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, fcntl_cmd_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_mmap(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * length
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * prot
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, mmap_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * offset/pgoffset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 5, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_brk_munmap_mmap(struct event_filler_arguments *args)
{
	int64_t retval;
	int res = 0;
	struct mm_struct *mm = current->mm;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;

    if (args->event_type == NODE_SYSCALL_MMAP ||
        args->event_type == NODE_SYSCALL_MMAP2) {
        res = f_sys_mmap(args);
        if (unlikely(res != NOD_SUCCESS))
            return res;
    }

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = nod_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = nod_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_SPLICE: auto fill only */

int f_sys_ptrace(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	int res;
    u16 request;

	/*
	 * request
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, ptrace_requests_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * pid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	if (retval < 0) {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		return NOD_SUCCESS;
	}

	/*
	 * request
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	request = ptrace_requests_to_scap(val);

	res = parse_ptrace_addr(args, request);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	res = parse_ptrace_data(args, request);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_IOCTL_3: auto fill only */
/* NODE_SYSCALL_RENAME: auto fill only */

int f_sys_renameat(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * olddirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_SYMLINK: auto fill only */

int f_sys_symlinkat(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_sendfile(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	off_t offset;

    /*
	 * out_fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * in_fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if (val != 0) {

			res = nod_copy_from_user(&offset, (void *)val, sizeof(off_t));

		if (unlikely(res))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if (val != 0) {

			res = nod_copy_from_user(&offset, (void *)val, sizeof(off_t));

		if (unlikely(res))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_quotactl(struct event_filler_arguments *args)
{
	unsigned long val, len;
	int res;
	int64_t retval;
	uint8_t quota_fmt;
    uint32_t id;
	uint16_t cmd;
	struct if_dqblk dqblk;
	struct if_dqinfo dqinfo;
	uint32_t quota_fmt_out;

	const char empty_string[] = "";

    /*
	 * extract cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	cmd = quotactl_cmd_to_scap(val);
	res = val_to_ring(args, cmd, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * extract type
	 */
	res = val_to_ring(args, quotactl_type_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 *  extract id
	 */
	id = 0;
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	if ((cmd == NOD_Q_GETQUOTA) ||
		 (cmd == NOD_Q_SETQUOTA) ||
		 (cmd == NOD_Q_XGETQUOTA) ||
		 (cmd == NOD_Q_XSETQLIM)) {
		/*
		 * in this case id represent an userid or groupid so add it
		 */
		id = val;
	}
	res = val_to_ring(args, id, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * extract quota_fmt from id
	 */
	quota_fmt = NOD_QFMT_NOT_USED;
	if (cmd == NOD_Q_QUOTAON)
		quota_fmt = quotactl_fmt_to_scap(val);

	res = val_to_ring(args, quota_fmt, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * extract cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	cmd = quotactl_cmd_to_scap(val);

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Add special
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * get addr
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);

	/*
	 * get quotafilepath only for QUOTAON
	 */
	if (cmd == NOD_Q_QUOTAON)
		res = val_to_ring(args, val, 0, true, 0);
	else
		res = val_to_ring(args, (unsigned long)empty_string, 0, false, 0);

	if (unlikely(res != NOD_SUCCESS))
		return res;


	/*
	 * dqblk fields if present
	 */
	dqblk.dqb_valid = 0;
	if ((cmd == NOD_Q_GETQUOTA) || (cmd == NOD_Q_SETQUOTA)) {
		len = nod_copy_from_user(&dqblk, (void *)val, sizeof(struct if_dqblk));
		if (unlikely(len != 0))
			return NOD_FAILURE_INVALID_USER_MEMORY;
	}
	if (dqblk.dqb_valid & QIF_BLIMITS) {
		res = val_to_ring(args, dqblk.dqb_bhardlimit, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
		res = val_to_ring(args, dqblk.dqb_bsoftlimit, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_SPACE) {
		res = val_to_ring(args, dqblk.dqb_curspace, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_ILIMITS) {
		res = val_to_ring(args, dqblk.dqb_ihardlimit, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
		res = val_to_ring(args, dqblk.dqb_isoftlimit, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_BTIME) {
		res = val_to_ring(args, dqblk.dqb_btime, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_ITIME) {
		res = val_to_ring(args, dqblk.dqb_itime, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	/*
	 * dqinfo fields if present
	 */
	dqinfo.dqi_valid = 0;
	if ((cmd == NOD_Q_GETINFO) || (cmd == NOD_Q_SETINFO)) {
		len = nod_copy_from_user(&dqinfo, (void *)val, sizeof(struct if_dqinfo));
		if (unlikely(len != 0))
			return NOD_FAILURE_INVALID_USER_MEMORY;
	}

	if (dqinfo.dqi_valid & IIF_BGRACE) {
		res = val_to_ring(args, dqinfo.dqi_bgrace, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	if (dqinfo.dqi_valid & IIF_IGRACE) {
		res = val_to_ring(args, dqinfo.dqi_igrace, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	if (dqinfo.dqi_valid & IIF_FLAGS) {
		res = val_to_ring(args, dqinfo.dqi_flags, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != NOD_SUCCESS))
			return res;
	}

	quota_fmt_out = NOD_QFMT_NOT_USED;
	if (cmd == NOD_Q_GETFMT) {
		len = nod_copy_from_user(&quota_fmt_out, (void *)val, sizeof(uint32_t));
		if (unlikely(len != 0))
			return NOD_FAILURE_INVALID_USER_MEMORY;
		quota_fmt_out = quotactl_fmt_to_scap(quota_fmt_out);
	}
	res = val_to_ring(args, quota_fmt_out, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_SETRESUID: auto fill only */
/* NODE_SYSCALL_SETRESGID: auto fill only */
/* NODE_SYSCALL_SETUID: auto fill only */
/* NODE_SYSCALL_SETGID: auto fill only */
/* NODE_SYSCALL_GETUID: auto fill only */
/* NODE_SYSCALL_GETEUID: auto fill only */
/* NODE_SYSCALL_GETRESUID: auto fill only */
/* NODE_SYSCALL_GETRESGID: auto fill only */

int f_sys_getresuid_and_gid(struct event_filler_arguments *args)
{
	int res;
	unsigned long val, len;
	uint32_t uid;
	int16_t retval;

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * ruid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

		len = nod_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * euid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	len = nod_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * suid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	len = nod_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_setns(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u32 flags;

	/*
	 * parse fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * get type, parse as clone flags as it's a subset of it
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	flags = clone_flags_to_scap(val);
	res = val_to_ring(args, flags, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_flock(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u32 flags;

	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	flags = flock_flags_to_scap(val);
	res = val_to_ring(args, flags, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

static int f_sys_accept_common(struct event_filler_arguments *args)
{
    int res;
    int fd;
    char *targetbuf = args->str_storage;
    u16 size = 0;
    syscall_arg_t queuepct = 0;
    syscall_arg_t ack_backlog = 0;
    syscall_arg_t max_ack_backlog = 0;
    syscall_arg_t srvskfd;
    int err = 0;
    struct socket *sock;

    /*
     * Push the fd
     */
    fd = syscall_get_return_value(current, args->regs);
    res = val_to_ring(args, (int64_t)fd, 0, false, 0);
    if (unlikely(res != NOD_SUCCESS))
        return res;

    /*
     * Convert the fd into socket endpoint information
     */
    size = fd_to_socktuple(fd,
            NULL,
            0,
            false,
            true,
            targetbuf,
            STR_STORAGE_SIZE);

    /*
     * Copy the endpoint info into the ring
     */
    res = val_to_ring(args,
                (uint64_t)targetbuf,
                size,
                false,
                0);
    if (unlikely(res != NOD_SUCCESS))
        return res;

    /*
     * queuepct
     */
    syscall_get_arguments_deprecated(current, args->regs, 0, 1, &srvskfd);
    sock = sockfd_lookup(srvskfd, &err);

    if (sock && sock->sk) {
        ack_backlog = sock->sk->sk_ack_backlog;
        max_ack_backlog = sock->sk->sk_max_ack_backlog;
    }

    if (sock)
        sockfd_put(sock);

    if (max_ack_backlog)
        queuepct = (unsigned long)ack_backlog * 100 / max_ack_backlog;

    res = val_to_ring(args, queuepct, 0, false, 0);
    if (res != NOD_SUCCESS)
        return res;

    res = val_to_ring(args, ack_backlog, 0, false, 0);
    if (res != NOD_SUCCESS)
        return res;

    res = val_to_ring(args, max_ack_backlog, 0, false, 0);
    if (res != NOD_SUCCESS)
        return res;

    return NOD_SUCCESS;
}

int f_sys_accept(struct event_filler_arguments *args)
{
    return f_sys_accept_common(args);	
}

int f_sys_accept4(struct event_filler_arguments *args) {
    int res;

    res = val_to_ring(args, 0, 0, false, 0);
    if (unlikely(res != NOD_SUCCESS))
        return res;

    return f_sys_accept_common(args);
}

int f_sys_semop(struct event_filler_arguments *args)
{
	unsigned long nsops;
	int res;
	int64_t retval;
	struct sembuf *ptr;

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * nsops
	 * actually this could be read in the enter function but
	 * we also need to know the value to access the sembuf structs
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &nsops);
	res = val_to_ring(args, nsops, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * sembuf
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, (unsigned long *) &ptr);

	if (nsops && ptr) {
		/* max length of sembuf array in g_event_info = 2 */
		const unsigned max_nsops = 2;
		unsigned       j;

		for (j = 0; j < max_nsops; j++) {
			struct sembuf sops = {0, 0, 0};

			if (nsops--)
				if (unlikely(nod_copy_from_user(&sops, (void *)&ptr[j], sizeof(struct sembuf))))
					return NOD_FAILURE_INVALID_USER_MEMORY;

			res = val_to_ring(args, sops.sem_num, 0, true, 0);
			if (unlikely(res != NOD_SUCCESS))
				return res;

			res = val_to_ring(args, sops.sem_op, 0, true, 0);
			if (unlikely(res != NOD_SUCCESS))
				return res;

			res = val_to_ring(args, semop_flags_to_scap(sops.sem_flg), 0, true, 0);
			if (unlikely(res != NOD_SUCCESS))
				return res;
		}
	}

	return NOD_SUCCESS;
}

int f_sys_semctl(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * semid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * semnum
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, semctl_cmd_to_scap(val), 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * optional argument semun/val
	 */
	if (val == SETVAL)
		syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	else
		val = 0;
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_ppoll(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	res = poll_parse_fds(args, true);
	if (res != NOD_SUCCESS)
		return res;

	/*
	 * timeout
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	/* NULL timeout specified as 0xFFFFFF.... */
	if (val == (unsigned long)NULL)
		res = val_to_ring(args, (uint64_t)(-1), 0, false, 0);
	else
		res = timespec_parse(args, val);
	if (res != NOD_SUCCESS)
		return res;

	/*
	 * sigmask
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	if (val != (unsigned long)NULL)
		if (0 != nod_copy_from_user(&val, (void __user *)val, sizeof(val)))
			return NOD_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, val, 0, false, 0);
	if (res != NOD_SUCCESS)
		return res;

	return f_sys_poll_x_common(args);
}

int f_sys_mount(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * Fix mount flags in arg 3.
	 * See http://lxr.free-electrons.com/source/fs/namespace.c?v=4.2#L2650
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	if ((val & NOD_MS_MGC_MSK) == NOD_MS_MGC_VAL)
		val &= ~NOD_MS_MGC_MSK;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_UMOUNT: auto fill only */

int f_sys_semget(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * key
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * nsems
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * semflg
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, semget_flags_to_scap(val), 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_access(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, access_flags_to_scap(val), 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_CHROOT: auto fill only */
/* NODE_SYSCALL_SETSID: auto fill only */
/* NODE_SYSCALL_SETPGID: auto fill only */
/* NODE_SYSCALL_MKDIR_2: auto fill only */
/* NODE_SYSCALL_RMDIR_2: auto fill only */

int f_sys_unshare(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u32 flags;

	/*
	 * get type, parse as clone flags as it's a subset of it
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	flags = clone_flags_to_scap(val);
	res = val_to_ring(args, flags, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_bpf(struct event_filler_arguments *args)
{
	int64_t retval;
	unsigned long cmd;
	int res;

	/*
	 * res, if failure or depending on cmd
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	if (retval < 0) {
		res = val_to_ring(args, retval, 0, false, NOD_BPF_IDX_RES);
		if (unlikely(res != NOD_SUCCESS))
			return res;

		return NOD_SUCCESS;
	}
	/*
	 * fd, depending on cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &cmd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	if(cmd == BPF_MAP_CREATE || cmd == BPF_PROG_LOAD)
#else
	if(0)
#endif
	{
		res = val_to_ring(args, retval, 0, false, NOD_BPF_IDX_FD);
	}
	else
	{
		res = val_to_ring(args, retval, 0, false, NOD_BPF_IDX_RES);
	}
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_SECCOMP: auto fill only */
/* NODE_SYSCALL_UNLINK: auto fill only */

int f_sys_unlinkat(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * flags
	 * Note that we convert them into the nod portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, unlinkat_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_mkdirat(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * path
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_openat(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long flags;
	unsigned long modes;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the nod portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &flags);
	res = val_to_ring(args, open_flags_to_scap(flags), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dev
	 */
	res = val_to_ring(args, get_fd_dev(retval), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_LINK_2: auto fill only */

int f_sys_linkat(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long flags;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * olddir
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newdir
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the nod portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &flags);
	res = val_to_ring(args, linkat_flags_to_scap(flags), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_fchmodat(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * filename
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_chmod(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * filename
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_fchmod(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_renameat2(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * olddirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;


	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

/* NODE_SYSCALL_USERFAULTFD: auto fill only */

int f_sys_openat2(struct event_filler_arguments *args)
{
	unsigned long resolve;
	unsigned long flags;
	unsigned long val;
	unsigned long mode;
	int res;
	int64_t retval;
#ifdef __NR_openat2
	struct open_how how;
#endif

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = NOD_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;
	

#ifdef __NR_openat2
	/*
	 * how: we get the data structure, and put its fields in the buffer one by one
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = nod_copy_from_user(&how, (void *)val, sizeof(struct open_how));
	if (unlikely(res != 0))
		return NOD_FAILURE_INVALID_USER_MEMORY;

	flags = open_flags_to_scap(how.flags);
	mode = open_modes_to_scap(how.flags, how.mode);
	resolve = openat2_resolve_to_scap(how.resolve);
#else
	flags = 0;
	mode = 0;
	resolve = 0;
#endif
	/*
	 * flags (extracted from open_how structure)
	 * Note that we convert them into the nod portable representation before pushing them to the ring
	 */
	res = val_to_ring(args, flags, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * mode (extracted from open_how structure)
	 * Note that we convert them into the nod portable representation before pushing them to the ring
	 */
	res = val_to_ring(args, mode, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * resolve (extracted from open_how structure)
	 * Note that we convert them into the nod portable representation before pushing them to the ring
	 */
	res = val_to_ring(args, resolve, 0, true, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_mprotect(struct event_filler_arguments *args)
{
	unsigned long val;
    int64_t retval;
	int res;

	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * length
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	 * prot
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

    retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}

int f_sys_copy_file_range(struct event_filler_arguments *args)
{
	unsigned long fdin;
	unsigned long fdout;
	unsigned long offin;
	unsigned long offout;
	int64_t retval;
	unsigned long len;
	int res;

	/*
	* fdin
	*/
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &fdin);
	res = val_to_ring(args, fdin, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	* offin
	*/
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &offin);
	res = val_to_ring(args, offin, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	* len
	*/
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &len);
	res = val_to_ring(args, len, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;
	
    retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	* fdout
	*/
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &fdout);
	res = val_to_ring(args, fdout, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	/*
	* offout
	*/
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &offout);
	res = val_to_ring(args, offout, 0, false, 0);
	if (unlikely(res != NOD_SUCCESS))
		return res;

	return NOD_SUCCESS;
}
