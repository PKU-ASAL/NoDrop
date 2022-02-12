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
#ifdef CONFIG_CGROUPS
#include <linux/cgroup.h>
#endif
#include <asm/syscall.h>

#include "pinject.h"
#include "include/common.h"
#include "include/events.h"
#include "include/fillers.h"
#include "include/flags.h"

/*
 * The kernel patched with grsecurity makes the default access_ok trigger a
 * might_sleep(), so if present we use the one defined by them
 */
#ifdef access_ok_noprefault
#define spr_access_ok access_ok_noprefault
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0))
#define spr_access_ok(type, addr, size)	access_ok(addr, size)
#else
#define spr_access_ok(type, addr, size)	access_ok(type, addr, size)
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

static void memory_dump(char *p, size_t size)
{
	unsigned int j;

	for (j = 0; j < size; j += 8)
		pr_info("%*ph\n", 8, &p[j]);
}

/*
 * What this function does is basically a special memcpy
 * so that, if the page fault handler detects the address is invalid,
 * won't kill the process but will return a positive number
 * Plus, this doesn't sleep.
 * The risk is that if the buffer is partially paged out, we get an error.
 * Returns the number of bytes NOT read.
 */
unsigned long spr_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;

	pagefault_disable();

	if (likely(spr_access_ok(VERIFY_READ, from, n)))
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
long spr_strncpy_from_user(char *to, const char __user *from, unsigned long n)
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

		if (!spr_access_ok(VERIFY_READ, from, bytes_to_read)) {
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

static inline uint32_t get_fd_dev(int64_t fd)
{
#ifdef UDIG
	return 0;
#else
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
#endif /* UDIG */
}

int resolve_arguments(struct event_filler_arguments *args, uint64_t val, u32 val_len, bool fromuser, u8 dyn_idx)
{
	const struct spr_param_info *param_info;
	int len = -1;
	u16 *psize = (u16 *)(args->buf_ptr + args->curarg * sizeof(u16));
	u32 max_arg_size = args->arg_data_size;

	if (unlikely(args->curarg >= args->nargs)) {
		pr_err("(%u)resolve_arguments: too many arguments for event #%llu, type=%u, curarg=%u, nargs=%u tid:%u\n",
			smp_processor_id(),
			args->nevents,
			(u32)args->event_type,
			args->curarg,
			args->nargs,
			current->pid);
		memory_dump(args->buf_ptr - sizeof(struct spr_event_hdr), 32);
		return SPR_FAILURE_BUG;
	}

	if (unlikely(args->arg_data_size == 0))
		return SPR_FAILURE_BUFFER_FULL;

	if (max_arg_size > SPR_MAX_ARG_SIZE)
		max_arg_size = SPR_MAX_ARG_SIZE;

	param_info = &(g_event_info[args->event_type].params[args->curarg]);
	if (param_info->type == PT_DYN && param_info->info != NULL) {
		const struct spr_param_info *dyn_params;

		if (unlikely(dyn_idx >= param_info->ninfo)) {
			return SPR_FAILURE_BUG;
		}

		dyn_params = (const struct spr_param_info *)param_info->info;

		param_info = &dyn_params[dyn_idx];
		if (likely(max_arg_size >= sizeof(u8)))	{
			*(u8 *)(args->buf_ptr + args->arg_data_offset) = dyn_idx;
			len = sizeof(u8);
		} else {
			return SPR_FAILURE_BUFFER_FULL;
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
				len = spr_strncpy_from_user(args->buf_ptr + args->arg_data_offset,
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

			/*
			 * Make sure the string is null-terminated
			 */
			*(char *)(args->buf_ptr + args->arg_data_offset + len) = 0;
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
					return SPR_FAILURE_BUFFER_FULL;

				len = (int)spr_copy_from_user(args->buf_ptr + args->arg_data_offset,
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
						len = (int)spr_copy_from_user(args->buf_ptr + args->arg_data_offset + dpi_lookahead_size,
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
					return SPR_FAILURE_BUFFER_FULL;

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
				return SPR_FAILURE_BUFFER_FULL;

			if (fromuser) {
				len = (int)spr_copy_from_user(args->buf_ptr + args->arg_data_offset,
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
			return SPR_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_SYSCALLID:
		if (likely(max_arg_size >= sizeof(u16))) {
			*(u16 *)(args->buf_ptr + args->arg_data_offset) = (u16)val;
			len = sizeof(u16);
		} else {
			return SPR_FAILURE_BUFFER_FULL;
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
			return SPR_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_UINT64:
		if (likely(max_arg_size >= sizeof(u64))) {
			*(u64 *)(args->buf_ptr + args->arg_data_offset) = (u64)val;
			len = sizeof(u64);
		} else {
			return SPR_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT8:
		if (likely(max_arg_size >= sizeof(s8))) {
			*(s8 *)(args->buf_ptr + args->arg_data_offset) = (s8)(long)val;
			len = sizeof(s8);
		} else {
			return SPR_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT16:
		if (likely(max_arg_size >= sizeof(s16))) {
			*(s16 *)(args->buf_ptr + args->arg_data_offset) = (s16)(long)val;
			len = sizeof(s16);
		} else {
			return SPR_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT32:
		if (likely(max_arg_size >= sizeof(s32))) {
			*(s32 *)(args->buf_ptr + args->arg_data_offset) = (s32)(long)val;
			len = sizeof(s32);
		} else {
			return SPR_FAILURE_BUFFER_FULL;
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
			return SPR_FAILURE_BUFFER_FULL;
		}

		break;
	default:
		pr_err("resolve_arguments: invalid argument type %d. Event %u (%s) might have less parameters than what has been declared in nargs\n",
			(int)g_event_info[args->event_type].params[args->curarg].type,
			(u32)args->event_type,
			g_event_info[args->event_type].name);
		return SPR_FAILURE_BUG;
	}

	ASSERT(len <= SPR_MAX_ARG_SIZE);
	ASSERT(len <= (int)max_arg_size);

	*psize += (u16)len;
	args->curarg++;
	args->arg_data_offset += len;
	args->arg_data_size -= len;

	return SPR_SUCCESS;
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
	retval = (int64_t)syscall_get_return_value(current, args->reg);
	res = resolve_arguments(args, retval, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;


	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->reg, 0, 1, &val);
	res = resolve_arguments(args, val, 0, true, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->reg, 1, 1, &flags);
	res = resolve_arguments(args, open_flags_to_scap(flags), 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(current, args->reg, 2, 1, &modes);
	res = resolve_arguments(args, open_modes_to_scap(flags, modes), 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	/*
	 * dev
	 */
	res = resolve_arguments(args, get_fd_dev(retval), 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	return SPR_SUCCESS;
}

int f_sys_read(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments_deprecated(current, args->reg, 0, 1, &val);
	res = resolve_arguments(args, val, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->reg, 2, 1, &val);
	res = resolve_arguments(args, val, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->reg);
	res = resolve_arguments(args, retval, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
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
		syscall_get_arguments_deprecated(current, args->reg, 1, 1, &val);

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	/*
	 * Copy the buffer
	 */
	res = resolve_arguments(args, val, bufsize, true, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	return SPR_SUCCESS;
}

int f_sys_write(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * FD
	 */
	syscall_get_arguments_deprecated(current, args->reg, 0, 1, &val);
	res = resolve_arguments(args, val, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	/*
	 * data size
	 */
	syscall_get_arguments_deprecated(current, args->reg, 2, 1, &val);
	bufsize = val;
	res = resolve_arguments(args, val, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;
	
	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->reg);

	res = resolve_arguments(args, retval, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;


	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->reg, 1, 1, &val);
	res = resolve_arguments(args, val, bufsize, true, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;

	return SPR_SUCCESS;
}

int f_sys_exit(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	syscall_get_arguments_deprecated(current, args->reg, 0, 1, &val);
	res = resolve_arguments(args, val, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;
	
	return SPR_SUCCESS;
}

int f_sys_exit_group(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	syscall_get_arguments_deprecated(current, args->reg, 0, 1, &val);
	res = resolve_arguments(args, val, 0, false, 0);
	if (unlikely(res != SPR_SUCCESS))
		return res;
	
	return SPR_SUCCESS;
}