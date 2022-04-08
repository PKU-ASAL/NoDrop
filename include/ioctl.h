#ifndef NOD_IOCTL_H_
#define NOD_IOCTL_H_


#define NOD_IOCTL_NAME "nodrop"
#define NOD_IOCTL_PATH "/proc/"NOD_IOCTL_NAME

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif //__KERNEL__

#define NOD_IOCTL_MAGIC 's'
#define NOD_IOCTL_CLEAR_BUFFER                  _IO(NOD_IOCTL_MAGIC, 0)
#define NOD_IOCTL_FETCH_BUFFER                  _IO(NOD_IOCTL_MAGIC, 1)
#define NOD_IOCTL_READ_BUFFER_COUNT_INFO        _IO(NOD_IOCTL_MAGIC, 2)
#define NOD_IOCTL_STOP_RECORDING                _IO(NOD_IOCTL_MAGIC, 3)
#define NOD_IOCTL_START_RECORDING               _IO(NOD_IOCTL_MAGIC, 4)
#define NOD_IOCTL_RESTORE_SECURITY              _IO(NOD_IOCTL_MAGIC, 5)

struct buffer_count_info {
	uint64_t event_count;
	uint64_t unflushed_count;
	uint64_t unflushed_len;
};

struct fetch_buffer_struct {
	uint64_t len;
	char *buf;
};

#endif //NOD_IOCTL_H_