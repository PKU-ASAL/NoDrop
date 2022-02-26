#ifndef SPR_IOCTL_H_
#define SPR_IOCTL_H_


#define SPR_IOCTL_NAME "pinject"
#define SPR_IOCTL_PATH "/proc/"SPR_IOCTL_NAME

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif //__KERNEL__

#define SPR_IOCTL_MAGIC 's'
#define SPR_IOCTL_CLEAR_BUFFER                  _IO(SPR_IOCTL_MAGIC, 0)
#define SPR_IOCTL_READ_BUFFER_COUNT             _IO(SPR_IOCTL_MAGIC, 1)
#define SPR_IOCTL_STOP_RECORDING                _IO(SPR_IOCTL_MAGIC, 2)
#define SPR_IOCTL_START_RECORDING               _IO(SPR_IOCTL_MAGIC, 3)
#define SPR_IOCTL_EXIT_MONITOR                  _IO(SPR_IOCTL_MAGIC, 4)

#endif //SPR_IOCTL_H_