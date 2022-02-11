#include <linux/kobject.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include <linux/unistd.h>

#include "include/events.h"
#include "pinject.h"



/*
 * SYSCALL TABLE
 */
const enum spr_event_type g_syscall_event_table[SYSCALL_TABLE_SIZE] = {
	[__NR_close - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_CLOSE,
	[__NR_read - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_READ,
	[__NR_write - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_WRITE,
    [__NR_open - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_OPEN,
    [__NR_exit - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXIT,
    [__NR_exit_group - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXIT_GROUP,
};

#endif /* CONFIG_IA32_EMULATION */
