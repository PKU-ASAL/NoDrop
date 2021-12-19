KDIR := /lib/modules/$(shell uname -r)/build
KDIR-debug := /mnt/hgfs/Projects/kernel-dbg/linux-5.4
PWD  := $(shell pwd)
EXTRA_CFLAGS += -I$(src)/include

MODULE := pinject
obj-m  += $(MODULE).o
$(MODULE)-objs := \
	pinject_main.o \
	loader.o \
	hook.o \
	# kprobe.o \

all:
	make -C $(KDIR) M=$(PWD) modules
.PHONY: clean load debug
clean:
	make -C $(KDIR) M=$(PWD) clean
load: all
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	sudo insmod $(MODULE).ko

debug:
	make -C $(KDIR-debug) M=$(PWD) modules
	cp pinject.ko $(PWD)/../kernel-dbg/busybox-1.34.0/initramfs/
	cd $(PWD)/../kernel-dbg/busybox-1.34.0/initramfs/; find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
