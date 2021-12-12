KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

MODULE := pinject
obj-m  += $(MODULE).o
$(MODULE)-objs := \
	pinject_main.o \
	loader.o \
	kprobe.o \
	# hock.o \

all:
	make -C $(KDIR) M=$(PWD) modules
.PHONY: clean load
clean:
	make -C $(KDIR) M=$(PWD) clean
load: all
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	sudo insmod $(MODULE).ko
