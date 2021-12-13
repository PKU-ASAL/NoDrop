KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
EXTRA_CFLAGS += -I$(src)/include

MODULE := pinject
obj-m  += $(MODULE).o
$(MODULE)-objs := \
	pinject_main.o \
	loader.o \
	hock.o \
	# kprobe.o \

all:
	make -C $(KDIR) M=$(PWD) modules
.PHONY: clean load
clean:
	make -C $(KDIR) M=$(PWD) clean
load: all
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	sudo insmod $(MODULE).ko
