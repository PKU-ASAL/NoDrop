KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

MODULE := pinject
obj-m  += $(MODULE).o
$(MODULE)-objs := \
	pinject_main.o \
	loader.o \
	hook.o \
	proc.o \
	fillers.o \
	events.o \
	privil.o \
	elf.o \
	events_table.o \
	fillers_table.o \
	flags_table.o \
	syscall_table.o \
	dynamic_params_table.o

ccflags-y += -I$(src) -I$(src)/include -I$(src)/include

all:
	make -C $(KDIR) M=$(PWD) modules

.PHONY: clean distclean load mkfig monitor test
clean:
	make -C $(KDIR) M=$(PWD) clean
	make -C mkfig/ clean
	make -C monitor/ clean
	make -C StressTesting/ clean

distclean:
	make -C $(KDIR) M=$(PWD) clean

load: all
	sudo rm -rf /tmp/pinject; mkdir /tmp/pinject
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	sudo insmod $(MODULE).ko

mkfig:
	make -C mkfig/

monitor:
	make -C monitor/

test:
	make -C StressTesting/