KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m  += $(MODULE).o
$(MODULE)-objs := \
	nod_main.o \
	loader.o \
	trace.o \
	proc.o \
	procinfo.o \
	fillers.o \
	events.o \
	privil.o \
	elf.o \
	events_table.o \
	fillers_table.o \
	flags_table.o \
	syscall_table.o \
	dynamic_params_table.o \

ccflags-y += -I$(src) -I$(src)/../include

all:
	make -C $(KDIR) M=$(PWD) modules

.PHONY: clean
clean:
	make -C $(KDIR) M=$(PWD) clean
