KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m  += $(MODULE).o
$(MODULE)-objs := \
	main.o \
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

ccflags-y += -I$(src) -I$(src)/../include

all:
	make -C $(KDIR) M=$(PWD) modules

.PHONY: clean
clean:
	make -C $(KDIR) M=$(PWD) clean
