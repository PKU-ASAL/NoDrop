MODULE := nodrop

all: mkfig monitor modules test ctrl

.PHONY: modules clean load mkfig monitor test ctrl
clean:
	rm -f $(MODULE).ko sprctl
	make -C src clean
	make -C mkfig/ clean
	make -C monitor/ clean
	make -C StressTesting/ clean

load: modules monitor
	sudo rm -rf /tmp/nodrop; mkdir /tmp/nodrop
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	sudo insmod $(MODULE).ko

mkfig:
	make -C mkfig/

modules:
	make -C src MODULE=$(MODULE)
	mv src/$(MODULE).ko .

monitor:
	make -C monitor/

test:
	make -C StressTesting/

ctrl: nodrop-ctl.c include/ioctl.h
	$(CC) nodrop-ctl.c -o nodrop-ctl