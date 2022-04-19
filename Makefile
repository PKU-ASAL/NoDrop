MODULE := nodrop

all: monitor module test ctrl mkfig

.PHONY: module clean load mkfig monitor test ctrl
clean:
	rm -f $(MODULE).ko $(MODULE)-ctl
	make -C src clean
	make -C mkfig/ clean
	make -C monitor/ clean
	make -C StressTesting/ clean

load: monitor module
	sudo rm -rf /tmp/$(MODULE); mkdir /tmp/$(MODULE)
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	sudo insmod $(MODULE).ko

mkfig:
	make -C mkfig/

module:
	make -C src MODULE=$(MODULE)
	mv src/$(MODULE).ko .

monitor:
	make -C monitor/ CFLAGS="-Ofast"

test:
	make -C StressTesting/

ctrl: $(MODULE)-ctl.c include/ioctl.h
	$(CC) $(MODULE)-ctl.c -o $(MODULE)-ctl