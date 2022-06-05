MODULE := nodrop

all: monitor module test ctrl gui

.PHONY: module clean load gui monitor test ctrl
clean:
	rm -f $(MODULE).ko $(MODULE)-ctl
	make -C src clean
	make -C gui/ clean
	make -C monitor/ clean
	make -C StressTesting/ clean

load: monitor module
	sudo rm -rf /tmp/$(MODULE); mkdir /tmp/$(MODULE)
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	sudo insmod $(MODULE).ko

gui:
	make -C gui/

module:
	make -C src MODULE=$(MODULE)
	mv src/$(MODULE).ko .

monitor:
	make -C monitor/ CFLAGS="-Ofast"

test:
	make -C StressTesting/

ctrl: $(MODULE)-ctl.c include/ioctl.h
	$(CC) $(MODULE)-ctl.c -o $(MODULE)-ctl