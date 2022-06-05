# NoDrop

### How to build

NoDrop contains 2 major components: the kernel module and the monitor. All codes under `src/` is the kernel module and all codes under `monitor` is the monitor.

NoDrop is tested on Ubuntu 18.04 with unmodified Linux kernel 4.15.0-171. 

Before building NoDrop, make sure that `gcc` has been installed on your machine. To build kernel module and monitor, just run (privilege is not required)

```shell
make
make load
```

Then the kernel module is loaded. You can find the kernel module file called `nodrop.ko` in project root directory.

### Configuration

##### Size of logging buffer

In NoDrop, each core has one independent logging buffer with 8MB by default. The buffer size is configured by macro `BUFFER_SIZE` in `include/events.h`

##### Path of storing event logs

All event logs are located in `/tmp/nodrop` by default. You can adjust this path by modifying `PATH_FMT` in `monitor/main.c`.