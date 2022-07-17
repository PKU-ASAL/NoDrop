# NoDrop

## How to build

NoDrop contains 2 major components: the kernel module and the monitor. All codes under `src/` is the kernel module and all codes under `monitor` is the monitor.

NoDrop is tested on Ubuntu 18.04 with unmodified Linux kernel 4.15.0-171. 

Before building NoDrop, make sure that `gcc` has been installed on your machine. To build kernel module and monitor, just run (privilege is not required)

```shell
mkdir build && cd build
cmake ..
make load
```

Then the kernel module is loaded. You can find the kernel module file called `nodrop.ko` in project root directory.

## Configuration

In NoDrop, there are 3 variables can be configured with cmake.

- `BUFFER_SIZE`: the size of each per-thread buffer (default value: 8MB)
- `MONITOR_PATH`: the path to find monitor executable (default value: `${PROJECT_BINARY_PATH}/monitor/monitor`)
- `STORE_PATH`: the pare that store the event data (default value: `/tmp/nodrop`)

When you generate cmake files, you can specify these variables. For example, if you want to set that buffer size is 4MB, monitor path is `/my/path/to/monitor` and store path is `/my/path/to/store`, you can run the following commands

```
cmake .. -DBUFFER_SIZE=4*Mib -DMONITOR_PATH=/my/path/to/monitor -DSTORE_PATH=/my/path/to/store
```

For buffer size, you can specify it with integer or using unit including Kib and Mib. For the above exmaple, you can also sepcify the buffer size using `-DBUFFER_SIZE=4096*1024`.

NoDrop also supports customed log path format. In default, the log path format in C-like is `STORE_PATH/%u-%ld.buf`, which accepts two arguments including thread id and ns-scale timestamp. This log path format can also be configured with CMake by defining a macro. For example, if you would like to specify the log path format to a tty device, the following commands will achieve this.

```
cmake .. -DPATH_FORMAT=/dev/pts/1
```

### Pkey Support

NoDrop utilizes Intel Protection Key (PKEY) to protect its memory. If your machine does not support pkey, you must disable it otherwise a SIGILL will triggered due to the illegel instruction used by pkey.

This option is enabled on default. To disable the pkey, you can instruct CMake with `-DPKEY_SUPPORT=off`.