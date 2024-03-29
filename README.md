# Auditing Frameworks Need Resource Isolation: A Systematic Study on the Super Producer Threat to System Auditing and Its Mitigation
Prototype source code for the NODROP research paper, presented at USENIX Security 2023. This paper is available at https://www.usenix.org/conference/usenixsecurity23/presentation/jiang-peng. If you find this repository useful, please cite our paper/repository.

We evaluated the event dropping, application performance slowdown and the running overhead of NODROP under different hardware configurations. Due to space limitations of the paper, we have included some results in **Appendix.pdf** in this GitHub repository as mentioned in our paper. 

## Overview
Nodrop is a provenance collector which addresses the “data integrity vs. efficiency dilemma” without introducing significant extra overhead. It efficiently isolates resources for provenance data handling by enforcing processes to consume their own resource quota to handle the provenance data generated by themselves. NoDrop is inspired by the idea of threadlet. Instead of having independent threads to process system call events, NoDrop leverages the capability of other running threads. It dynamically instruments the processing logic to the memory of a running thread.

## Getting Started
NoDrop contains 2 major components: the kernel module and the monitor. 
* **the kernel module**: codes under `kmodule/`. Nodrop-modules builds against a vanilla or distribution kernel, with no need for additional patches.
* **the monitor**: codes under `monitor/`. 
NoDrop is tested on Ubuntu 18.04 with unmodified Linux kernel 4.15.0-171.

### How to Install Nodrop 
#### Environment requirements
* make
* CMake
* GCC/G++ > 8.0 (Linux) which supports '--static-pie' option 
* pkg-config binary
* For Linux, the following kernel options must be enabled (usually they are, unless a custom built kernel is used):
    *  `CONFIG_TRACEPOINTS`
    *  `CONFIG_HAVE_SYSCALL_TRACEPOINTS`
 * To get musl libc, just run the following command
```shell
 ./scripts/getmusl.sh <absolute-path-to-Nodrop>
```

#### Installation Instructions
```shell
mkdir build && cd build
cmake ..
make load
```
Then the kernel module is loaded. You can find the kernel module file called `nodrop.ko` in project root directory.

### Configuration
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
