# Quick Start

## 安装依赖

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
* To get lua, run the following command
```shell
 ./scripts/getlua.sh
```

## 编译和启动
```shell
mkdir build && cd build
cmake ..
make load
make ctrl
./scripts/ctrl/ctrl start ../scripts/lua/test.lua 
```

其中 ctrl 是用于控制 nodrop 的命令行工具，使用 `start <lua_path>` 启用对应的 lua 脚本。

## lua 脚本编写
lua脚本中需要包含两个函数，分别是 `on_event` 和 `on_init`。

在访问某一个字段时，需要先通过 `chisel.request_field("<field_name>")` 来获取句柄，之后通过 `evt.filed(<handle>)` 来访问事件相关字段。

目前支持的字段有：`evt.time`, `evt.type`, `evt.tid`, `evt.arg.<arg_name>`。

其中在访问 `evt.arg.<arg_name>` 需要保证该事件有对应名字的参数。

下面的 lua 脚本示范了抓取 `write` 系统调用的 fd 和 size 参数，并将其保存到文件 `/tmp/nodrop_hello_args.log`。

```lua
local outfile = "/tmp/nodrop_hello_args.log"
local f = io.open(outfile, "w")

if not f then
    print("ERROR: cannot open log file:", outfile)
    return
end

function on_init()
    ftype  = chisel.request_field("evt.type")
    ffd    = chisel.request_field("evt.arg.fd")
    fcount = chisel.request_field("evt.arg.count")

    f:write("=== hello world arg test ===\n")
    f:flush()
    return true
end

function on_event()
    local t = evt.field(ftype)
    if t == "write" then
        local fd    = evt.field(ffd)
        local count = evt.field(fcount)

        f:write(string.format(
            "write(fd=%s, count=%s)\n",
            tostring(fd),
            tostring(count)
        ))
        f:flush()
    end

    return true
end
```

## 测试
如果仅为了测试，可以修改 nodrop.h 中 `NOD_TEST(task)` 宏，将对应的名字修改为进程名。

```shell
make helloworld
./scripts/tests/helloworld
cat /tmp/nodrop_hello_args.log
```

通过上面的命令可以测试 lua 脚本输出 write 系统调用的信息。
