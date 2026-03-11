# Quick Start

# 安装依赖

```shell
# make cmake pkg-config GCC/G++ 
sudo apt install -y build-essential cmake pkg-config
# musl lua zlib
./scripts/getmusl.sh <absolute-path-to-Nodrop>
./scripts/getlua.sh
./scripts/getzlib.sh
```

需要确认 GCC/G++ version > 8.0。

## 编译和启动

```shell
mkdir build && cd build
cmake ..
make load
make ctrl
```

如果不支持PKEY，请在编译时令 PKEY_SUPPORT 为 OFF。如果仅进行debug测试，可以修改 nodrop.h 中 `NOD_TEST(task)` 宏，将对应的名字修改为进程名。

当编译完成后，可以通过 ctrl 命令行控制工具来启动 NoDrop，使用 `./scripts/ctrl/ctrl`。

为了方便，可以执行下面的命令创建一个 wrapper，使用 nodrop 作为全局工具名称。
```shell
cd build

sudo tee /usr/local/bin/nodrop >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail

CTRL_BIN="$(pwd)/scripts/ctrl/ctrl"

if [[ ! -x "\$CTRL_BIN" ]]; then
  echo "[nodrop] ctrl not found or not executable: \$CTRL_BIN" >&2
  echo "[nodrop] Hint: run 'make ctrl' first." >&2
  exit 1
fi

exec "\$CTRL_BIN" "\$@"
EOF

sudo chmod +x /usr/local/bin/nodrop
```

以下是使用 nodrop 的一些命令。
```shell
# start nodrop without lua
nodrop start
# start nodrop with lua
nodrop start <lua_path>
# stop nodrop
nodrop stop
# set record mode, [normal, compress, none]
# normal: raw binary log buffer
nodrop record normal
# compress: compressed binary log buffer
nodrop record compress
# none: do NOT record (default)
nodrop record none
```

以 helloworld 为例，可以使用以下命令：

```shell
cd build
make load
make helloworld
make ctrl
nodrop start ../scripts/lua/save.lua
./scripts/tests/helloworld
nodrop record normal
./scripts/tests/helloworld
```

可以在 `/tmp/nodrop/` 目录下看到一个新增的 .log 文件和 .buf 文件，分别是可读的日志与原始的日志 buffer。

## lua 脚本编写
lua脚本中需要包含两个函数，分别是 `on_event` 和 `on_init`。

在访问某一个字段时，需要先通过 `chisel.request_field("<field_name>")` 来获取句柄，之后通过 `evt.filed(<handle>)` 来访问事件相关字段。

目前支持的字段有：`evt.time`, `evt.type`, `evt.tid`, `evt.arg.<arg_name>`。

其中在访问 `evt.arg.<arg_name>` 需要保证该事件有对应名字的参数。

下面的 lua 脚本示范了抓取 `write` 系统调用的 fd 和 size 参数，并将其保存到文件 `/tmp/nodrop/nodrop_hello_args.log`。

```lua
local outfile = "/tmp/nodrop/nodrop_hello_args.log"
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

