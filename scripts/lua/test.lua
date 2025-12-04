local outfile = "/tmp/nodrop_events.log"

local f = io.open(outfile, "a")
if not f then
    print("ERROR: cannot open output file:", outfile)
    return
end

function on_event()
    local t = evt.type or "unknown"
    local tid = evt.tid or -1
    local ts = evt.ts or 0

    f:write(string.format("[ts=%d] [tid=%d] %s\n", ts, tid, t))
    f:flush()   -- 立即写入
end

function on_init()
    f:write("\n=== Lua logging started ===\n")
    f:flush()
end
