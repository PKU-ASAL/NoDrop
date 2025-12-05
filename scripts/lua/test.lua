local outfile = "/tmp/nodrop_evt_args.log"

local f = io.open(outfile, "a")
if not f then
    print("ERROR: cannot open log file:", outfile)
    return
end

function on_init()
    f:write("\n=== Lua logging started ===\n")
    f:flush()
end

function on_event(evt)
    f:write(string.format(
        "type=%s tid=%d cpu=%d time=%d\n",
        tostring(evt.type),
        tonumber(evt.tid or -1),
        tonumber(evt.cpu or -1),
        tonumber(evt.time or 0)
    ))

    if evt.args then
        for k, v in pairs(evt.args) do
            f:write(string.format("  %s = %s\n", tostring(k), tostring(v)))
        end
    end

    f:write("\n")
    f:flush()
end
