local outfile = "/tmp/nodrop/nodrop_hello_args.log"
local f = io.open(outfile, "w")

if not f then
    print("ERROR: cannot open log file:", outfile)
    return
end

function on_init()
    ftype  = chisel.request_field("evt.type")
    ffd    = chisel.request_field("evt.arg.fd")
    fsize = chisel.request_field("evt.arg.size")

    f:write("=== hello world arg test ===\n")
    f:flush()
    return true
end

function on_event()
    local t = evt.field(ftype)
    if t == "write" then
        local fd    = evt.field(ffd)
        local size = evt.field(fsize)

        f:write(string.format(
            "write(fd=%s, count=%s)\n",
            tostring(fd),
            tostring(size)
        ))
        f:flush()
    end

    return true
end
