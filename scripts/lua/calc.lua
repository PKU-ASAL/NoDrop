description = "Count number of occurrences of each syscall"
short_description = "syscall counter"
category = "Example"

args = {}

-- table to store counts
syscall_counts = {}

-- request fields from sysdig
function on_init()
    f_type = chisel.request_field("evt.type")
    return true
end

function on_event()
    local evt = evt.field(f_type)

    if evt == nil then
        return
    end

    if syscall_counts[evt] == nil then
        syscall_counts[evt] = 1
    else
        syscall_counts[evt] = syscall_counts[evt] + 1
    end

    return true
end

function on_capture_end()
    print("========== Syscall Statistics ==========")

    for k,v in pairs(syscall_counts) do
        print(string.format("%-20s %d", k, v))
    end
end