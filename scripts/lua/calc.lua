syscall_counts = {}

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