function on_init()
    return true
end

function on_event()
    evt.save("/tmp/nodrop/nodrop.log")
    return true
end
