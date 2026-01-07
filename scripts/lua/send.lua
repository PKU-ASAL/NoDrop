-- UDP server address
local SERVER_IP   = "127.0.0.1"
local SERVER_PORT = 9000

function on_init()
    -- 申请几个字段只是为了确认 field 系统也正常
    ftype = chisel.request_field("evt.type")
    ftime = chisel.request_field("evt.time")

    print("[lua] send_all_events.lua initialized")
    return true
end

function on_event()
    -- 发送当前 event（sysdig-style 完整文本）
    evt.send(SERVER_IP, SERVER_PORT)

    return true
end
