do
    local mac_timestamp =  Proto("arista_mac_timestamp", "Arista Source Mac Timestamp")

    local ns_field = ProtoField.uint32("arista_mac_timestamp.ns", "ns")
    local s_field = ProtoField.uint16("arista_mac_timestamp.sec", "sec")
    local timestamp_field = ProtoField.uint64("arista_mac_timestamp.timestamp", "timestamp")

    local eth_src = Field.new("eth.src")

    mac_timestamp.fields = { s_field, ns_field, timestamp_field }
    register_postdissector(mac_timestamp)

    function mac_timestamp.dissector(buf, pinfo, tree)
        local ts_raw = eth_src()
        if ts_raw then
            local subtree = tree:add(mac_timestamp, "Arista Timestamp")
            local offset = ts_raw.offset

            local sec = buf(offset, 2):uint()
            local ns = buf(offset + 2, 4):uint()
            local ts = (UInt64(sec) * UInt64(1000000000)) + UInt64(ns)

            subtree:add(s_field, sec)
            subtree:add(ns_field, ns)
            subtree:add(timestamp_field, ts)
        end
    end
end

