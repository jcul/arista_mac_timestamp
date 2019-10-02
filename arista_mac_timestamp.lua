do
    local mac_timestamp =  Proto("arista_mac_timestamp", "Arista Source Mac Timestamp")

    local ns_field = ProtoField.uint32("arista_mac_timestamp.ns", "ns")
    local s_field = ProtoField.uint16("arista_mac_timestamp.sec", "sec")
    local timestamp_field = ProtoField.uint64("arista_mac_timestamp.timestamp", "timestamp")
    local diff_field = ProtoField.int64("arista_mac_timestamp.diff", "diff")

    local eth_src = Field.new("eth.src")

    mac_timestamp.fields = { s_field, ns_field, timestamp_field, diff_field }
    register_postdissector(mac_timestamp, true)

    -- Wireshark dissects packets at different times
    -- For example when a packet is clicked in the GUI it is dissected again
    -- This means we cannot just compare to the last packet as they will be
    -- out of sequence. However if using tshark then we can get the difference
    local last_ts = UInt64()
    local last_number = nil

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

            if last_number == (pinfo.number - 1) then
                subtree:add(diff_field, Int64(ts) - Int64(last_ts))
            end
            last_number = pinfo.number
            last_ts = ts
        end
    end
end

