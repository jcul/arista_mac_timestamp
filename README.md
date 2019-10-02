
Wireshark post-dissector to decode arista timestamps that are embedded in the
source mac address, e.g. from an Arista 7280.

You can run the plugin using tshark or wireshark:

    wireshark -Xlua_script:arista_mac_timestamp.lua
    tshark -Xlua_script:arista_mac_timestamp.lua -rpcap -Tfields -earista_mac_timestamp.sec -earista_mac_timestamp.ns -earista_mac_timestamp.timestamp -earista_mac_timestamp.diff

The diff field is the current packet timestamp - previous packet timestamp.

Wireshark does not always dissect the packets in sequence, for example when a
packet is clicked in the GUI it is dissected again. This means we can't always
calculate the diff by just looking at the last packet. For tshark it should work
OK.

Or you can install it by copying the lua script to wireshark's plugin directory:

https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

To enable / disable, in the GUI, Analyze->Enabled Protocols... (Ctrl+Shift+E).
