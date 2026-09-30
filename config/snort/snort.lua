-- SenseL NDR Edge — minimal Snort 3 config for the alert_json bridge.
-- The edge bridge (packet-sensor SnortAlertSource) only depends on the
-- alert_json output and its field set, so this file stays intentionally small.
--
-- Run (inside the snort container):
--   snort -c /etc/snort/snort.lua -i "$SNORT_INTERFACE" -l /var/log/snort
--
-- Set HOME_NET to your monitored subnet(s) for tighter scoping (e.g.
-- '10.10.1.0/24'); 'any' works for an initial passive lab bring-up.

HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Load the community/local rules mounted into the container.
ips =
{
    enable_builtin_rules = true,
    rules = [[
        include /etc/snort/rules/local.rules
    ]],
}

-- Stream / service inspection kept at defaults; enough for L3/L4 + common
-- app-layer SIDs to fire. Extend as the OT rule pack grows.
stream = { }
stream_tcp = { }
stream_udp = { }

-- NDJSON alert output consumed by the SenseL edge bridge. Fields are pinned so
-- the mapper (snort_source.py) has a stable contract — do not change without
-- updating SnortAlertMapper.
alert_json =
{
    file = true,
    limit = 100,   -- MB before rotation
    fields = 'timestamp gid sid rev priority class action msg proto \
              src_addr src_port dst_addr dst_port service pkt_num iface',
}
