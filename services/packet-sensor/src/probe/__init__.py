"""Safe, read-only active device probing (opt-in).

Runs inside the packet-sensor container (host network → can reach the OT
subnet). Limited to a TCP connect fingerprint plus the standardised Modbus
Read Device Identification (FC 0x2B/0x0E), which is a read-only request.
"""
