"""External detection engine sources (Snort 3, Suricata).

These bridge third-party engine alert output into the SenseL ``SecurityEvent``
model so they flow north through the existing edge-agent upload path without
any changes to the MQTT publisher, local buffer, or sighting reporter.
"""
