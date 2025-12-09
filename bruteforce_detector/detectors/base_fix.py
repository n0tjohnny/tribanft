# Add after line 47 in __init__ (after self.logger = ...)

# Map event types to their config enable flags
enable_map = {
    EventType.PRELOGIN_INVALID: config.enable_prelogin_detection,
    EventType.FAILED_LOGIN: config.enable_failed_login_detection,
    EventType.PORT_SCAN: config.enable_port_scan_detection,
    EventType.CROWDSEC_BLOCK: config.enable_crowdsec_integration,
}

# Set enabled flag based on event type
self.enabled = enable_map.get(event_type, True)
self.name = self.__class__.__name__
