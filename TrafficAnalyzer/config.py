import os

# Threshold for switching to SQLite storage (in bytes)
# Default: 100MB. If pcap size > this, use SQLite.
LARGE_PCAP_THRESHOLD = 100 * 1024 * 1024

# Analyzer Configurations
# Key must match the Analyzer class name or a specific identifier if we add one.
# Currently matching by class name is implicit or we can pass these to the constructor.
# Our BaseAnalyzer doesn't strictly enforce a config dict, but we will pass these as **kwargs.
ANALYZER_CONFIGS = {
    "PortScanAnalyzer": {
        "threshold": 10,
        "time_window": 5.0
    },
    # Future analyzers
    # "HttpAnalyzer": { ... }
}
