"""
Config file for file paths and thread creation intervals
"""

# Path to logger folder
LOGGER_PATH = "./logs/"

# Datetime format
DATETIME_FORMAT = "%Y-%m-%d_%H-%M-%S"

# Path to cap folder
CAP_PATH = "./cap/"
CAP_EXTENSION = ".cap"

# Path to rules folder
RULES_DIR = "./rules/"

# Path to threat-intel folder
INTEL_DIR = "./rules/threat_intel/"

# Path to threat-intel folder
CUSTOM_RULES_DIR = "./rules/custom_rules/"

# Path to malware rules folder
MAL_DIR = "./rules/malware/"

# Path to carved files directory
CARVED_DIR = "./carved/"

# Path to session cache folder
SESSION_CACHE_PATH = "./.cache"

# THREAD INTERVALS
MEMORY_WATCHDOG_INTERVAL = 5
BULK_MANAGER_INTERVAL = 5  # handling "session yara" and "threat"
SESSION_CACHING_INTERVAL = 10
