#!/usr/bin/env python3
"""
Test script to check if required modules can be imported.
"""

import sys
import os

print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print(f"Python path: {sys.path}")

try:
    import tldextract
    print(f"tldextract version: {tldextract.__version__}")
except ImportError as e:
    print(f"Failed to import tldextract: {e}")

try:
    import whois
    print(f"whois module imported successfully")
except ImportError as e:
    print(f"Failed to import whois: {e}")

try:
    import fuzzywuzzy
    print(f"fuzzywuzzy imported successfully")
except ImportError as e:
    print(f"Failed to import fuzzywuzzy: {e}")

try:
    import validators
    print(f"validators imported successfully")
except ImportError as e:
    print(f"Failed to import validators: {e}")

try:
    from phishsniper import PhishSniper
    print(f"PhishSniper imported successfully")
except ImportError as e:
    print(f"Failed to import PhishSniper: {e}") 