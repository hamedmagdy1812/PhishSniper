#!/usr/bin/env python3
"""
Example script demonstrating PhishSniper usage.
"""

import sys
import json
import os

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phishsniper import PhishSniper

# Sample URLs to analyze
SAMPLE_URLS = [
    "https://www.google.com",                  # Legitimate
    "http://g00gle.tk/login.php",              # Suspicious TLD + homoglyph
    "http://192.168.1.1/login",                # IP address
    "https://paypal-secure.com/login",         # Brand in domain
    "https://arnazon.com/login",               # Homoglyph attack
    "https://www.microsoft.com",               # Legitimate
    "https://micr0s0ft.xyz/security/login",    # Homoglyph + suspicious TLD
    "https://login.banking.wellsfargo.com",     # Legitimate with subdomains
    "https://login.banking.wel1sfargo.com"      # Legitimate-looking with typo
]


def main():
    """Main function."""
    # Initialize PhishSniper
    phish_sniper = PhishSniper()
    
    # Analyze each URL
    for url in SAMPLE_URLS:
        print(f"\nAnalyzing URL: {url}")
        print("-" * 50)
        
        # Analyze with verbose output
        result = phish_sniper.analyze(url, verbose=True)
        
        # Print basic results
        print(f"Risk Score: {result.risk_score:.1f}%")
        print(f"Risk Level: {result.risk_level}")
        
        # Print risk factors
        if result.risk_factors:
            print("\nRisk Factors:")
            for factor in result.risk_factors:
                print(f"  - {factor['description']} ({factor['weight']} points)")
        else:
            print("\nNo risk factors detected.")
        
        # Print brand matches if any
        if result.features and "brand_matches" in result.features and result.features["brand_matches"]:
            print("\nBrand Matches:")
            for match in result.features["brand_matches"]:
                print(f"  - {match['description']}")
        
        print("\n" + "=" * 80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 