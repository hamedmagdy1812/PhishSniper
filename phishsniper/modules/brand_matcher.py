"""
Brand Matcher module for detecting brand spoofing in URLs.
"""

import os
import logging
import json
from typing import Dict, Any, List, Tuple
import pkg_resources

from fuzzywuzzy import fuzz
import tldextract

logger = logging.getLogger(__name__)


class BrandMatcher:
    """
    Detect brand spoofing in URLs using fuzzy string matching.
    """

    def __init__(self, brands_file: str = None):
        """
        Initialize the Brand Matcher.

        Args:
            brands_file (str, optional): Path to a JSON file containing brand names.
                                        If None, uses the default brands list.
        """
        # Top global brands commonly targeted in phishing
        self.default_brands = [
            "google", "microsoft", "apple", "amazon", "facebook", "paypal", 
            "netflix", "instagram", "twitter", "linkedin", "dropbox", "yahoo",
            "chase", "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
            "americanexpress", "mastercard", "visa", "outlook", "gmail", "icloud",
            "office365", "onedrive", "dropbox", "box", "adobe", "spotify",
            "steam", "epicgames", "blizzard", "ea", "ubisoft", "nintendo",
            "playstation", "xbox", "twitch", "youtube", "walmart", "target",
            "ebay", "aliexpress", "fedex", "ups", "dhl", "usps"
        ]
        
        # Load brands from file if provided
        self.brands = self._load_brands(brands_file)
        
        # Threshold for fuzzy matching (0-100)
        self.fuzzy_threshold = 85
        
        # Threshold for Levenshtein distance (based on domain length)
        self.levenshtein_threshold = 2
        
        logger.debug(f"BrandMatcher initialized with {len(self.brands)} brands")

    def find_matches(self, hostname: str) -> List[Dict[str, Any]]:
        """
        Find potential brand matches in a hostname.

        Args:
            hostname (str): The hostname to check

        Returns:
            List[Dict[str, Any]]: List of potential brand matches
        """
        logger.debug(f"Checking for brand spoofing in: {hostname}")
        
        # Extract domain without TLD
        extracted = tldextract.extract(hostname)
        domain = extracted.domain
        
        matches = []
        
        # Check for exact matches in subdomain or domain
        for brand in self.brands:
            # Check for brand name in domain
            if brand in domain.lower():
                # Skip if the domain is exactly the brand name
                if domain.lower() == brand.lower():
                    continue
                    
                matches.append({
                    "type": "brand_in_domain",
                    "brand": brand,
                    "value": domain,
                    "description": f"Brand '{brand}' found in domain"
                })
            
            # Check for brand name in subdomain
            if extracted.subdomain and brand in extracted.subdomain.lower():
                matches.append({
                    "type": "brand_in_subdomain",
                    "brand": brand,
                    "value": extracted.subdomain,
                    "description": f"Brand '{brand}' found in subdomain"
                })
        
        # Check for typosquatting using fuzzy matching
        for brand in self.brands:
            # Skip very short brands (to avoid false positives)
            if len(brand) < 4:
                continue
                
            # Calculate fuzzy match ratio
            ratio = fuzz.ratio(domain.lower(), brand.lower())
            
            # Calculate Levenshtein distance
            levenshtein = self._levenshtein_distance(domain.lower(), brand.lower())
            
            # Check if it's a potential typosquatting attempt
            if (ratio >= self.fuzzy_threshold or 
                (levenshtein <= self.levenshtein_threshold and len(brand) > 4)):
                
                # Skip exact matches
                if domain.lower() == brand.lower():
                    continue
                    
                matches.append({
                    "type": "typosquatting",
                    "brand": brand,
                    "value": domain,
                    "similarity": ratio,
                    "levenshtein": levenshtein,
                    "description": f"Possible typosquatting of '{brand}' (similarity: {ratio}%)"
                })
        
        # Check for homoglyph attacks
        homoglyph_matches = self._check_homoglyphs(domain)
        matches.extend(homoglyph_matches)
        
        return matches

    def _load_brands(self, brands_file: str = None) -> List[str]:
        """
        Load brands from a file or use the default list.

        Args:
            brands_file (str, optional): Path to a JSON file containing brand names.

        Returns:
            List[str]: List of brand names
        """
        if brands_file and os.path.exists(brands_file):
            try:
                with open(brands_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load brands from {brands_file}: {str(e)}")
                
        return self.default_brands

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate the Levenshtein distance between two strings.

        Args:
            s1 (str): First string
            s2 (str): Second string

        Returns:
            int: Levenshtein distance
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _check_homoglyphs(self, domain: str) -> List[Dict[str, Any]]:
        """
        Check for homoglyph attacks (similar-looking characters).

        Args:
            domain (str): The domain to check

        Returns:
            List[Dict[str, Any]]: List of potential homoglyph matches
        """
        # Common homoglyph replacements
        homoglyphs = {
            '0': 'o', 'o': '0',
            '1': 'l', 'l': '1', 'i': '1', '1': 'i',
            '5': 's', 's': '5',
            'rn': 'm', 'm': 'rn',
            'cl': 'd', 'd': 'cl',
            'vv': 'w', 'w': 'vv',
            'nn': 'm', 'm': 'nn'
        }
        
        matches = []
        
        # Check each brand
        for brand in self.brands:
            # Skip very short brands
            if len(brand) < 4:
                continue
                
            # Try replacing homoglyphs in the brand name
            for original, replacement in homoglyphs.items():
                if original in brand:
                    modified_brand = brand.replace(original, replacement)
                    
                    # If the modified brand matches the domain
                    if domain.lower() == modified_brand.lower():
                        matches.append({
                            "type": "homoglyph_attack",
                            "brand": brand,
                            "value": domain,
                            "substitution": f"'{original}' to '{replacement}'",
                            "description": f"Homoglyph attack on '{brand}' (replacing '{original}' with '{replacement}')"
                        })
                        
                    # Also check for partial matches in longer domains
                    elif modified_brand.lower() in domain.lower():
                        matches.append({
                            "type": "partial_homoglyph",
                            "brand": brand,
                            "value": domain,
                            "substitution": f"'{original}' to '{replacement}'",
                            "description": f"Partial homoglyph match for '{brand}' in domain"
                        })
        
        return matches 