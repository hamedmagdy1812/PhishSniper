"""
URL Parser module for decomposing and analyzing URLs.
"""

import re
import logging
import urllib.parse
import ipaddress
from typing import Dict, Any, List, Tuple

import tldextract
import validators

logger = logging.getLogger(__name__)


class URLParser:
    """
    Parse and analyze URL components for suspicious traits.
    """

    def __init__(self):
        """Initialize the URL parser."""
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = {
            "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "date", "bid",
            "stream", "racing", "win", "review", "country", "science", "download"
        }
        
        # Regular expressions for detecting obfuscation
        self.hex_pattern = re.compile(r'%[0-9a-fA-F]{2}')
        self.ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.unicode_pattern = re.compile(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}')
        
        logger.debug("URLParser initialized")

    def parse(self, url: str) -> Dict[str, Any]:
        """
        Parse a URL and extract its components.

        Args:
            url (str): The URL to parse

        Returns:
            Dict[str, Any]: Dictionary of URL components and features
        """
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        logger.debug(f"Parsing URL: {url}")
        
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        
        # Extract domain parts using tldextract
        extracted = tldextract.extract(url)
        
        # Get query parameters
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Analyze suspicious traits
        suspicious_traits = self._analyze_suspicious_traits(parsed, extracted)
        
        # Prepare result
        result = {
            "url": url,
            "scheme": parsed.scheme,
            "hostname": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "domain": extracted.domain,
            "subdomain": extracted.subdomain,
            "tld": extracted.suffix,
            "query_params": query_params,
            "suspicious_traits": suspicious_traits
        }
        
        logger.debug(f"URL parsed: {result}")
        return result

    def _analyze_suspicious_traits(self, parsed: urllib.parse.ParseResult, 
                                  extracted: tldextract.ExtractResult) -> List[Dict[str, Any]]:
        """
        Analyze URL for suspicious traits.

        Args:
            parsed (urllib.parse.ParseResult): Parsed URL
            extracted (tldextract.ExtractResult): Extracted domain parts

        Returns:
            List[Dict[str, Any]]: List of suspicious traits found
        """
        suspicious_traits = []
        netloc = parsed.netloc
        
        # Check for non-standard port
        if ":" in netloc and not netloc.endswith((":80", ":443")):
            port = netloc.split(":")[-1]
            suspicious_traits.append({
                "type": "non_standard_port",
                "value": port,
                "description": f"Non-standard port {port} in use"
            })
        
        # Check for IP address instead of domain name
        if self.ip_pattern.search(netloc.split(":")[0]):
            suspicious_traits.append({
                "type": "ip_address",
                "value": netloc.split(":")[0],
                "description": "IP address used instead of domain name"
            })
            
            # Check if IP is private
            try:
                ip = netloc.split(":")[0]
                if ipaddress.ip_address(ip).is_private:
                    suspicious_traits.append({
                        "type": "private_ip",
                        "value": ip,
                        "description": "Private IP address used"
                    })
            except ValueError:
                pass
        
        # Check for too many subdomains
        subdomain_parts = extracted.subdomain.split('.')
        if len(subdomain_parts) > 3:
            suspicious_traits.append({
                "type": "many_subdomains",
                "value": extracted.subdomain,
                "description": f"Excessive number of subdomains ({len(subdomain_parts)})"
            })
        
        # Check for suspicious TLD
        if extracted.suffix in self.suspicious_tlds:
            suspicious_traits.append({
                "type": "suspicious_tld",
                "value": extracted.suffix,
                "description": f"Suspicious TLD '{extracted.suffix}'"
            })
        
        # Check for hexadecimal/URL encoding in domain or path
        if self.hex_pattern.search(netloc) or self.hex_pattern.search(parsed.path):
            suspicious_traits.append({
                "type": "hex_encoding",
                "value": url,
                "description": "Hexadecimal encoding detected in URL"
            })
        
        # Check for unicode/punycode obfuscation
        if "xn--" in netloc:
            suspicious_traits.append({
                "type": "punycode",
                "value": netloc,
                "description": "Punycode (IDN) encoding detected"
            })
        
        # Check for excessive URL length
        url_length = len(parsed.geturl())
        if url_length > 100:
            suspicious_traits.append({
                "type": "long_url",
                "value": url_length,
                "description": f"Excessively long URL ({url_length} characters)"
            })
        
        # Check for excessive number of special characters in domain
        special_chars = sum(1 for c in netloc if not c.isalnum() and c not in ['.', '-', ':'])
        if special_chars > 3:
            suspicious_traits.append({
                "type": "special_chars",
                "value": special_chars,
                "description": f"Excessive special characters in domain ({special_chars})"
            })
        
        return suspicious_traits 