"""
Domain Intelligence module for WHOIS lookups and domain analysis.
"""

import logging
import datetime
import socket
from typing import Dict, Any, Optional

import whois
import tldextract

logger = logging.getLogger(__name__)


class DomainIntelligence:
    """
    Perform WHOIS lookups and analyze domain information.
    """

    def __init__(self):
        """Initialize the Domain Intelligence module."""
        # List of suspicious registrars often associated with malicious domains
        self.suspicious_registrars = {
            "namecheap", "namesilo", "namebright", "porkbun", 
            "dynadot", "internetbs", "epik", "regru"
        }
        
        # Minimum domain age considered legitimate (in days)
        self.min_domain_age = 30
        
        logger.debug("DomainIntelligence initialized")

    def analyze(self, hostname: str) -> Dict[str, Any]:
        """
        Analyze domain intelligence for a given hostname.

        Args:
            hostname (str): The hostname to analyze

        Returns:
            Dict[str, Any]: Domain intelligence information
        """
        logger.debug(f"Analyzing domain intelligence for: {hostname}")
        
        # Extract domain from hostname (remove port if present)
        if ":" in hostname:
            hostname = hostname.split(":")[0]
            
        # Extract the domain without subdomains
        extracted = tldextract.extract(hostname)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        
        # Initialize result
        result = {
            "domain": domain,
            "domain_exists": False,
            "creation_date": None,
            "expiration_date": None,
            "last_updated": None,
            "registrar": None,
            "domain_age_days": None,
            "suspicious_traits": []
        }
        
        # Skip WHOIS lookup for IP addresses
        if self._is_ip_address(hostname):
            result["suspicious_traits"].append({
                "type": "ip_address_no_whois",
                "value": hostname,
                "description": "IP address used instead of domain name (no WHOIS data)"
            })
            return result
        
        try:
            # Perform WHOIS lookup
            whois_info = whois.whois(domain)
            
            # Check if domain exists
            if whois_info.domain_name is None:
                result["suspicious_traits"].append({
                    "type": "non_existent_domain",
                    "value": domain,
                    "description": "Domain does not exist in WHOIS records"
                })
                return result
                
            result["domain_exists"] = True
            
            # Extract WHOIS information
            result["creation_date"] = self._get_first_date(whois_info.creation_date)
            result["expiration_date"] = self._get_first_date(whois_info.expiration_date)
            result["last_updated"] = self._get_first_date(whois_info.updated_date)
            result["registrar"] = whois_info.registrar
            
            # Calculate domain age
            if result["creation_date"]:
                age = datetime.datetime.now() - result["creation_date"]
                result["domain_age_days"] = age.days
                
                # Check if domain is newly created
                if age.days < self.min_domain_age:
                    result["suspicious_traits"].append({
                        "type": "new_domain",
                        "value": age.days,
                        "description": f"Domain was registered recently ({age.days} days ago)"
                    })
            
            # Check for suspicious registrar
            if result["registrar"] and any(sr in str(result["registrar"]).lower() for sr in self.suspicious_registrars):
                result["suspicious_traits"].append({
                    "type": "suspicious_registrar",
                    "value": result["registrar"],
                    "description": f"Domain registered with suspicious registrar: {result['registrar']}"
                })
                
            # Check for short registration period
            if result["creation_date"] and result["expiration_date"]:
                registration_period = result["expiration_date"] - result["creation_date"]
                if registration_period.days < 365:
                    result["suspicious_traits"].append({
                        "type": "short_registration",
                        "value": registration_period.days,
                        "description": f"Short registration period ({registration_period.days} days)"
                    })
                    
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
            result["suspicious_traits"].append({
                "type": "whois_lookup_failed",
                "value": str(e),
                "description": "WHOIS lookup failed, which may indicate a suspicious domain"
            })
        
        return result
        
    def _get_first_date(self, date_value) -> Optional[datetime.datetime]:
        """
        Extract the first date from a date value that might be a list.

        Args:
            date_value: Date value from WHOIS (might be a list or single value)

        Returns:
            Optional[datetime.datetime]: The first date, or None if not available
        """
        if not date_value:
            return None
            
        if isinstance(date_value, list):
            return date_value[0] if date_value else None
        
        return date_value
        
    def _is_ip_address(self, hostname: str) -> bool:
        """
        Check if a hostname is an IP address.

        Args:
            hostname (str): The hostname to check

        Returns:
            bool: True if the hostname is an IP address, False otherwise
        """
        try:
            socket.inet_aton(hostname)
            return True
        except socket.error:
            return False 