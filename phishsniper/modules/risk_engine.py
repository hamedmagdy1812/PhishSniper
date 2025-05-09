"""
Risk Engine module for calculating phishing risk scores.
"""

import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Calculate phishing risk scores based on URL features.
    """

    def __init__(self):
        """Initialize the Risk Engine with risk weights."""
        # Risk weights for different factors
        self.risk_weights = {
            # URL Parser suspicious traits
            "non_standard_port": 15,
            "ip_address": 25,
            "private_ip": 30,
            "many_subdomains": 15,
            "suspicious_tld": 20,
            "hex_encoding": 30,
            "punycode": 25,
            "long_url": 10,
            "special_chars": 15,
            
            # Domain Intelligence suspicious traits
            "non_existent_domain": 40,
            "whois_lookup_failed": 15,
            "new_domain": 25,
            "suspicious_registrar": 15,
            "short_registration": 20,
            "ip_address_no_whois": 25,
            
            # Brand Matcher suspicious traits
            "brand_in_domain": 15,
            "brand_in_subdomain": 20,
            "typosquatting": 40,
            "homoglyph_attack": 50,
            "partial_homoglyph": 35
        }
        
        # Maximum possible risk score
        self.max_risk_score = 100
        
        logger.debug("RiskEngine initialized")

    def calculate_risk(self, features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate the phishing risk score based on URL features.

        Args:
            features (Dict[str, Any]): URL features from all analyzers

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Risk score (0-100) and list of risk factors
        """
        logger.debug("Calculating risk score")
        
        risk_factors = []
        total_weight = 0
        
        # Process URL suspicious traits
        if "suspicious_traits" in features:
            for trait in features["suspicious_traits"]:
                trait_type = trait["type"]
                if trait_type in self.risk_weights:
                    weight = self.risk_weights[trait_type]
                    total_weight += weight
                    risk_factors.append({
                        "type": trait_type,
                        "weight": weight,
                        "description": trait["description"]
                    })
        
        # Process domain intelligence suspicious traits
        if "domain_info" in features and "suspicious_traits" in features["domain_info"]:
            for trait in features["domain_info"]["suspicious_traits"]:
                trait_type = trait["type"]
                if trait_type in self.risk_weights:
                    weight = self.risk_weights[trait_type]
                    total_weight += weight
                    risk_factors.append({
                        "type": trait_type,
                        "weight": weight,
                        "description": trait["description"]
                    })
        
        # Process brand matches
        if "brand_matches" in features:
            for match in features["brand_matches"]:
                match_type = match["type"]
                if match_type in self.risk_weights:
                    weight = self.risk_weights[match_type]
                    
                    # Adjust weight for typosquatting based on similarity
                    if match_type == "typosquatting" and "similarity" in match:
                        # Higher similarity = higher risk
                        similarity_factor = match["similarity"] / 100
                        weight = int(weight * similarity_factor)
                    
                    total_weight += weight
                    risk_factors.append({
                        "type": match_type,
                        "weight": weight,
                        "description": match["description"]
                    })
        
        # Calculate final risk score (capped at 100)
        risk_score = min(total_weight, self.max_risk_score)
        
        # Sort risk factors by weight (descending)
        risk_factors.sort(key=lambda x: x["weight"], reverse=True)
        
        logger.info(f"Risk score: {risk_score}%, Risk factors: {len(risk_factors)}")
        return risk_score, risk_factors

    def adjust_weights(self, new_weights: Dict[str, int]) -> None:
        """
        Adjust the risk weights.

        Args:
            new_weights (Dict[str, int]): New weights to apply
        """
        for key, value in new_weights.items():
            if key in self.risk_weights:
                self.risk_weights[key] = value
                logger.debug(f"Adjusted weight for {key}: {value}")
            else:
                logger.warning(f"Unknown risk factor: {key}")
                
        logger.info(f"Risk weights adjusted: {len(new_weights)} weights updated") 