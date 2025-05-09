"""
Main PhishSniper class that orchestrates the URL analysis process.
"""

import logging
from typing import Dict, Any, Optional, List

from .modules.url_parser import URLParser
from .modules.domain_intelligence import DomainIntelligence
from .modules.brand_matcher import BrandMatcher
from .modules.risk_engine import RiskEngine
from .result import AnalysisResult

logger = logging.getLogger(__name__)


class PhishSniper:
    """
    PhishSniper - Enterprise-grade phishing URL analyzer
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize PhishSniper with optional configuration.

        Args:
            config (Dict[str, Any], optional): Configuration dictionary.
        """
        self.config = config or {}
        
        # Initialize modules
        self.url_parser = URLParser()
        self.domain_intelligence = DomainIntelligence()
        self.brand_matcher = BrandMatcher()
        self.risk_engine = RiskEngine()
        
        logger.debug("PhishSniper initialized")

    def analyze(self, url: str, verbose: bool = False) -> AnalysisResult:
        """
        Analyze a URL for phishing indicators.

        Args:
            url (str): The URL to analyze
            verbose (bool, optional): Whether to include detailed analysis. Defaults to False.

        Returns:
            AnalysisResult: Analysis result with risk score and details
        """
        logger.info(f"Analyzing URL: {url}")
        
        # Parse URL and extract components
        url_features = self.url_parser.parse(url)
        
        # Get domain intelligence
        domain_info = self.domain_intelligence.analyze(url_features["hostname"])
        
        # Check for brand spoofing
        brand_matches = self.brand_matcher.find_matches(url_features["hostname"])
        
        # Combine all features
        all_features = {
            **url_features,
            "domain_info": domain_info,
            "brand_matches": brand_matches
        }
        
        # Calculate risk score
        risk_score, risk_factors = self.risk_engine.calculate_risk(all_features)
        
        # Create result object
        result = AnalysisResult(
            url=url,
            risk_score=risk_score,
            risk_factors=risk_factors,
            features=all_features if verbose else None
        )
        
        logger.info(f"Analysis complete. Risk score: {risk_score}%")
        return result 