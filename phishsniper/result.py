"""
Result class for PhishSniper analysis.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional


@dataclass
class AnalysisResult:
    """
    Container for URL analysis results.
    """
    url: str
    risk_score: float
    risk_factors: List[Dict[str, Any]]
    features: Optional[Dict[str, Any]] = None

    @property
    def risk_level(self) -> str:
        """
        Get the risk level based on the risk score.

        Returns:
            str: Risk level (Low, Medium, High)
        """
        if self.risk_score < 30:
            return "Low"
        elif self.risk_score < 70:
            return "Medium"
        else:
            return "High"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the result to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the result
        """
        result = {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
        }
        
        if self.features:
            result["features"] = self.features
            
        return result 