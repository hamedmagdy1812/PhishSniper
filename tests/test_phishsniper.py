"""
Unit tests for PhishSniper.
"""

import unittest
from phishsniper import PhishSniper


class TestPhishSniper(unittest.TestCase):
    """Test cases for PhishSniper."""

    def setUp(self):
        """Set up test fixtures."""
        self.phish_sniper = PhishSniper()

    def test_analyze_legitimate_url(self):
        """Test analyzing a legitimate URL."""
        result = self.phish_sniper.analyze("https://www.google.com")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.url, "https://www.google.com")
        self.assertLessEqual(result.risk_score, 30)
        self.assertEqual(result.risk_level, "Low")

    def test_analyze_suspicious_url(self):
        """Test analyzing a suspicious URL."""
        result = self.phish_sniper.analyze("http://g00gle.tk/login.php")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.url, "http://g00gle.tk/login.php")
        self.assertGreaterEqual(result.risk_score, 30)
        self.assertIn(result.risk_level, ["Medium", "High"])
        
        # Check for specific risk factors
        risk_types = [factor["type"] for factor in result.risk_factors]
        self.assertIn("suspicious_tld", risk_types)

    def test_analyze_ip_address_url(self):
        """Test analyzing a URL with IP address."""
        result = self.phish_sniper.analyze("http://192.168.1.1/login")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.url, "http://192.168.1.1/login")
        
        # Check for IP address risk factor
        risk_types = [factor["type"] for factor in result.risk_factors]
        self.assertIn("ip_address", risk_types)
        self.assertIn("private_ip", risk_types)

    def test_analyze_homoglyph_attack(self):
        """Test analyzing a URL with homoglyph attack."""
        result = self.phish_sniper.analyze("https://arnazon.com/login")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.url, "https://arnazon.com/login")
        
        # Check for brand spoofing risk factor
        has_brand_match = False
        for factor in result.risk_factors:
            if "amazon" in factor["description"].lower():
                has_brand_match = True
                break
                
        self.assertTrue(has_brand_match)

    def test_analyze_verbose(self):
        """Test analyzing a URL with verbose output."""
        result = self.phish_sniper.analyze("https://www.google.com", verbose=True)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.features)
        self.assertIn("scheme", result.features)
        self.assertIn("hostname", result.features)
        self.assertIn("domain", result.features)
        self.assertIn("domain_info", result.features)


if __name__ == "__main__":
    unittest.main() 