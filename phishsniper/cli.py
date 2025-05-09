"""
Command Line Interface for PhishSniper.
"""

import sys
import json
import logging
import argparse
from typing import List, Optional

import colorama
from colorama import Fore, Style

from .phishsniper import PhishSniper
from .result import AnalysisResult

# Initialize colorama
colorama.init(autoreset=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def setup_parser() -> argparse.ArgumentParser:
    """
    Set up the argument parser.

    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="PhishSniper - Enterprise-grade phishing URL analyzer"
    )
    
    parser.add_argument(
        "--url", "-u",
        type=str,
        help="URL to analyze for phishing indicators"
    )
    
    parser.add_argument(
        "--file", "-f",
        type=str,
        help="File containing URLs to analyze (one per line)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for results (JSON format)"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    parser.add_argument(
        "--brands-file",
        type=str,
        help="Path to JSON file containing brand names"
    )
    
    return parser


def analyze_url(url: str, phish_sniper: PhishSniper, verbose: bool = False) -> AnalysisResult:
    """
    Analyze a single URL.

    Args:
        url (str): URL to analyze
        phish_sniper (PhishSniper): PhishSniper instance
        verbose (bool, optional): Enable verbose output. Defaults to False.

    Returns:
        AnalysisResult: Analysis result
    """
    try:
        return phish_sniper.analyze(url, verbose)
    except Exception as e:
        logger.error(f"Error analyzing URL {url}: {str(e)}")
        raise


def analyze_urls_from_file(file_path: str, phish_sniper: PhishSniper, verbose: bool = False) -> List[AnalysisResult]:
    """
    Analyze URLs from a file.

    Args:
        file_path (str): Path to file containing URLs
        phish_sniper (PhishSniper): PhishSniper instance
        verbose (bool, optional): Enable verbose output. Defaults to False.

    Returns:
        List[AnalysisResult]: List of analysis results
    """
    results = []
    
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
            
        for url in urls:
            try:
                result = phish_sniper.analyze(url, verbose)
                results.append(result)
                print_result(result, verbose)
            except Exception as e:
                logger.error(f"Error analyzing URL {url}: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        
    return results


def print_result(result: AnalysisResult, verbose: bool = False) -> None:
    """
    Print analysis result to console.

    Args:
        result (AnalysisResult): Analysis result
        verbose (bool, optional): Enable verbose output. Defaults to False.
    """
    # Determine color based on risk level
    if result.risk_level == "High":
        risk_color = Fore.RED
    elif result.risk_level == "Medium":
        risk_color = Fore.YELLOW
    else:
        risk_color = Fore.GREEN
        
    print("\n" + "="*80)
    print(f"URL: {Style.BRIGHT}{result.url}{Style.RESET_ALL}")
    print(f"Risk Score: {risk_color}{result.risk_score:.1f}%{Style.RESET_ALL}")
    print(f"Risk Level: {risk_color}{result.risk_level}{Style.RESET_ALL}")
    
    if result.risk_factors:
        print("\nRisk Factors:")
        for factor in result.risk_factors:
            print(f"  - {factor['description']} {Fore.CYAN}({factor['weight']} points){Style.RESET_ALL}")
    
    if verbose and result.features:
        print("\nDetailed Analysis:")
        
        # URL components
        print(f"\n{Fore.BLUE}URL Components:{Style.RESET_ALL}")
        print(f"  Scheme: {result.features.get('scheme', 'N/A')}")
        print(f"  Domain: {result.features.get('domain', 'N/A')}")
        print(f"  Subdomain: {result.features.get('subdomain', 'N/A')}")
        print(f"  TLD: {result.features.get('tld', 'N/A')}")
        print(f"  Path: {result.features.get('path', 'N/A')}")
        
        # Domain intelligence
        if "domain_info" in result.features:
            domain_info = result.features["domain_info"]
            print(f"\n{Fore.BLUE}Domain Intelligence:{Style.RESET_ALL}")
            print(f"  Domain Age: {domain_info.get('domain_age_days', 'N/A')} days")
            print(f"  Registrar: {domain_info.get('registrar', 'N/A')}")
            print(f"  Creation Date: {domain_info.get('creation_date', 'N/A')}")
            
        # Brand matches
        if "brand_matches" in result.features and result.features["brand_matches"]:
            print(f"\n{Fore.BLUE}Brand Matches:{Style.RESET_ALL}")
            for match in result.features["brand_matches"]:
                print(f"  - {match['description']}")


def save_results(results: List[AnalysisResult], output_file: str) -> None:
    """
    Save results to a JSON file.

    Args:
        results (List[AnalysisResult]): List of analysis results
        output_file (str): Output file path
    """
    try:
        with open(output_file, 'w') as f:
            json_results = [result.to_dict() for result in results]
            json.dump(json_results, f, indent=2, default=str)
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving results to {output_file}: {str(e)}")


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        args (Optional[List[str]], optional): Command line arguments. Defaults to None.

    Returns:
        int: Exit code
    """
    parser = setup_parser()
    args = parser.parse_args(args)
    
    # Set log level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize PhishSniper
    config = {}
    if args.brands_file:
        config["brands_file"] = args.brands_file
        
    phish_sniper = PhishSniper(config)
    
    # Check if URL or file is provided
    if not args.url and not args.file:
        parser.print_help()
        return 1
    
    results = []
    
    # Analyze single URL
    if args.url:
        try:
            result = analyze_url(args.url, phish_sniper, args.verbose)
            results.append(result)
            print_result(result, args.verbose)
        except Exception:
            return 1
    
    # Analyze URLs from file
    if args.file:
        file_results = analyze_urls_from_file(args.file, phish_sniper, args.verbose)
        results.extend(file_results)
    
    # Save results if output file is provided
    if args.output and results:
        save_results(results, args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 