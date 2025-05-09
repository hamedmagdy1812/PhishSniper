# PhishSniper

PhishSniper is an enterprise-grade phishing URL analyzer that uses a hybrid heuristic and rule-based scoring system to identify potentially malicious URLs. It's designed to be integrated into SOC pipelines, email filters, or threat intelligence platforms.

## Features

- **URL Parsing & Heuristic Analysis**: Decompose URLs and flag suspicious traits
- **WHOIS & Domain Intelligence**: Check domain age, registrar reputation, and lifespan
- **Brand Spoofing Detection**: Detect typosquatting and homoglyph attacks
- **Phishing Risk Scoring Engine**: Assign weighted scores and provide risk levels
- **Modular Architecture**: Easily extensible for future enhancements

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m phishsniper.cli --url "https://example.com" --verbose
```

## API Usage

```python
from phishsniper import PhishSniper

analyzer = PhishSniper()
result = analyzer.analyze("https://example.com")
print(f"Risk Score: {result.risk_score}%")
print(f"Risk Level: {result.risk_level}")
```

## License

PhishSniper is released under the [MIT License](LICENSE). See the LICENSE file for details.
