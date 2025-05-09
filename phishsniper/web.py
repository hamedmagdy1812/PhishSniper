"""
Web interface for PhishSniper using Flask.
"""

import os
import logging
from typing import Dict, Any

from flask import Flask, request, jsonify, render_template, abort

from .phishsniper import PhishSniper

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize PhishSniper
phish_sniper = PhishSniper()

# Initialize Flask app
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))


@app.route("/")
def index():
    """Render the index page."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """API endpoint to analyze a URL."""
    data = request.json
    
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400
        
    url = data["url"]
    verbose = data.get("verbose", False)
    
    try:
        result = phish_sniper.analyze(url, verbose)
        return jsonify(result.to_dict())
    except Exception as e:
        logger.error(f"Error analyzing URL {url}: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/batch", methods=["POST"])
def batch_analyze():
    """API endpoint to analyze multiple URLs."""
    data = request.json
    
    if not data or "urls" not in data or not isinstance(data["urls"], list):
        return jsonify({"error": "List of URLs is required"}), 400
        
    urls = data["urls"]
    verbose = data.get("verbose", False)
    
    results = []
    errors = []
    
    for url in urls:
        try:
            result = phish_sniper.analyze(url, verbose)
            results.append(result.to_dict())
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            errors.append({"url": url, "error": str(e)})
    
    return jsonify({
        "results": results,
        "errors": errors
    })


def create_app(config: Dict[str, Any] = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config (Dict[str, Any], optional): Configuration dictionary. Defaults to None.

    Returns:
        Flask: Configured Flask application
    """
    if config:
        app.config.update(config)
        
        # Re-initialize PhishSniper with config if needed
        if "phishsniper" in config:
            global phish_sniper
            phish_sniper = PhishSniper(config["phishsniper"])
    
    return app


def main():
    """Run the Flask development server."""
    app.run(debug=True, host="0.0.0.0", port=5001)


if __name__ == "__main__":
    main() 