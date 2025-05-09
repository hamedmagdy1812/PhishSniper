"""
Setup script for PhishSniper.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="phishsniper",
    version="0.1.0",
    author="PhishSniper Team",
    author_email="info@phishsniper.example.com",
    description="Enterprise-grade phishing URL analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/phishsniper/phishsniper",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "phishsniper": ["data/*.json", "templates/*.html"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.28.1",
        "python-whois>=0.8.0",
        "tldextract>=3.4.0",
        "validators>=0.20.0",
        "fuzzywuzzy>=0.18.0",
        "python-Levenshtein>=0.20.9",
        "idna>=3.4",
        "urllib3>=1.26.15",
        "colorama>=0.4.6",
        "click>=8.1.3",
        "flask>=2.2.3",
    ],
    entry_points={
        "console_scripts": [
            "phishsniper=phishsniper.cli:main",
            "phishsniper-web=phishsniper.web:main",
        ],
    },
) 