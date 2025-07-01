#!/usr/bin/env python3
"""
Setup script for OpenADP Python SDK.

This script allows the OpenADP Python SDK to be installed via pip:
    pip install .

Or in development mode:
    pip install -e .
"""

from setuptools import setup, find_packages
import os

# Read the README file for the long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return "OpenADP Python SDK for distributed secret sharing and advanced data protection"

# Read requirements from requirements.txt
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(requirements_path):
        with open(requirements_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        # Filter out comments and optional dependencies
        requirements = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                # Only include core dependencies (cryptography and requests)
                if any(dep in line for dep in ["cryptography", "requests"]):
                    requirements.append(line)
        return requirements
    
    # Fallback to hardcoded requirements
    return [
        "cryptography>=41.0.0",
        "requests>=2.28.0"
    ]

setup(
    name="openadp",
    version="0.1.3",
    author="OpenADP Team",
    author_email="contact@openadp.org",
    description="OpenADP Python SDK for distributed secret sharing and advanced data protection",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/openadp/openadp",
    project_urls={
        "Bug Reports": "https://github.com/openadp/openadp/issues",
        "Source": "https://github.com/openadp/openadp",
        "Documentation": "https://docs.openadp.org",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Archiving :: Backup",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-asyncio>=0.21.0",
            "mypy>=1.0.0",
            "types-requests>=2.28.0",
            "black>=23.0.0",
            "isort>=5.12.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "openadp-test=openadp.test_client:main",
        ],
    },
    keywords="cryptography, secret-sharing, backup, security, distributed, threshold",
    zip_safe=False,
    include_package_data=True,
    package_data={
        "openadp": ["*.md", "*.txt"],
    },
) 