#!/usr/bin/env python3
"""
OpenADP Server URL Scraper

This module provides functionality to scrape a list of OpenADP server URLs
from a central registry. It handles various error conditions and provides
fallback mechanisms for robust server discovery.

The main function `scrape_server_urls()` fetches a list of servers from
a URL where each line contains one server URL.
"""

import urllib.request
import urllib.error
from typing import List, Optional


def scrape_server_urls(url: str = "https://servers.openadp.org") -> List[str]:
    """
    Scrape server URLs from a registry page.
    
    Fetches a web page where server URLs are listed one per line and returns
    them as a list. Includes a User-Agent header to avoid being blocked by
    servers that restrict automated requests.
    
    Args:
        url: The URL to scrape for server list. 
             Defaults to "https://servers.openadp.org".
    
    Returns:
        List of server URLs (strings). Empty list if scraping fails.
    
    Example:
        >>> servers = scrape_server_urls()
        >>> print(f"Found {len(servers)} servers")
        >>> for server in servers:
        ...     print(f"  {server}")
    """
    server_urls = []
    
    try:
        # Create request with realistic User-Agent to avoid 403 Forbidden errors
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            for line in response:
                decoded_line = line.decode('utf-8').strip()
                
                # Skip empty lines
                if not decoded_line:
                    continue
                    
                # Filter out HTML tags and other non-URL content
                if _is_valid_server_url(decoded_line):
                    server_urls.append(decoded_line)
                    
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason}")
        print(f"Failed to fetch server list from {url}")
        print("This may indicate the URL is incorrect or the server blocks automated requests.")
        
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
        print(f"Failed to connect to {url}")
        print("This often indicates a network issue or invalid URL.")
        
    except Exception as e:
        print(f"Unexpected error while scraping servers: {e}")
    
    return server_urls


def _is_valid_server_url(line: str) -> bool:
    """
    Check if a line contains a valid server URL.
    
    Filters out HTML tags, comments, and other non-URL content that might
    appear in the server list page.
    
    Args:
        line: Line of text to validate
        
    Returns:
        True if the line appears to be a valid server URL
    """
    # Skip HTML tags
    if line.startswith('<') or line.endswith('>'):
        return False
        
    # Skip HTML comments
    if line.startswith('<!--') or line.endswith('-->'):
        return False
        
    # Skip lines that don't look like URLs
    if not (line.startswith('http://') or line.startswith('https://')):
        return False
        
    # Skip lines with spaces (URLs shouldn't have spaces)
    if ' ' in line:
        return False
        
    return True


def get_fallback_servers() -> List[str]:
    """
    Get a list of fallback servers to use if scraping fails.
    
    Returns:
        List of known working server URLs
    """
    return [
        "https://xyzzybill.openadp.org",
        "https://sky.openadp.org"
    ]


def main():
    """
    Test/demo function for server URL scraping.
    
    Attempts to scrape servers and displays the results, falling back
    to hardcoded servers if scraping fails.
    """
    print("OpenADP Server Discovery")
    print("=" * 30)
    
    # Try to scrape servers
    print("Attempting to scrape server list...")
    servers = scrape_server_urls()
    
    if servers:
        print(f"✅ Successfully found {len(servers)} servers:")
        for i, server_url in enumerate(servers, 1):
            print(f"  {i}. {server_url}")
    else:
        print("❌ Failed to scrape servers, using fallback list:")
        servers = get_fallback_servers()
        for i, server_url in enumerate(servers, 1):
            print(f"  {i}. {server_url}")
    
    print(f"\nTotal servers available: {len(servers)}")


if __name__ == "__main__":
    main()
