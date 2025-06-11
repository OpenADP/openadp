#!/usr/bin/env python3
"""
OpenADP Server Discovery

This module provides functionality to discover OpenADP server URLs and public keys
from the central registry. It fetches server information from the JSON API and
provides fallback mechanisms for robust server discovery.

The main function `get_servers()` fetches server information from the JSON API
and returns a list of server dictionaries with URL, public key, and country.
"""

import urllib.request
import urllib.error
import json
from typing import List, Dict, Optional


def get_servers(registry_url: str = "https://servers.openadp.org") -> List[Dict[str, str]]:
    """
    Get server information from the OpenADP registry.
    
    Fetches server data from the JSON API which includes URLs, public keys,
    and country information for each server.
    
    Args:
        registry_url: The base URL of the OpenADP server registry.
                     Defaults to "https://servers.openadp.org".
    
    Returns:
        List of server dictionaries, each containing:
        - 'url': The server endpoint URL
        - 'public_key': The server's Ed25519 public key  
        - 'country': ISO country code
        Empty list if fetching fails.
    
    Example:
        >>> servers = get_servers()
        >>> print(f"Found {len(servers)} servers")
        >>> for server in servers:
        ...     print(f"  {server['url']} ({server['country']})")
    """
    api_url = f"{registry_url.rstrip('/')}/api/servers.json"
    
    try:
        # Create request with realistic User-Agent
        req = urllib.request.Request(
            api_url,
            headers={
                'User-Agent': 'OpenADP-Client/1.0',
                'Accept': 'application/json'
            }
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # Extract servers from JSON response
            if 'servers' in data and isinstance(data['servers'], list):
                return data['servers']
            else:
                print("Warning: Invalid JSON format - missing 'servers' array")
                return []
                
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason}")
        print(f"Failed to fetch server list from {api_url}")
        if e.code == 404:
            print("The servers.json API endpoint was not found.")
        
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
        print(f"Failed to connect to {api_url}")
        print("This often indicates a network issue or invalid URL.")
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        print("The server returned invalid JSON data.")
        
    except Exception as e:
        print(f"Unexpected error while fetching servers: {e}")
    
    return []


def get_server_urls(registry_url: str = "https://servers.openadp.org") -> List[str]:
    """
    Get just the server URLs (for backward compatibility).
    
    Args:
        registry_url: The base URL of the OpenADP server registry.
    
    Returns:
        List of server URLs (strings). Empty list if fetching fails.
    """
    servers = get_servers(registry_url)
    return [server['url'] for server in servers if 'url' in server]


def get_servers_by_country(registry_url: str = "https://servers.openadp.org") -> Dict[str, List[Dict[str, str]]]:
    """
    Get servers grouped by country.
    
    Args:
        registry_url: The base URL of the OpenADP server registry.
    
    Returns:
        Dictionary mapping country codes to lists of servers in that country.
    """
    servers = get_servers(registry_url)
    by_country = {}
    
    for server in servers:
        country = server.get('country', 'Unknown')
        if country not in by_country:
            by_country[country] = []
        by_country[country].append(server)
    
    return by_country


def get_fallback_servers() -> List[Dict[str, str]]:
    """
    Get a list of fallback servers to use if the registry is unavailable.
    
    Returns:
        List of hardcoded server information
    """
    return [
        {
            "url": "https://xyzzybill.openadp.org",
            "public_key": "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder1XyZzyBillServer12345TestKey",
            "country": "US"
        },
        {
            "url": "http://sky.openadp.org", 
            "public_key": "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder2SkyServerTestKey67890Demo",
            "country": "US"
        },
        {
            "url": "https://akash.network",
            "public_key": "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder3AkashNetworkTestKey111Demo", 
            "country": "CA"
        }
    ]


# Backward compatibility aliases
scrape_server_urls = get_server_urls  # Old function name


def main():
    """
    Test/demo function for server discovery.
    
    Attempts to fetch servers from the registry and displays the results,
    falling back to hardcoded servers if the registry is unavailable.
    """
    print("OpenADP Server Discovery")
    print("=" * 30)
    
    # Try to fetch servers from registry
    print("Fetching servers from registry...")
    servers = get_servers()
    
    if servers:
        print(f"✅ Successfully found {len(servers)} servers:")
        
        # Group by country for better display
        by_country = get_servers_by_country()
        for country, country_servers in by_country.items():
            country_flag = {'US': '🇺🇸', 'CA': '🇨🇦'}.get(country, '🏳️')
            print(f"\n  {country_flag} {country} ({len(country_servers)} servers):")
            for server in country_servers:
                print(f"    • {server['url']}")
                print(f"      Key: {server['public_key'][:32]}...")
                
    else:
        print("❌ Failed to fetch from registry, using fallback servers:")
        servers = get_fallback_servers()
        for i, server in enumerate(servers, 1):
            print(f"  {i}. {server['url']} ({server['country']})")
    
    print(f"\nTotal servers available: {len(servers)}")
    
    # Show countries for diversity analysis
    countries = set(server['country'] for server in servers)
    print(f"Countries represented: {', '.join(sorted(countries))}")


if __name__ == "__main__":
    main()
