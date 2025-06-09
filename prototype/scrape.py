import urllib.request
import urllib.error # Import urllib.error to catch specific HTTP errors

def scrape_server_urls(url="https://servers.openadp.org"):
    """
    Scrapes a URL where server URLs are listed one per line and returns them as a list.
    Includes a User-Agent header to potentially bypass 403 Forbidden errors.

    Args:
        url (str): The URL to scrape. Defaults to "https://servers.openadp.org".

    Returns:
        list: A list of server URLs (strings).
    """
    server_urls = []
    try:
        # Create a Request object and add a User-Agent header
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )
        with urllib.request.urlopen(req) as response:
            for line in response:
                decoded_line = line.decode('utf-8').strip()
                if decoded_line:  # Only add non-empty lines
                    # Total hack for now: don't include lines starting with <, because they are tags.
                    if decoded_line[0] != "<":
                        server_urls.append(decoded_line)
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
        print(f"Check if the URL is correct or if the server explicitly blocks automated requests.")
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
        print(f"This often indicates a network issue or an invalid URL.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return server_urls

if __name__ == "__main__":
    servers = scrape_server_urls()
    if servers:
        print("Scraped Server URLs:")
        for server_url in servers:
            print(server_url)
    else:
        print("No server URLs found or an error occurred during scraping.")
