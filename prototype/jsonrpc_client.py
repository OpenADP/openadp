import json
import ssl
import urllib.parse
import urllib.request

import scrape

def send_jsonrpc_request(url, method, params, request_id=1):
    """
    Sends a JSON-RPC 2.0 request over HTTPS.

    Args:
        url (str): The HTTPS URL of the JSON-RPC server.
        method (str): The JSON-RPC method to call.
        params (dict or list): The parameters for the method.
        request_id (int or str, optional): The ID of the request. Defaults to 1.

    Returns:
        dict: The parsed JSON response from the server, or None on error.
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    payload = {
        'jsonrpc': '2.0',
        'method': method,
        'params': params,
        'id': request_id
    }

    try:
        # Encode the payload to JSON
        json_payload = json.dumps(payload).encode('utf-8')

        # Create a default SSL context. This is generally secure enough
        # for most common use cases, but for very strict security
        # requirements, you might want to customize it.
        # Ubuntu 24.04's default SSL context should be up-to-date.
        context = ssl.create_default_context()

        # Create a Request object
        req = urllib.request.Request(url, data=json_payload, headers=headers, method='POST')

        # Open the URL and send the request
        with urllib.request.urlopen(req, context=context) as response:
            # Read the response
            response_body = response.read().decode('utf-8')

            # Parse the JSON response
            json_response = json.loads(response_body)
            return json_response

    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def testServerEcho(rpc_url):
    print("Sending Echo request to", rpc_url)
    method_name = "Echo"
    params_data = ["Hello from Python!"]
    response = send_jsonrpc_request(rpc_url, method_name, params_data, request_id="my_echo_call_123")

    if response:
        print("Response received:")
        print(json.dumps(response, indent=2))
        if 'error' in response:
            print(f"JSON-RPC Error: {response['error']}")
        elif 'result' in response:
            print(f"JSON-RPC Result: {response['result']}")
        else:
            print("Response does not contain 'result' or 'error' (might not be a JSON-RPC response).")
    else:
        print("Failed to get a response.")

if __name__ == "__main__":
    servers = [
        "https://xyzzybill.openadp.org",
        "https://sky.openadp.org"
    ]
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
    servers = scrape.scrape_server_urls()
    if not servers:
        print("Unable to scrape OpenADP servers, using default servers instead")
        servers = [
            "https://xyzzybill.openadp.org",
            "https://sky.openadp.org"
        ]
    for rpc_url in servers:
        testServerEcho(rpc_url)
