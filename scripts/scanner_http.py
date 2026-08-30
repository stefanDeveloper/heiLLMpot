import sys
import http.client
from urllib.parse import urlparse

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner_http.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    parsed = urlparse(url)
    
    host = parsed.hostname
    port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)

    try:
        if parsed.scheme == "https":
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, context=context)
        else:
            conn = http.client.HTTPConnection(host, port)
        
        conn.request("GET", "/")
        res = conn.getresponse()
        
        headers = res.getheaders()
        print("Received HTTP Headers:")
        for k, v in headers:
            print(f"  {k}: {v}")
            
        print("\n--- Scanning for Evasion Indicators ---")
        
        # Check alphabetical sorting
        keys = [k.lower() for k, v in headers]
        if keys == sorted(keys):
            print("[DETECTED] The headers are perfectly alphabetized. This is a common indicator of cpp-httplib or a honeypot!")
            sys.exit(1)
        else:
            print("[SAFE] Header ordering looks organic.")
            
        # Check if 'server' and 'date' are near the top, which is typical of Nginx/Apache/IIS
        if len(keys) >= 2:
            top_two = keys[:2]
            if "server" in top_two or "date" in top_two:
                print("[SAFE] Server/Date headers are properly prioritized.")
            else:
                print("[WARNING] Expected Server or Date to be near the top of the headers.")
                
        print("\nResult: UNDETECTED")
        sys.exit(0)
        
    except Exception as e:
        print(f"Error connecting: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
