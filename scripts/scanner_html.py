import sys
import urllib.request
import ssl

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner_html.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx) as response:
            html = response.read().decode('utf-8', errors='ignore')
            
            print("--- HTML Body Analysis ---")
            print(f"Response length: {len(html)} bytes")
            
            # Check for honeypot artifact
            if "<!-- generated" in html:
                print("[DETECTED] Honeypot generation artifact found in HTML: '<!-- generated ... -->'")
                sys.exit(1)
            else:
                print("[SAFE] No generated honeypot artifacts found.")
                
            # Check for basic HTML validity so it doesn't look like an empty stub
            if "<html" in html.lower() and "<body" in html.lower():
                print("[SAFE] HTML payload contains valid structure tags.")
            else:
                print("[WARNING] Response doesn't look like a full HTML document.")
                
            print("\nResult: UNDETECTED")
            sys.exit(0)
            
    except urllib.error.URLError as e:
        if hasattr(e, 'read'):
            # Some error pages (404, etc.) are still HTML
            html = e.read().decode('utf-8', errors='ignore')
            if "<!-- generated" in html:
                print("[DETECTED] Honeypot generation artifact found in error page HTML!")
                sys.exit(1)
            else:
                print("[SAFE] Error page served with no honeypot artifacts.")
                print("\nResult: UNDETECTED")
                sys.exit(0)
        else:
            print(f"Connection failed: {e}")
            sys.exit(2)

if __name__ == "__main__":
    main()
