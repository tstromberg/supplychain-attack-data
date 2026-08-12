import urllib.request
import urllib.error

urls = [
    "https://socket.dev/blog/duckdb-npm-account-compromised-in-continuing-supply-chain-attack",
    "https://jfrog.com/blog/new-compromised-packages-in-largest-npm-attack-in-history/",
    "https://www.sentinelone.com/blog/duckdb-npm-packages-compromised-in-supply-chain-attack/",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-59037"
]

for url in urls:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        urllib.request.urlopen(req)
        print(f"VALID: {url}")
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {url}")
    except Exception as e:
        print(f"Error {e}: {url}")
