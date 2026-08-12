import urllib.request
import re

query = "duckdb+npm+compromised"
url = f"https://duckduckgo.com/html/?q={query}"

try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    response = urllib.request.urlopen(req)
    html = response.read().decode('utf-8')
    links = re.findall(r'href="([^"]+)"', html)
    for link in links:
        if link.startswith('http') and 'duckduckgo' not in link:
            print(link)
except Exception as e:
    print(f"Failed: {e}")
