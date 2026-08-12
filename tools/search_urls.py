import urllib.request
import re

query = "DuckDB npm account compromised in continuing supply chain attack"
url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
req = urllib.request.Request(
    url, 
    data=None, 
    headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
    }
)

try:
    response = urllib.request.urlopen(req)
    html = response.read().decode('utf-8')
    links = re.findall(r'href="([^"]+)"', html)
    for link in links:
        if link.startswith('http') and 'duckduckgo' not in link:
            print(link)
except Exception as e:
    print(e)
