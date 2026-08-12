import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

urls = [
"https://vertexaisearch.cloud.google.com/grounding-api-redirect/AUZIYQEprQp3miXQ3KC-sBmOQ90WlcHNduWtoIa6dJHcGoNqmOn-bZgBRzViBHldkbtzfkK_54-M8T_W8hNt1EV73OPl4Vam-scTxt2inYlI2O-icgV54bQ164KjaDKW61VBavrGZKR57SAv3a3LvZQ8tvuavMAbKqGZ4YIgCNwb",
"https://vertexaisearch.cloud.google.com/grounding-api-redirect/AUZIYQHX96VwQDi7tdqapOMmBNNYJbSFshjlw83B3rB9TkbCDPoZ247z-IT_psYM3q6zOOVsgaI9LhQW2s7TT4UYR4XSgEIgq-Bd0z4m-bAVf6z2MP7jPqOnBknv0010PQLxy3HYzI85OJB3ugJ2jc8CQKYMTn7jeIQ7KxVDope7G1V3sa_VJyy8D2diFH2FD-mE4YDD2omZ8yHPSfz2lgeD",
"https://vertexaisearch.cloud.google.com/grounding-api-redirect/AUZIYQGdWye7KpxThyu2HqqSZWXLoXN6p8Bara7r5ZLx9hsqvcRxPJpPzCgXmV6mfQgxEbtkZjoMXJELSroNlfGDvQi_MUIwSBhI8KUtfervMnA4uiu-B8cKm82nQ5H-qXATY7bSYugyIm8WmIzjuyrUGIQA2JFNcVvo9BaDIXNCojoxkwWzgUVbskofEEZKqXbUp-ga5txKs9yUcDW26KRVCaIqIDX0OEO_TqyCE05hqj4SJkWmAluIXO9jw93I0NrC"
]

for url in urls:
    try:
        req = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Mozilla/5.0'})
        resp = urllib.request.urlopen(req, context=ctx)
        print(resp.url)
    except Exception as e:
        print(f"Error {e} for {url}")
