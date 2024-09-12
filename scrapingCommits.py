import os
from dotenv import load_dotenv
import requests as r
from github import Github
import json
load_dotenv()
api_url_commits = "https://api.github.com/search/commits"
gh_apikey = os.getenv('TOKEN_GITHUB')
# Autenticarse con tu token personal

keywords = ["buffer overflow","denial of service", "dos", "XXE","vuln","CVE","XSS","NVD","malicious","cross site","exploit","directory traversal","rce","remote code execution","XSRF","cross site request forgery","click jack","clickjack","session fixation","cross origin","infinite loop","brute force","buffer overflow","cache overflow","command injection","cross frame scripting","csv injection","eval injection","execution after redirect","format string","path disclosure","function injection","replay attack","session hijacking","smurf","sql injection","flooding","tampering","sanitize","sanitise", "unauthorized", "unauthorised"]

prefixes =["prevent", "fix", "attack", "protect", "issue", "correct", "update", "improve", "change", "check", "malicious", "insecure", "vulnerable", "vulnerability"]

# Realiza una búsqueda global de commits
query = "fix vulnerability"
print(gh_apikey)
resuls = []
for k in keywords :
    for p in prefixes :
        query = k+"+"+p
        result = r.get(url = api_url_commits,headers={"Authorization":f'Bearer {gh_apikey}',"X-GitHub-Api-Version":"2022-11-28"} ,params={'q':query})
        try :
            print(result.status_code)
            print(result.json().get('total_count'))
        except :
            pass
        