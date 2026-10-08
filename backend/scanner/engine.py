import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from .crawler import Crawler
from .checks import CHECKS

ORDER={"Critical":4,"High":3,"Medium":2,"Low":1,"Info":0}
USER_AGENT="SentinelScan/1.0 (authorized educational security scanner)"

class Scanner:
    def __init__(self,target,delay=0.25,max_pages=30,timeout=8,progress=None):
        p=urlparse(target)
        if p.scheme not in ("http","https") or not p.netloc: raise ValueError("Invalid target URL")
        self.target=target; self.delay=delay; self.max_pages=max_pages; self.timeout=timeout
        self.progress=progress or (lambda x:None)
        self.session=requests.Session()
        self.session.headers.update({"User-Agent":USER_AGENT})
    def run(self,progress=None):
        progress=progress or self.progress
        started=datetime.now(timezone.utc).isoformat()
        pages=Crawler(self.target,self.session,self.delay,self.max_pages,self.timeout,progress).crawl()
        findings=[]; seen=set()
        for i,page in enumerate(pages):
            c={"response":page["response"],"soup":page["soup"],"url":page["url"],
               "session":self.session,"timeout":self.timeout}
            for check in CHECKS:
                try:
                    for f in check(c):
                        key=(f.title,f.url,f.check,f.evidence)
                        if key not in seen:
                            seen.add(key); findings.append(f.to_dict())
                except Exception:
                    continue
            progress({"progress":50+int((i+1)/max(1,len(pages))*50),
                      "stage":f"Checked {i+1}/{len(pages)} page(s)"})
            time.sleep(self.delay)
        counts=Counter(x["severity"] for x in findings)
        sev={k:counts.get(k,0) for k in ("Critical","High","Medium","Low","Info")}
        return {"scanner":"SentinelScan 1.0","target":self.target,"started":started,
                "finished":datetime.now(timezone.utc).isoformat(),"pages_crawled":len(pages),
                "summary":{"total":len(findings),"by_severity":sev},
                "findings":sorted(findings,key=lambda x:(-ORDER.get(x["severity"],0),x["title"])),
                "limitations":["A09 and A10 are not safely testable remotely by this lightweight scanner.",
                               "Authenticated-only, business-logic, blind injection, SSRF and browser-state issues may be missed.",
                               "Findings are indicators and should be manually validated."]}
