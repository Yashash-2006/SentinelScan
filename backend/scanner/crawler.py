import time
from urllib.parse import urljoin, urlparse, urldefrag
import requests
from bs4 import BeautifulSoup

class Crawler:
    def __init__(self,start_url,session,delay=0.25,max_pages=30,timeout=8,progress=None):
        self.start_url=start_url; self.session=session; self.delay=delay
        self.max_pages=max_pages; self.timeout=timeout; self.progress=progress or (lambda x:None)
    def same_site(self,url):
        a=urlparse(self.start_url); b=urlparse(url)
        return b.scheme in ("http","https") and b.netloc==a.netloc
    def crawl(self):
        queue=[self.start_url]; seen=set(); pages=[]
        while queue and len(pages)<self.max_pages:
            url=urldefrag(queue.pop(0))[0]
            if url in seen or not self.same_site(url): continue
            seen.add(url)
            try: r=self.session.get(url,timeout=self.timeout,allow_redirects=True)
            except requests.RequestException: continue
            if "text/html" not in r.headers.get("Content-Type",""): continue
            soup=BeautifulSoup(r.text,"html.parser")
            pages.append({"url":r.url,"response":r,"soup":soup})
            for a in soup.find_all("a",href=True):
                nxt=urldefrag(urljoin(r.url,a["href"]))[0]
                if self.same_site(nxt) and nxt not in seen and nxt not in queue: queue.append(nxt)
            self.progress({"progress":int(len(pages)/self.max_pages*100),"stage":f"Crawled {len(pages)} page(s)"})
            time.sleep(self.delay)
        return pages
