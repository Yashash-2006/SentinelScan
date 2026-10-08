import argparse, json
from backend.scanner.engine import Scanner

def main():
    p=argparse.ArgumentParser(description="SentinelScan lightweight web vulnerability scanner")
    p.add_argument("url")
    p.add_argument("--i-have-permission", action="store_true")
    p.add_argument("-o","--output",default="report.json")
    p.add_argument("--delay",type=float,default=0.25)
    p.add_argument("--max-pages",type=int,default=30)
    p.add_argument("--timeout",type=float,default=8)
    a=p.parse_args()
    if not a.i_have_permission:
        p.error("Refusing to scan. Add --i-have-permission for an authorized target.")
    s=Scanner(a.url,delay=max(0,a.delay),max_pages=max(1,min(a.max_pages,200)),
              timeout=max(1,min(a.timeout,30)))
    report=s.run()
    with open(a.output,"w",encoding="utf-8") as f: json.dump(report,f,indent=2)
    print("\nSentinelScan complete")
    print("Target:",report["target"])
    print("Pages:",report["pages_crawled"])
    print("Findings:",report["summary"]["total"])
    print("Severity:",report["summary"]["by_severity"])
    print("Report:",a.output)

if __name__=="__main__":
    main()
