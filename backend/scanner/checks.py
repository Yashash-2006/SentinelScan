import re
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse
from .models import Finding

def F(title,severity,owasp,evidence,url,fix,check):
    return Finding(title,severity,owasp,evidence[:500],url,fix,check)

def check_transport(c):
    r,u=c["response"],c["url"]; out=[]
    if u.lower().startswith("http://"):
        out.append(F("HTTP is used instead of HTTPS","Medium","A02 Cryptographic Failures",
            "Target URL uses http://",u,"Serve the application over HTTPS and redirect HTTP to HTTPS.","transport"))
    if u.lower().startswith("https://") and "Strict-Transport-Security" not in r.headers:
        out.append(F("HSTS header is missing","Low","A02 Cryptographic Failures",
            "Strict-Transport-Security was not present.",u,"Add a suitable HSTS policy after validating HTTPS deployment.","hsts"))
    return out

def check_headers(c):
    r,u=c["response"],c["url"]; out=[]
    required=[
        ("Content-Security-Policy","Missing Content-Security-Policy","Medium","Define a restrictive CSP to reduce script injection impact."),
        ("X-Frame-Options","Missing X-Frame-Options","Low","Use CSP frame-ancestors and/or X-Frame-Options to control framing."),
        ("X-Content-Type-Options","Missing X-Content-Type-Options","Low","Set X-Content-Type-Options: nosniff.")
    ]
    for h,title,severity,fix in required:
        if h not in r.headers:
            out.append(F(title,severity,"A05 Security Misconfiguration",f"{h} was not present in the response.",u,fix,"security_headers"))
    return out

def check_server(c):
    r,u=c["response"],c["url"]; out=[]
    for h in ("Server","X-Powered-By"):
        if h in r.headers and r.headers[h].strip():
            out.append(F(f"{h} version/technology disclosure","Low","A06 Vulnerable and Outdated Components",
                f"{h}: {r.headers[h]}",u,"Minimize unnecessary technology/version disclosure.","server_disclosure"))
    return out

def check_cookies(c):
    r,u=c["response"],c["url"]; out=[]
    for cookie in r.headers.get("Set-Cookie","").split(","):
        if not cookie.strip(): continue
        low=cookie.lower(); name=cookie.split("=",1)[0].strip()
        if "secure" not in low:
            out.append(F("Cookie missing Secure attribute","Medium","A07 Identification and Authentication Failures",
                f"{name} cookie does not contain Secure.",u,"Set Secure on cookies that should only travel over HTTPS.","cookies"))
        if "httponly" not in low:
            out.append(F("Cookie missing HttpOnly attribute","Low","A07 Identification and Authentication Failures",
                f"{name} cookie does not contain HttpOnly.",u,"Set HttpOnly on session/authentication cookies where client access is unnecessary.","cookies"))
        if "samesite" not in low:
            out.append(F("Cookie missing SameSite attribute","Low","A07 Identification and Authentication Failures",
                f"{name} cookie does not contain SameSite.",u,"Set an appropriate SameSite policy for session cookies.","cookies"))
    return out

def check_cors(c):
    try:
        r=c["session"].get(c["url"],headers={"Origin":"https://sentinelscan.invalid"},
                            timeout=c["timeout"],allow_redirects=False)
    except Exception: return []
    acao=r.headers.get("Access-Control-Allow-Origin","").strip()
    if acao=="*":
        return [F("Wildcard CORS policy","Medium","A01 Broken Access Control",
            "Access-Control-Allow-Origin: *",c["url"],"Restrict allowed origins to trusted origins.","cors")]
    if acao=="https://sentinelscan.invalid":
        return [F("CORS reflects arbitrary Origin","High","A01 Broken Access Control",
            "Test Origin was reflected in Access-Control-Allow-Origin.",c["url"],
            "Use an explicit allowlist of trusted origins and validate Origin values.","cors")]
    return []

def check_xss(c):
    out=[]; marker="SENTINELSCAN_XSS_MARKER"
    for form in c["soup"].find_all("form"):
        if (form.get("method") or "get").lower()!="get": continue
        action=urljoin(c["url"],form.get("action") or c["url"]); params={}
        for inp in form.find_all(["input","textarea"]):
            if inp.get("name"): params[inp["name"]]=marker
        if not params: continue
        try:
            r=c["session"].get(action,params=params,timeout=c["timeout"],allow_redirects=False)
            if marker in r.text:
                out.append(F("Reflected input marker detected","Medium","A03 Injection",
                    f"Harmless marker '{marker}' was reflected.",r.url,
                    "Contextually encode untrusted output and validate/sanitize input; manually confirm before treating as XSS.",
                    "reflected_marker"))
        except Exception: pass
    return out

def check_sql(c):
    qs=parse_qsl(urlparse(c["url"]).query,keep_blank_values=True)
    if not qs: return []
    parsed=urlparse(c["url"]); changed=[(k,(v+"'" if v else "'")) for k,v in qs]
    probe=urlunparse(parsed._replace(query=urlencode(changed)))
    sigs=("you have an error in your sql syntax","sqlite error","sqlstate","ora-009","postgresql query failed","mysql_fetch")
    try: body=c["session"].get(probe,timeout=c["timeout"],allow_redirects=False).text.lower()
    except Exception: return []
    hits=[s for s in sigs if s in body]
    if hits:
        return [F("Database error signature after harmless quote probe","High","A03 Injection",
            "Response contained: "+", ".join(hits),probe,
            "Use parameterized queries/prepared statements and avoid exposing database errors.","sql_error_probe")]
    return []

def check_sri(c):
    out=[]; host=urlparse(c["url"]).netloc
    for script in c["soup"].find_all("script",src=True):
        src=urljoin(c["url"],script["src"]); p=urlparse(src)
        if p.netloc and p.netloc!=host and not script.get("integrity"):
            out.append(F("External script without Subresource Integrity","Low","A08 Software and Data Integrity Failures",
                f"External script: {src}",c["url"],"Use SRI integrity hashes for externally hosted scripts where appropriate.","sri"))
    return out

def check_exposed(c):
    out=[]; base=c["url"].rstrip("/")+"/"
    paths={".env":("dotenv-style",("db_password","database_url","secret_key","api_key")),
           ".git/HEAD":("git metadata",("ref: refs/")),
           "phpinfo.php":("phpinfo",("php version","phpinfo()","configuration"))}
    for path,(label,sigs) in paths.items():
        target=urljoin(base,path)
        try: r=c["session"].get(target,timeout=c["timeout"],allow_redirects=False); body=r.text[:10000].lower()
        except Exception: continue
        if r.status_code==200 and any(s in body for s in sigs):
            out.append(F(f"Potentially exposed {label}","High","A05 Security Misconfiguration",
                f"{target} returned content matching an exposed-file signature.",target,
                "Remove exposed deployment artifacts from web-accessible paths.","exposed_paths"))
    return out

def check_directory(c):
    body=c["response"].text[:20000].lower()
    if any(s in body for s in ("index of /","directory listing for","<title>index of")):
        return [F("Directory listing detected","Medium","A05 Security Misconfiguration",
            "Response resembles a web server directory index.",c["url"],"Disable directory indexing unless explicitly required.","directory_listing")]
    return []

def check_login_http(c):
    if c["url"].lower().startswith("http://") and c["soup"].find("input",{"type":re.compile("^password$",re.I)}):
        return [F("Password form served over HTTP","High","A07 Identification and Authentication Failures",
            "A password input was found on an HTTP page.",c["url"],"Serve authentication flows exclusively over HTTPS.","login_transport")]
    return []

CHECKS=[check_transport,check_headers,check_server,check_cookies,check_cors,check_xss,
        check_sql,check_sri,check_exposed,check_directory,check_login_http]
