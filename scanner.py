# scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
from datetime import datetime
import urllib3

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

with open("payloads.json", "r") as f:
    all_payloads = json.load(f)

error_signatures = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "mysql_fetch_array()",
    "syntax error",
    "ORA-01756",
    "SQLite3::query()"
]

def suggest_fix(payload):
    if "union select" in payload.lower():
        return "Use parameterized queries to prevent UNION-based injection."
    elif "sleep" in payload.lower() or "benchmark" in payload.lower():
        return "Avoid evaluating user input directly. Use server-side validation."
    elif "or" in payload.lower() and "=" in payload:
        return "Sanitize input and use prepared statements to avoid boolean-based injection."
    elif "xp_cmdshell" in payload.lower() or "exec" in payload.lower():
        return "Disable dangerous SQL procedures and use least-privilege accounts."
    elif "drop table" in payload.lower():
        return "Validate all input and avoid executing raw queries."
    else:
        return "Use parameterized queries and strict input validation."

def generate_attack_replay(url, method, data):
    if method.lower() == "get":
        params = "&".join([f"{k}={v}" for k, v in data.items()])
        return f"{url}?{params}"
    else:
        payload_str = " -d \"" + "&".join([f"{k}={v}" for k, v in data.items()]) + "\""
        return f"curl -X POST \"{url}\"{payload_str}"

def scan_sql_injection(url, mode="basic"):
    output_logs = []
    results = []
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml",
        "Connection": "keep-alive"
    }

    try:
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=10, verify=False)

        if response.status_code != 200:
            output_logs.append(f"[!] Failed to access {url} - Status Code: {response.status_code}")
            return output_logs, None

        soup = BeautifulSoup(response.content, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            output_logs.append(f"[!] No forms found on {url}")
            return output_logs, None

        output_logs.append(f"[+] Found {len(forms)} form(s) on {url}")
        payloads = all_payloads.get(mode, [])

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)
            inputs = form.find_all(["input", "textarea", "select"])
            input_names = [inp.get("name") for inp in inputs if inp.get("name")]

            for name in input_names:
                for payload in payloads:
                    data = {}
                    for field in input_names:
                        data[field] = payload if field == name else "test"

                    if method == "post":
                        res = session.post(form_url, data=data, headers=headers, verify=False)
                    else:
                        res = session.get(form_url, params=data, headers=headers, verify=False)

                    for error in error_signatures:
                        if error.lower() in res.text.lower():
                            attack = generate_attack_replay(form_url, method, data)
                            result = {
                                "url": form_url,
                                "method": method.upper(),
                                "vulnerable_parameter": name,
                                "payload": payload,
                                "error": error,
                                "suggestion": suggest_fix(payload),
                                "attack_replay": attack
                            }
                            results.append(result)
                            output_logs.append(f"[!] SQLi in parameter '{name}'")
                            output_logs.append(f"    ↪ Payload: {payload}")
                            output_logs.append(f"    ↪ Replay: {attack}")
                            break

        if results:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            domain = url.split("//")[-1].split("/")[0]
            filename = f"sqlivuln_{domain}_{mode}_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump(results, f, indent=4)
            output_logs.append(f"[+] JSON Report saved as: {filename}")

            return output_logs, filename
        else:
            output_logs.append("[+] No SQL injection vulnerabilities detected.")
            return output_logs, None

    except Exception as e:
        output_logs.append(f"[!] Error scanning {url}: {str(e)}")
        return output_logs, None
