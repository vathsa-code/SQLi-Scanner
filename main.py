import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
from datetime import datetime
import tkinter as tk

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

def save_results(url, results, mode, log):
    domain = url.split("//")[-1].split("/")[0]
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"sqlivuln_{domain}_{mode}_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    log(f"[+] JSON Report saved as: {filename}")

def scan_sql_injection(url, mode="basic", gui_log=None, verdict_var=None):
    def log(msg):
        if gui_log:
            gui_log.insert(tk.END, msg + "\n")
            gui_log.see(tk.END)
        else:
            print(msg)

    try:
        session = requests.Session()
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.content, "html.parser")
        forms = soup.find_all("form")
        results = []

        if not forms:
            log(f"[!] No forms found on {url}")
            if verdict_var:
                verdict_var.set("No forms found")
            return

        log(f"[+] Found {len(forms)} form(s) on {url}")
        payloads = all_payloads.get(mode, [])

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)
            inputs = form.find_all(["input", "textarea"])
            input_names = [inp.get("name") for inp in inputs if inp.get("name")]

            for name in input_names:
                for payload in payloads:
                    data = {}
                    for field in input_names:
                        data[field] = payload if field == name else "test"

                    if method == "post":
                        res = session.post(form_url, data=data)
                    else:
                        res = session.get(form_url, params=data)

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
                            log(f"[!] SQLi in parameter '{name}'")
                            log(f"    ↪ Payload: {payload}")
                            log(f"    ↪ Replay: {attack}")
                            break

        if results:
            save_results(url, results, mode, log)
            log("\n[+] Scan Summary:")
            log(f"    - Total forms scanned: {len(forms)}")
            log(f"    - Total issues found: {len(results)}")
            affected_forms = list({r['url'] for r in results})
            log(f"    - Forms with vulnerabilities: {len(affected_forms)}")
            log(f"    - Vulnerable parameters: {list({r['vulnerable_parameter'] for r in results})}")
            if verdict_var:
                verdict_var.set("⚠️ Vulnerabilities found")
        else:
            log("[+] No SQL injection vulnerabilities detected.")
            if verdict_var:
                verdict_var.set("✅ No vulnerabilities found")

    except Exception as e:
        log(f"[!] Error scanning {url}: {e}")
        if verdict_var:
            verdict_var.set("❌ Scan failed")

if __name__ == "__main__":
    target = input("Enter URL to scan: ").strip()
    print("Mode options: basic | advanced")
    mode = input("Select payload mode (default = basic): ").strip().lower()
    if mode not in ["basic", "advanced"]:
        mode = "basic"

    if target:
        scan_sql_injection(target, mode)
    else:
        print("[!] URL is required.")
