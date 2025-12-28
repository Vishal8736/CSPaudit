#!/usr/bin/env python3
"""
Tool Name: CSPAudit (Advanced Security Chain Analyzer)
Developed by: Vishal ❤️ Subhi
Version: 5.0 (Fully Updated & Autonomous)
Purpose: Multi-page CSP scanning, Attack Chain mapping, and Risk Assessment.
"""

import sys, json, urllib.request, urllib.parse, ssl, argparse, os, threading, queue, csv, socket
from collections import defaultdict
from datetime import datetime

# --- UI & Branding ---
class Style:
    RED, GREEN, YELLOW, BLUE, CYAN = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m'
    BOLD, UNDERLINE, RESET = '\033[1m', '\033[4m', '\033[0m'

def log(msg, color=Style.RESET):
    print(f"{color}{msg}{Style.RESET}")

def print_banner():
    banner = f"""
    {Style.CYAN}{Style.BOLD}====================================================
    {Style.GREEN}   _____  _____ _____                _ _ _ 
    {Style.GREEN}  / ____|/ ____|  __ \              | (_) |
    {Style.GREEN} | |    | (___ | |__) |__ _ _   _ __| |_| |_ 
    {Style.GREEN} | |     \___ \|  ___/ _` | | | | _` | | | __|
    {Style.GREEN} | |____ ____) | |  | (_| | |_| | (_| | | | |_ 
    {Style.GREEN}  \_____|_____/|_|   \__,_|\__,_|\__,_|_|_|\__|
                                            
    {Style.CYAN}{Style.BOLD}      CSPAudit - Advanced Chain Analyzer
    {Style.YELLOW}{Style.BOLD}      Crafted with ❤️ by: Vishal & Subhi
    {Style.CYAN}{Style.BOLD}===================================================={Style.RESET}
    """
    print(banner)

# --- Core Engine ---
class CSPAudit:
    def __init__(self, outdir='reports', timeout=15):
        self.outdir = outdir
        self.timeout = timeout
        os.makedirs(outdir, exist_ok=True)
        self.csv_file = os.path.join(outdir, 'cspaudit_summary.csv')

    def validate_and_fetch(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urllib.parse.urlparse(url)
        try:
            socket.gethostbyname(parsed.hostname)
        except:
            return None, None, f"DNS Resolution Failed for {parsed.hostname}"

        try:
            # Handling SSL for local & production environments
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'CSPAudit-Scanner/5.0 (Vishal-Subhi)'})
            with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
                return resp.getcode(), dict(resp.getheaders()), None
        except Exception as e:
            return None, None, str(e)

    def analyze_csp(self, csp_text):
        directives = {}
        findings = []
        if not csp_text: 
            findings.append({'dir': 'Global', 'risk': 'CRITICAL', 'msg': 'CSP Header is completely MISSING!'})
            return directives, findings
        
        parts = [p.strip() for p in csp_text.split(';') if p.strip()]
        for p in parts:
            pieces = p.split(None, 1)
            name = pieces[0].lower()
            val = pieces[1] if len(pieces) > 1 else ""
            directives[name] = val
            
            # Smart Risk Detection
            if "'unsafe-inline'" in val: findings.append({'dir': name, 'risk': 'CRITICAL', 'msg': 'Insecure inline scripts/styles allowed'})
            if "'unsafe-eval'" in val: findings.append({'dir': name, 'risk': 'HIGH', 'msg': 'JS eval() enabled (high risk)'})
            if '*' in val: findings.append({'dir': name, 'risk': 'HIGH', 'msg': 'Wildcard origin allows unauthorized domains'})
            if 'data:' in val: findings.append({'dir': name, 'risk': 'MEDIUM', 'msg': 'Data URIs allowed (common XSS vector)'})
        
        return directives, findings

    def map_attack_chains(self, csp_findings, headers):
        chains = []
        hdrs = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Logic: If CSP is weak AND other headers are missing, it's a chain.
        has_critical_csp = any(f['risk'] == 'CRITICAL' for f in csp_findings)
        
        # 1. XSS Execution Chain
        if has_critical_csp and 'nosniff' not in hdrs.get('x-content-type-options', ''):
            chains.append({'name': 'XSS Execution Chain', 'impact': 'CRITICAL', 'desc': 'CSP bypass possible via MIME sniffing.'})
        
        # 2. Clickjacking Chain
        if 'frame-ancestors' not in str(csp_findings) and not hdrs.get('x-frame-options'):
            chains.append({'name': 'UI Redressing Chain', 'impact': 'HIGH', 'desc': 'No framing protection; site can be hijacked in iframes.'})
            
        # 3. Protocol Downgrade
        if not hdrs.get('strict-transport-security'):
            chains.append({'name': 'Transport Security Chain', 'impact': 'MEDIUM', 'desc': 'Missing HSTS; vulnerable to SSL Stripping.'})

        return chains

    def get_risk_rating(self, chains, findings):
        score = len(chains) * 25 + len(findings) * 10
        if score >= 70: return "CRITICAL", Style.RED
        if score >= 40: return "HIGH", Style.RED
        if score >= 20: return "MEDIUM", Style.YELLOW
        return "LOW", Style.GREEN

    def run_audit(self, url):
        log(f"\n[*] Initiating Audit: {url}", Style.CYAN)
        code, headers, err = self.validate_and_fetch(url)
        
        if err:
            log(f"[-] Audit Aborted: {err}", Style.RED)
            return

        csp_raw = headers.get('Content-Security-Policy', '') or headers.get('Content-Security-Policy-Report-Only', '')
        directives, findings = self.analyze_csp(csp_raw)
        chains = self.map_attack_chains(findings, headers)
        rating, rate_color = self.get_risk_rating(chains, findings)

        # Output Dashboard
        log(f"[+] Status Code: {code}", Style.GREEN)
        log(f"[!] Risk Rating: {rating}", rate_color + Style.BOLD)
        
        if findings:
            log("\n--- Vulnerabilities Detected ---", Style.YELLOW + Style.UNDERLINE)
            for f in findings:
                log(f"  [{f['risk']}] {f['dir']}: {f['msg']}", Style.YELLOW)

        if chains:
            log("\n--- Attack Chain Analysis ---", Style.RED + Style.UNDERLINE)
            for c in chains:
                log(f"  [CHAIN] {c['name']} (Impact: {c['impact']})", Style.RED)
                log(f"          Reason: {c['desc']}", Style.RESET)

        self.save_data(url, rating, findings, chains)
        log(f"\n[✓] Audit Complete for {url}", Style.GREEN)

    def save_data(self, url, rating, findings, chains):
        domain = urllib.parse.urlparse(url).netloc.replace(':', '_')
        report_path = f"{self.outdir}/{domain}_audit.json"
        
        with open(report_path, 'w') as f:
            json.dump({'target': url, 'auditor': 'Vishal & Subhi', 'rating': rating, 'findings': findings, 'chains': chains}, f, indent=4)
        
        file_exists = os.path.isfile(self.csv_file)
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Date', 'Target', 'Auditor', 'Risk_Rating', 'Issue_Count'])
            writer.writerow([datetime.now().strftime('%Y-%m-%d'), url, 'Vishal & Subhi', rating, len(findings)])

# --- Main CLI ---
def main():
    print_banner()
    parser = argparse.ArgumentParser(description='CSPAudit - Advanced Chain Analyzer (by Vishal ❤️ Subhi)')
    parser.add_argument('-t', '--target', help='Single URL to audit')
    parser.add_argument('-f', '--file', help='List of URLs for batch audit')
    parser.add_argument('-T', '--threads', type=int, default=5, help='Audit threads (Default: 5)')
    args = parser.parse_args()

    audit_engine = CSPAudit()

    if args.target:
        audit_engine.run_audit(args.target)
    elif args.file:
        q = queue.Queue()
        try:
            with open(args.file, 'r') as f:
                for line in f: q.put(line.strip())
        except:
            log("[-] Error: File not found!", Style.RED)
            return
        
        def auditor_task():
            while not q.empty():
                target = q.get()
                audit_engine.run_audit(target)
                q.task_done()
        
        for _ in range(min(args.threads, q.qsize())):
            threading.Thread(target=auditor_task, daemon=True).start()
        q.join()
        log("\n[***] All batch audits finished successfully.", Style.GREEN + Style.BOLD)
    else:
        parser.print_help()

    log(f"\n{Style.CYAN}Thank you for using CSPAudit! - Vishal ❤️ Subhi{Style.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n[-] Process interrupted by user.", Style.RED)
  
