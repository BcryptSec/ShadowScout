#!/usr/bin/env python3
import asyncio
import aiohttp
import argparse
import re
import json
import sys
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# Purple (Magenta) and White ASCII Banner
BANNER = rf"""
{Fore.MAGENTA}{Style.BRIGHT}   _____ _               _                {Fore.WHITE}v1.4.6
{Fore.MAGENTA}{Style.BRIGHT}  / ____| |             | |               
{Fore.MAGENTA}{Style.BRIGHT} | (___ | |__   __ _  __| | _____      __ 
{Fore.MAGENTA}{Style.BRIGHT}  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / 
{Fore.MAGENTA}{Style.BRIGHT}  ____) | | | | (_| | (_| | (_) \ V  V /  
{Fore.MAGENTA}{Style.BRIGHT} |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   
{Fore.WHITE}{Style.BRIGHT}  / ____|               | |          
{Fore.WHITE}{Style.BRIGHT} | (___   ___ ___  _   _| |_         
{Fore.WHITE}{Style.BRIGHT}  \___ \ / __/ _ \| | | | __|        
{Fore.WHITE}{Style.BRIGHT}  ____) | (_| (_) | |_| | |_         
{Fore.WHITE}{Style.BRIGHT} |_____/ \___\___/ \__,_|\__|        

          {Fore.CYAN}https://github.com/BcryptSec
"""

class ShadowScout:
    def __init__(self, target, deep=False, match_codes=None, output_file=None, threads=5):
        self.target = target.rstrip('/')
        self.deep = deep
        self.match_codes = match_codes or [200, 301, 302, 403]
        self.output_file = output_file
        self.semaphore = asyncio.Semaphore(threads)
        self.found_endpoints = set()
        self.risk_points = 0
        
        self.severity_map = {"CRITICAL": 50, "HIGH": 20, "MEDIUM": 10, "LOW": 2}
        self.risk_paths = {
            "/.env": ("CRITICAL", "Environment file leakage"),
            "/.git/config": ("HIGH", "Git source metadata"),
            "/.aws/credentials": ("CRITICAL", "Cloud access keys"),
            "/phpinfo.php": ("MEDIUM", "Server config disclosure"),
            "/robots.txt": ("LOW", "Path disclosure")
        }
        self.final_report = {"target": self.target, "start_time": str(datetime.now()), "findings": []}

    async def fetch(self, session, url, is_risk_path=False):
        async with self.semaphore:
            try:
                # Disabling SSL verification to avoid crashes on sites with expired certs (common in bug hunting)
                async with session.get(url, timeout=10, allow_redirects=False, ssl=False) as response:
                    status = response.status
                    color = Fore.GREEN if status == 200 else Fore.YELLOW if status in [301, 302] else Fore.RED
                    
                    if status in self.match_codes:
                        print(f"[{color}{status}{Style.RESET_ALL}] {url}")
                        
                        if is_risk_path and status == 200:
                            path = "/" + url.split('/')[-1]
                            if path in self.risk_paths:
                                sev, desc = self.risk_paths[path]
                                self.risk_points += self.severity_map[sev]
                                self.final_report["findings"].append({
                                    "url": url, 
                                    "status": status, 
                                    "severity": sev, 
                                    "desc": desc
                                })
                    return await response.text() if status == 200 else None
            except: return None

    async def deep_analyze_js(self, session, js_url):
        content = await self.fetch(session, js_url)
        if content:
            # Regex for endpoint discovery in JS strings
            endpoints = re.findall(r'\"(/[a-zA-Z0-9._\-/]+)\"|\'(/[a-zA-Z0-9._\-/]+)\'', content)
            for ep in endpoints:
                path = ep[0] if ep[0] else ep[1]
                if len(path) > 4: self.found_endpoints.add(path)
            
            # Common Secret Patterns
            secrets = {
                "AWS_KEY": r'AKIA[0-9A-Z]{16}', 
                "GOOGLE_API": r'AIza[0-9A-Za-z-_]{35}'
            }
            for name, pattern in secrets.items():
                if re.search(pattern, content):
                    print(f"[{Fore.LIGHTRED_EX}SECRET{Style.RESET_ALL}] {name} found in {js_url}")
                    self.risk_points += self.severity_map["CRITICAL"]

    async def start(self):
        print(BANNER)
        print(f"{Fore.CYAN}[*] Target: {self.target} | Threads: {self.semaphore._value}\n")
        
        async with aiohttp.ClientSession(headers={"User-Agent": "ShadowScout/1.0"}) as session:
            # 1. Scanning Risk Paths
            await asyncio.gather(*[self.fetch(session, self.target+p, True) for p in self.risk_paths])

            # 2. Deep Intelligence (JS & API discovery)
            if self.deep:
                print(f"\n{Fore.MAGENTA}[*] Deep Mode: Crawling for JS & API Routes...")
                home = await self.fetch(session, self.target)
                if home:
                    soup = BeautifulSoup(home, 'html.parser')
                    js_files = [tag.get('src') for tag in soup.find_all('script') if tag.get('src')]
                    await asyncio.gather(*[
                        self.deep_analyze_js(session, js if js.startswith('http') else f"{self.target}/{js.lstrip('/')}") 
                        for js in js_files
                    ])

            # 3. Final Summary & Scoring
            score, color = "INFORMATIONAL", Fore.BLUE
            if self.risk_points >= 80: score, color = "CRITICAL", Fore.LIGHTRED_EX
            elif self.risk_points >= 40: score, color = "HIGH", Fore.RED
            elif self.risk_points >= 10: score, color = "MEDIUM", Fore.YELLOW
            elif self.risk_points > 0: score, color = "LOW", Fore.GREEN

            print(f"\n{Style.BRIGHT}{'='*55}")
            print(f"REPORT SUMMARY")
            print(f"Final Risk Score: {color}{score} ({self.risk_points} pts)")
            if self.deep: print(f"Endpoints Discovered: {len(self.found_endpoints)}")
            print(f"{Style.BRIGHT}{'='*55}")

            if self.output_file:
                self.final_report.update({
                    "end_time": str(datetime.now()),
                    "risk_score": score,
                    "endpoints": list(self.found_endpoints)
                })
                with open(self.output_file, 'w') as f:
                    json.dump(self.final_report, f, indent=4)
                print(f"{Fore.GREEN}[+] Audit report saved to {self.output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="ShadowScout v1.0: Advanced Offensive Recon", 
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-d", "--deep", action="store_true", help="Enable Deep API/JS Analysis")
    parser.add_argument("-mc", "--match-codes", default="200,301,302,403", help="Codes to display (default: 200,301,302,403)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Concurrency level (default: 5)")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    try:
        codes = [int(c.strip()) for c in args.match_codes.split(',')]
    except ValueError:
        print(f"{Fore.RED}[!] Error: Status codes must be a comma-separated list of integers.")
        sys.exit(1)

    scanner = ShadowScout(args.url, args.deep, codes, args.output, args.threads)
    
    try:
        asyncio.run(scanner.start())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
