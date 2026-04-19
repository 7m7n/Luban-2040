#!/usr/bin/env python3
# ============================================================
#   Luban 2040 v1  -  Advanced CVE & Exploit Finder
#   Author  : m.alfahdi
#   Purpose : Bug Bounty / Authorized Penetration Testing
# ============================================================

import requests
import re
import cloudscraper
import platform
import urllib
import argparse
import json
import sys
import time
from random import choice
from os import system
from termcolor import colored
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pyfiglet
except ImportError:
    print("[!] Install pyfiglet: pip install pyfiglet --break-system-packages")
    sys.exit(1)

# ─── Color helpers ───────────────────────────────────────────
ops_release = str(platform.release())
ops = str(platform.system())

if '2012ServerR2' not in ops_release and ops in ('Windows', 'Linux'):
    g   = lambda x: colored(x, 'green',   attrs=["bold"])
    rod = lambda x: colored(x, 'red',     attrs=["bold"])
    b   = lambda x: colored(x, 'blue',    attrs=["bold"])
    y   = lambda x: colored(x, 'yellow',  attrs=["bold"])
    c   = lambda x: colored(x, 'cyan',    attrs=["bold"])
    m   = lambda x: colored(x, 'magenta', attrs=["bold"])
else:
    g = rod = b = y = c = m = lambda x: x

clear = lambda: system("cls" if ops == "Windows" else "clear")
clear()

# ─── Banner symbols ──────────────────────────────────────────
exl  = '[' + rod('!') + ']'
ques = '[' + m('?')   + ']'
ha   = '[' + g('#')   + ']'
mult = '[' + c('*')   + ']'
bad  = '[' + rod('#') + ']'

# ─── ASCII Banner ─────────────────────────────────────────────
BANNER_FONTS = ['slant', 'big', 'banner3', 'doom', 'epic', 'starwars']
try:
    font = choice(BANNER_FONTS)
    banner = pyfiglet.figlet_format("Luban 2040", font=font)
except Exception:
    banner = "  LUBAN 2040  "

print(rod(banner))
print(g("=" * 62))
print(g("  Luban 2040 v1") + "  |  " + y("Advanced CVE & Exploit Finder"))
print(y("  Author : ") + c("m.alfahdi"))
print(y("  Use    : ") + c("Authorized Bug Bounty / Penetration Testing ONLY"))
print(g("=" * 62) + "\n")


# ─── NVD API – free, no scraping needed ──────────────────────
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def nvd_cve_info(cve_id: str) -> dict:
    """
    Fetch CVE description + CVSS score from NVD API (free, no key needed).
    Returns dict: {description, cvss, severity}
    Falls back to empty strings on error.
    """
    result = {"description": "", "cvss": "N/A", "severity": ""}
    try:
        r = requests.get(
            NVD_API,
            params={"cveId": cve_id},
            timeout=10,
            headers={"User-Agent": "Luban2040/1.0"}
        )
        if r.status_code == 200:
            data = r.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})

            # Description
            for d in vuln.get("descriptions", []):
                if d.get("lang") == "en":
                    result["description"] = d.get("value", "")
                    break

            # CVSS score (prefer v3.1 → v3.0 → v2)
            metrics = vuln.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    score_data = metrics[key][0].get("cvssData", {})
                    result["cvss"]     = str(score_data.get("baseScore", "N/A"))
                    result["severity"] = score_data.get("baseSeverity", "")
                    break
    except Exception:
        pass
    return result


# ─── EPSS Score (Exploit Prediction Scoring System) ──────────
def get_epss(cve_id: str) -> str:
    """Returns EPSS score (0.0–1.0) or 'N/A' on failure."""
    try:
        r = requests.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}",
            timeout=8,
            headers={"User-Agent": "Luban2040/1.0"}
        )
        if r.status_code == 200:
            data = r.json()
            epss_val = data.get("data", [{}])[0].get("epss", None)
            if epss_val:
                return str(round(float(epss_val) * 100, 2)) + "%"
    except Exception:
        pass
    return "N/A"


# ─── Main Scanner Class ───────────────────────────────────────
class Luban2040:

    def __init__(self, verbose, output_file, exclude_fp, min_cvss, threads):
        self.headers = {
            'Host': 'account.shodan.io',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/126.0.6478.36 Safari/537.36'
            ),
            'Accept': 'text/html',
            'Accept-Language': 'en-GB',
            'Accept-Encoding': 'gzip',
            'Priority': 'u=0, i'
        }
        self.s          = requests.Session()
        self.min_cvss   = float(min_cvss)
        self.exclude_fp = exclude_fp
        self.verbose    = verbose
        self.threads    = threads
        self.all_ips    = []
        self.query      = None

        if output_file:
            self.output = output_file
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output = f"Luban2040_Results_{ts}.json"

        # Create output file
        try:
            open(self.output, 'x').close()
        except FileExistsError:
            pass

    # ── Shodan Login ─────────────────────────────────────────
    def shodan_login(self, username: str, password: str):
        URL = "https://account.shodan.io/login"
        data = {
            'username': username,
            'password': password,
            'grant_type': 'password',
            'continue': 'dashboard'
        }
        try:
            page  = self.s.get(URL, headers=self.headers, timeout=15).text
            token = re.findall(
                r'"csrf_token" value="[0-9a-z]{40}"\/>',
                page
            )[0].split('"')[-2]
            print(f'{ha} CSRF token retrieved')
        except Exception as e:
            print(f'{exl} Could not retrieve CSRF token: {e}')
            sys.exit(1)

        data['csrf_token'] = token
        try:
            login = self.s.post(URL, data=data, timeout=15)
            if login.url == 'https://www.shodan.io/dashboard' and login.ok:
                self.polito = self.s.cookies.get_dict().get('polito', '')
                print(f'{ha} Authentication successful ✓')
            elif login.status_code == 429:
                print(f'{exl} Rate-limited – try again later.')
                sys.exit(1)
            else:
                print(f'{exl} Login failed. Check credentials in config.json')
                sys.exit(1)
        except Exception as e:
            print(f'{exl} Login error: {e}')
            sys.exit(1)

    # ── False-positive removal ────────────────────────────────
    def is_real_target(self, ip: str) -> bool:
        """Returns True if the IP really belongs to the target."""
        if self.query is None:
            return True
        self.headers['Host'] = 'www.shodan.io'
        try:
            r = self.s.get(
                f'https://www.shodan.io/host/{ip}',
                headers=self.headers,
                timeout=10
            )
            # Extract the keyword to look for
            if 'hostname:' in self.query:
                word = re.search(r'hostname:"?\S+"?', self.query)
                word = word.group().split(':')[-1].replace('"', '').replace('*.', '')
            elif 'org:' in self.query:
                word = re.search(r'org:"?\S+"?', self.query)
                word = word.group().split(':')[-1].replace('"', '')
            else:
                word = self.query.split(':')[-1] if ':' in self.query else self.query

            return word.lower() in r.text.lower()
        except Exception:
            return True   # If we can't verify, keep it

    # ── Shodan search ─────────────────────────────────────────
    def shodan_search(self, query_type, query: str):
        self.headers['Host'] = 'www.shodan.io'

        if query_type == 'org':
            self.query = f'org:"{query}"'
        elif query_type == 'hostname':
            self.query = f'hostname:"{query}"'
        else:
            self.query = query

        encoded = urllib.parse.quote(self.query, safe='')
        print(f'{mult} Target Query : {c(query)}')

        try:
            r = self.s.get(
                f'https://www.shodan.io/search/facet?query={encoded}&facet=ip',
                headers=self.headers,
                timeout=20
            )
            all_ips = re.findall(
                r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                r.text
            )
            self.all_ips = list(set(all_ips))
        except Exception as e:
            print(f'{exl} Search failed: {e}')
            sys.exit(1)

        # Save IPs
        with open('All_IPs.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.all_ips) + '\n')

        label = query_type if query_type else "query"
        print(f'{ha} Collected {g(str(len(self.all_ips)))} IPs [{label}: {c(query)}]')
        print(f'{ha} Saved to {c("All_IPs.txt")}')
        print(f'{mult} Starting scan engine ({self.threads} threads)...\n')
        self.ip_scan()

    # ── IP Scan (threaded) ────────────────────────────────────
    def ip_scan(self):
        idb_headers = self.headers.copy()
        idb_headers['Host'] = 'internetdb.shodan.io'

        def scan_one(ip):
            try:
                r    = requests.get(
                    f"https://internetdb.shodan.io/{ip}",
                    headers=idb_headers,
                    timeout=10
                )
                data = r.json()
                vulns = data.get('vulns', [])

                if not vulns:
                    if self.verbose:
                        print(f"{bad} {c(ip)} – No CVEs")
                    return

                print(f"{ha} {c(ip)} – {m(str(len(vulns)))} CVEs found")

                real = self.is_real_target(ip)
                fp_label = g("False") if real else rod("True")
                print(f"   {ha} False Positive? → {fp_label}")

                if not real and self.exclude_fp:
                    return

                self.cve_detail_check(vulns, ip)

            except Exception as e:
                if self.verbose:
                    print(f"{exl} Error scanning {ip}: {e}")

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(scan_one, ip): ip for ip in self.all_ips}
            for future in as_completed(futures):
                pass   # errors already handled inside scan_one

    # ── CVE detail check ─────────────────────────────────────
    def cve_detail_check(self, cves: list, ip: str):
        scraper = cloudscraper.create_scraper()
        cve_headers = {
            'Host': 'www.cvedetails.com',
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) '
                'Gecko/20100101 Firefox/146.0'
            ),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

        results = []

        for cve in cves:
            try:
                # ── NVD for description + CVSS ────────────
                nvd   = nvd_cve_info(cve)
                cvss  = nvd["cvss"]
                desc  = nvd["description"] or "No description available"
                sev   = nvd["severity"]

                # Skip if below threshold
                try:
                    if float(cvss) < self.min_cvss:
                        continue
                except ValueError:
                    pass

                # ── EPSS score ────────────────────────────
                epss = get_epss(cve)

                # ── cvedetails for exploit status ─────────
                exploit_type = None
                try:
                    r    = scraper.get(
                        f"https://www.cvedetails.com/cve/{cve}/",
                        headers=cve_headers,
                        timeout=12
                    )
                    text = r.text
                    if 'Public exploit exists!' in text:
                        exploit_type = 'Public'
                    elif 'Potential exploit' in text:
                        exploit_type = 'Potential'
                except Exception:
                    pass   # can't reach cvedetails, continue

                # ── Print result ──────────────────────────
                sev_label = f" [{sev}]" if sev else ""
                if exploit_type == 'Public':
                    print(f"   {ha} {rod(cve)} | CVSS {rod(cvss)}{sev_label} | EPSS {y(epss)} | {rod('PUBLIC EXPLOIT !')}")
                elif exploit_type == 'Potential':
                    print(f"   {ha} {rod(cve)} | CVSS {y(cvss)}{sev_label} | EPSS {y(epss)} | {y('Potential exploit')}")
                else:
                    print(f"   {mult} {rod(cve)} | CVSS {cvss}{sev_label} | EPSS {epss} | No public exploit")

                if self.verbose:
                    print(f"       {b('Desc:')} {desc[:120]}...")

                print(f"       {b('Ref :')} https://www.cvedetails.com/cve/{cve}/")
                print(f"       {b('NVD :')} https://nvd.nist.gov/vuln/detail/{cve}")

                if exploit_type:
                    results.append({
                        "CVE": cve,
                        "CVSS Score": cvss,
                        "Severity": sev,
                        "EPSS": epss,
                        "Exploit Type": exploit_type,
                        "Description": desc,
                        "CVEDetails URL": f"https://www.cvedetails.com/cve/{cve}/",
                        "NVD URL": f"https://nvd.nist.gov/vuln/detail/{cve}"
                    })

                time.sleep(0.3)   # be polite to APIs

            except Exception as e:
                if self.verbose:
                    print(f"   {exl} Error processing {cve}: {e}")

        if results:
            self.save_output(results, ip)

    # ── Save to JSON ──────────────────────────────────────────
    def save_output(self, cve_list: list, ip: str):
        entry = {
            "IP": ip,
            "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "CVEs": cve_list
        }
        try:
            with open(self.output, 'a', encoding='utf-8') as f:
                json.dump(entry, f, indent=4, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            print(f'{exl} Failed to save output: {e}')


# ─── CLI ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Luban 2040 v1 – Advanced CVE & Exploit Finder | by m.alfahdi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  luban2040.py -q "N-able" -e
  luban2040.py -q http.favicon.hash:945408572 -e -cvss 7
  luban2040.py -host netflix.com -v
  luban2040.py -org ADAC -e -cvss 9
  luban2040.py -l All_IPs.txt -e -v -cvss 9 -t 20
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-q",    "--query",        help="Shodan search query (port:8000, etc)")
    group.add_argument("-l",    "--list",          help="File with IPs (one per line)")
    group.add_argument("-org",  "--organization",  help="Organization name (BMW, Netflix, etc)")
    group.add_argument("-host", "--hostname",      help="Domain name or wildcard hostname")

    parser.add_argument("-o",    "--output",               default=None,  help="Output JSON file")
    parser.add_argument("-e",    "--exclude-false-postive", default=False, action="store_true",
                        help="Exclude IPs that don't actually belong to the target")
    parser.add_argument("-cvss", "--least-cvss",           default=1.0,
                        help="Minimum CVSS score to save (default 1.0)")
    parser.add_argument("-v",    "--verbose",              action="store_true",
                        help="Show extra details per IP/CVE")
    parser.add_argument("-t",    "--threads",              default=10, type=int,
                        help="Number of scan threads (default 10)")

    args = parser.parse_args()

    tool = Luban2040(
        verbose     = args.verbose,
        output_file = args.output,
        exclude_fp  = args.exclude_false_postive,
        min_cvss    = args.least_cvss,
        threads     = args.threads
    )

    # If using Shodan search → need login
    if args.query or args.organization or args.hostname:
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                creds = json.load(f)
            user = creds['username']
            pwd  = creds['password']
        except Exception as e:
            print(f'{exl} config.json error: {e}')
            print(f'{exl} Create config.json with: {{"username":"...", "password":"..."}}')
            sys.exit(1)

        tool.shodan_login(user, pwd)

        if args.query:
            tool.shodan_search(None, args.query)
        elif args.hostname:
            tool.shodan_search('hostname', args.hostname)
        else:
            tool.shodan_search('org', args.organization)

    else:
        # IP list mode – no Shodan login needed
        try:
            with open(args.list, 'r', encoding='utf-8') as f:
                hosts = [l.strip() for l in f if l.strip()]
            if not hosts:
                print(f'{exl} IP list is empty.')
                sys.exit(1)
            tool.all_ips = hosts
            print(f'{ha} Loaded {g(str(len(hosts)))} IPs from {c(args.list)}')
            print(f'{mult} Starting scan ({args.threads} threads)...\n')
            tool.ip_scan()
        except FileNotFoundError:
            print(f'{exl} File not found: {args.list}')
            sys.exit(1)

    print(f'\n{ha} Done! Results saved to {c(tool.output)}')


if __name__ == "__main__":
    main()