# Luban 2040 v1
### Advanced CVE & Exploit Finder
**Author:** m.alfahdi  
**Purpose:** Authorized Bug Bounty / Penetration Testing ONLY

---

## Description

Luban 2040 v1 is an advanced CVE finder that:
1. Extracts IPs (by hostname or organization name)
2. Scans each IP via **InternetDB ** for known CVEs
3. Checks exploit availability via **cvedetails.com**
4. Fetches CVSS scores via **NVD API**
5. Fetches **EPSS** (Exploit Prediction Score) for each CVE
6. Saves results to a **JSON** output file

---

## Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt --break-system-packages

# 2. Edit config.json with your Shodan credentials
nano config.json
```

**config.json format:**
```json
{
    "username": "your_shodan_email",
    "password": "your_shodan_password"
}
```

---

## Usage

```
python luban2040.py [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-host HOSTNAME` | Domain name (e.g. `example.com`) |
| `-org ORGANIZATION` | Organization name (e.g. `Netflix`) |
| `-l FILE` | Text file with IPs (one per line) |
| `-o FILE` | Output JSON file (default: auto-named) |
| `-e` | Exclude false positives |
| `-cvss N` | Minimum CVSS score to include (default: 1.0) |
| `-v` | Verbose output |
| `-t N` | Number of threads (default: 10) |

---

## Examples

```bash
# Scan by hostname
python luban2040.py -host target.com -e -v

# Scan by organization, only CVSS 7+
python luban2040.py -org "STC" -e -cvss 7

# Scan from IP list with 20 threads
python luban2040.py -l All_IPs.txt -e -cvss 7 -t 20 -v
```

---

## Output

- **All_IPs.txt** — all IPs collected from Shodan
- **Luban2040_Results_[timestamp].json** — CVE results per IP

### JSON Output Sample
```json
{
    "IP": "1.2.3.4",
    "Scan Time": "2026-04-19 12:00:00",
    "CVEs": [
        {
            "CVE": "CVE-2021-44228",
            "CVSS Score": "10.0",
            "Severity": "CRITICAL",
            "EPSS": "97.5%",
            "Exploit Type": "Public",
            "Description": "Apache Log4j2 RCE vulnerability...",
            "CVEDetails URL": "https://www.cvedetails.com/cve/CVE-2021-44228/",
            "NVD URL": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        }
    ]
}
```

---

## Notes

- `-e` flag re-checks if the IP truly belongs to your target (reduces false positives)
- InternetDB database is updated **weekly** — verify findings on Shodan directly
- **Public exploit** = confirmed on Metasploit
- **Potential exploit** = likely on GitHub, not yet in Metasploit
- Use `-t` to speed up large IP lists (e.g. `-t 20`)

---

## Disclaimer

This tool is intended **only for authorized security testing**, bug bounty programs, and vulnerability disclosure. The author is not responsible for any unauthorized or illegal use.

---

*Luban 2040 v1 — by m.alfahdi*
