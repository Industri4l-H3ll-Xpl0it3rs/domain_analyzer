# domain_analyzer

cr34t3d by **gr1tx**

**domain_analyzer** is a simple Python command-line tool that collects basic information about a domain or website in one place. It can be used for **initial phishing investigations** by highlighting details that may warrant closer inspection.

The tool **does not automatically detect phishing** or determine whether a website is safe. Its results are intended to support further manual analysis.

### Features

- **WHOIS information:** domain registration date, registrar, and registrar abuse contact (when available).
- **DNS lookup:** IPv4 (A), IPv6 (AAAA), and mail exchange (MX) records, including a check for a Null MX record.
- **IP WHOIS:** network owner/operator and abuse contact for each resolved IPv4 address (when available).
- **SSL/TLS certificate:** verifies the site's certificate on port 443 and reports its expiration date if verification succeeds; otherwise displays a validation or connection error.
- **VirusTotal Passive DNS:** queries the VirusTotal API for domain names previously associated with each resolved IPv4 address, subject to API access and rate limits. It also prints a link to the corresponding VirusTotal IP relations page.

### Installation / Requirements

**Requirements:** Ubuntu/Debian-based Linux, Python 3, and an internet connection.

Install the dependencies:

```bash
sudo apt update
sudo apt install python3-requests whois bind9-host dnsutils
```

These packages provide the Python `requests` module and the `whois`, `host`, and `dig` command-line utilities used by the script.

Download `domain_analyzer.py` and open a terminal in the directory containing the file.

**Optional: VirusTotal API key**

To enable VirusTotal API lookups, open `domain_analyzer.py` and replace the placeholder value:

```python
key = ("your API VirusTotal").strip()
```

with your actual VirusTotal API key:

```python
key = ("YOUR_VIRUSTOTAL_API_KEY").strip()
```

If you do not want to use the VirusTotal API, set the key to an empty string:

```python
key = ""
```

In that case, the script will print links for manual VirusTotal checks instead. **Leaving the original placeholder unchanged does not disable API requests** and may result in a `401` error.

### Usage

Start the interactive script:

```bash
python3 domain_analyzer.py
```

Enter a domain or full URL when prompted:

```text
Enter a URL or domain: example.com
```

The script prints the available WHOIS, DNS, IP, SSL/TLS, and VirusTotal information in the terminal. It uses an interactive prompt; **there is no `--help` command or other command-line option implemented**.

### Examples

Analyze a domain:

```bash
python3 domain_analyzer.py
```

```text
Enter a URL or domain: example.com
```

Analyze a full URL:

```bash
python3 domain_analyzer.py
```

```text
Enter a URL or domain: https://example.com/
```

**Interpreting results:** a recently registered domain, unexpected hosting details, or unusual DNS configuration may be reasons to investigate further, but none proves phishing. A valid SSL/TLS certificate is **not** proof that a website is trustworthy. WHOIS fields can be missing, and VirusTotal results depend on API permissions and available data.

### ⚠️ Disclaimer ⚠️

This software is provided **for educational, research, and defensive security purposes only**.

- The author is **not responsible** for misuse or damage caused by this software.
- Follow applicable laws and the terms of any third-party services you use.
- Do not attempt unauthorized access to systems or services.

**Use ethically and responsibly.**
