# XSS-Scanner

A Python-based tool for scanning websites for Cross-Site Scripting (XSS) vulnerabilities. This scanner supports both crawling mode (to discover and test URLs on a site) and target testing mode (to test a list of specific URLs). Built as part of my collection of Python projects for learning and practice in web security.

![Banner](https://img.shields.io/badge/Python-3.6%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![GitHub Repo](https://img.shields.io/badge/GitHub-Ian--Lusule-orange)

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Command-Line Arguments](#command-line-arguments)
- [How It Works](#how-it-works)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Introduction

Cross-Site Scripting (XSS) is a common web vulnerability where attackers inject malicious scripts into webpages viewed by other users. This scanner helps identify potential XSS vulnerabilities by injecting test vectors into URL parameters and checking if they are reflected in the response without proper sanitization.

This project is inspired by my other Python tools like WebScraper and 50PyScripts, focusing on web security testing. It's designed for educational purposes and ethical use only—always get permission before scanning any website.

**Disclaimer:** This tool is for educational and testing purposes. Do not use it on production sites without authorization, as it may violate terms of service or laws.

## Features

- **Two Modes of Operation:**
  - **Crawling Mode:** Starts from a base URL, crawls the site up to a specified depth, and tests discovered URLs for XSS.
  - **Target Testing Mode:** Tests a provided list of URLs from a file, using multi-threading for efficiency.

- **XSS Test Vectors:** Includes a variety of payloads:
  - Basic: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`.
  - Attribute-based: `' onmouseover='alert(1)`.
  - Evasion: Case variations and char code encodings.
  - Specialized: Iframes, body onload, etc.

- **Multi-Threading:** Supports concurrent testing in target mode for faster scans (default: 15 threads).
- **Customizable:** Options for threads, timeout, user-agent, and output file.
- **Immediate Output:** Vulnerable URLs are printed to the terminal (in green if colorama is installed) and appended to an output file as they are found.
- **Screen Clearing:** Clears the terminal before running for a clean interface.
- **Banner Display:** ASCII art banner with color support.

## Installation

1. **Clone the Repository:**
```bash
git clone https://github.com/Ian-Lusule/XSS-Scanner.git
cd XSS-Scanner
```

2. **Install Dependencies:**
This script requires Python 3.6+ and the following libraries (install via pip):
```bash
pip install requests beautifulsoup4 colorama
```
- `requests`: For HTTP requests.
- `beautifulsoup4`: For parsing HTML in crawling mode.
- `colorama` (optional): For colored terminal output.

Note: No additional packages can be installed during runtime; these are prerequisites.

3. **Run the Script:**
Ensure the script is executable:
```bash
chmod +x xss_scanner.py
```

## Usage

Run the script with Python:
```bash
python3 xss_scanner.py [options]
```

- Use `-h` or `--help` for a full list of arguments.
- The script clears the screen, displays a banner, and processes based on the mode.

## Command-Line Arguments

- **Modes (Mutually Exclusive):**
  - `-Tt, --target-testing`: Enable target testing mode (requires `-f`).
  - `-d, --depth <int>`: Set crawling depth (requires `-u`).

- **Targets (Mutually Exclusive):**
  - `-u, --url <URL>`: Single URL for crawling mode (e.g., http://example.com).
  - `-f, --file <file>`: File with list of URLs for target testing mode.

- **Other Options:**
  - `-t, --threads <int>`: Number of threads (default: 15).
  - `-T, --timeout <int>`: Request timeout in seconds (default: 8).
  - `-a, --user-agent <string>`: Custom User-Agent (default: 'XSSScanner/1.0').
  - `-o, --output <file>`: Output file for vulnerable URLs (appends immediately).
  - `-h, --help`: Show help message.

## Examples

1. **Target Testing Mode:**
   Test URLs from a file and save vulnerable ones:
```bash
python3 xss_scanner.py -Tt -f urls.txt -o vulnerable_xss.txt -t 20
```
- Reads `urls.txt` (one URL per line).
- Uses 20 threads.
- Appends vulnerable URLs to `vulnerable_xss.txt`.

2. **Crawling Mode:**
Crawl a site starting from a URL with depth 2:
```bash
python3 xss_scanner.py -d 2 -u http://example.com -o vulnerable_xss.txt
```
- Crawls links up to depth 2.
- Tests URLs with query params for XSS.

3. **Custom User-Agent:**
```bash
python3 xss_scanner.py -Tt -f urls.txt -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

## How It Works

1. **Test Vectors:** A list of XSS payloads is injected into each query parameter of the URL.
2. **Vulnerability Check:** If the payload is reflected unchanged in the response text, it's flagged as vulnerable.
3. **Crawling:** Uses BFS to discover links (via BeautifulSoup), staying within the same domain.
4. **Threading:** In target mode, uses `concurrent.futures` for parallel testing.
5. **Output Handling:** Vulnerable URLs are printed and written immediately to avoid data loss in long scans.
6. **Error Handling:** Skips invalid URLs or timeouts; prints file reading errors in red (if colorama installed).

## Limitations

- **Reflected XSS Only:** Detects reflected XSS; does not handle stored or DOM-based XSS.
- **False Positives/Negatives:** Reflection doesn't guarantee exploitability; manual verification needed.
- **No POST Support:** Only tests GET parameters in URLs.
- **Crawling Depth:** Limited to anchor tags; doesn't handle JavaScript-generated links.
- **Ethical Use:** May trigger security alerts; use only on sites you own or have permission for.
- **Dependencies:** Requires internet for requests; no offline mode.
- **Performance:** High thread counts may lead to rate-limiting or bans.

## Contributing

Contributions are welcome! Feel free to fork, submit issues, or pull requests.
- Report bugs via GitHub Issues.
- Suggest new XSS vectors or features.
- Follow Python best practices (PEP8).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

- GitHub: [Ian-Lusule](https://github.com/Ian-Lusule)
- For questions or collaborations, open an issue or check my other repos like 50PyScripts for more Python projects.
