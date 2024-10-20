#!/usr/bin/python3

from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    BOLD = '\033[1m'
    UNBOLD = '\033[22m'
    ITALIC = '\033[3m'
    UNITALIC = '\033[23m'

try:
    import os
    import requests
    from git import Repo
    import yaml
    import shutil
    from flask import session
    import sys
    from urllib.parse import urlsplit
    import subprocess
    from urllib.parse import urlunsplit
    import asyncio
    from selenium.webdriver.chrome.service import Service
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from curses import panel
    import random
    import re
    from wsgiref import headers
    from colorama import Fore, Style, init
    from time import sleep
    from rich import print as rich_print
    from rich.panel import Panel
    from rich.table import Table
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
    from bs4 import BeautifulSoup
    import urllib3
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    import logging
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import argparse
    import concurrent.futures
    import time
    import aiohttp
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium.common.exceptions import TimeoutException
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
    from rich.console import Console
    from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
    import signal
    from functools import partial
    
except Exception as e:
    print(f"{Fore.RED}An error occurred: {str(e)}")

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
        ]
    
    init(autoreset=True)
    
    def check_and_install_packages(packages):
        for package, version in packages.items():
            try:
                __import__(package)
            except ImportError:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def run_sql_scanner(scan_state=None):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        init(autoreset=True)
        
        def get_random_user_agent():
            return random.choice(USER_AGENTS)
            
        def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
                session = requests.Session()
                retry = Retry(
                total=retries,
                read=retries,
                connect=retries,
                backoff_factor=backoff_factor,
                status_forcelist=status_forcelist,
                )
                adapter = HTTPAdapter(max_retries=retry)
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                return session

        def perform_request(url, payload, cookie):
            url_with_payload = f"{url}{payload}"
            start_time = time.time()
                
            headers = {
                'User-Agent': get_random_user_agent()
            }

            try:
                response = requests.get(url_with_payload, headers=headers, cookies={'cookie': cookie} if cookie else None)
                response.raise_for_status()
                success = True
                error_message = None
            except requests.exceptions.RequestException as e:
                success = False
                error_message = str(e)

            response_time = time.time() - start_time
            
            vulnerability_detected = response_time >= 10
            if vulnerability_detected and scan_state:
                scan_state['vulnerability_found'] = True
                scan_state['vulnerable_urls'].append(url_with_payload)
                scan_state['total_found'] += 1
            if scan_state:
                scan_state['total_scanned'] += 1
            
            return success, url_with_payload, response_time, error_message, vulnerability_detected

        def get_file_path(prompt_text):
            completer = PathCompleter()
            return prompt(prompt_text, completer=completer).strip()

        def handle_exception(exc_type, exc_value, exc_traceback, vulnerable_urls, total_found, total_scanned, start_time):
            if issubclass(exc_type, KeyboardInterrupt):
                print(f"\n{Fore.YELLOW}Program terminated by the user!")
                os._exit(0)
            else:
                print(f"\n{Fore.RED}An unexpected error occurred: {exc_value}")
                os._exit(0)
                
        def prompt_for_urls():
            while True:
                try:
                    url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
                    if url_input:
                        if not os.path.isfile(url_input):
                            raise FileNotFoundError(f"File not found: {url_input}")
                        with open(url_input) as file:
                            urls = [line.strip() for line in file if line.strip()]
                        return urls
                    else:
                        single_url = input(f"{Fore.CYAN}[?] Enter a single URL to scan: ").strip()
                        if single_url:
                            return [single_url]
                        else:
                            print(f"{Fore.RED}[!] You must provide either a file with URLs or a single URL.")
                            input(f"{Fore.YELLOW}\n[i] Press Enter to try again...")
                            clear_screen()
                            print(f"{Fore.GREEN}Welcome to the Loxs SQL-Injector! - Coffinxp - 1hehaq- HexSh1dow - AnonKryptiQuz - Naho\n")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error reading input file: {url_input}. Exception: {str(e)}")
                    input(f"{Fore.YELLOW}[i] Press Enter to try again...")
                    clear_screen()
                    print(f"{Fore.GREEN}Welcome to the Loxs SQL-Injector! - Coffinxp - 1hehaq - HexSh1dow - AnonKryptiQuz - Naho\n")

        def prompt_for_payloads():
            while True:
                try:
                    payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                    if not os.path.isfile(payload_input):
                        raise FileNotFoundError(f"File not found: {payload_input}")
                    with open(payload_input) as file:
                        payloads = [line.strip() for line in file if line.strip()]
                    return payloads
                except Exception as e:
                    print(f"{Fore.RED}[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
                    input(f"{Fore.YELLOW}[i] Press Enter to try again...")
                    clear_screen()
                    print(f"{Fore.GREEN}Welcome to the Loxs SQL-Injector! - Coffinxp - 1hehaq - HexSh1dow - AnonKryptiQuz - Naho\n")

        def print_scan_summary(total_found, total_scanned, start_time):
            summary = [
                "→ Scanning finished.",
                f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}",
                f"• Total scanned: {total_scanned}",
                f"• Time taken: {int(time.time() - start_time)} seconds"
            ]
            max_length = max(len(line.replace(Fore.GREEN, '').replace(Fore.YELLOW, '')) for line in summary)
            border = "┌" + "─" * (max_length + 2) + "┐"
            bottom_border = "└" + "─" * (max_length + 2) + "┘"
            
            print(Fore.YELLOW + f"\n{border}")
            for line in summary:
                padded_line = line.replace(Fore.GREEN, '').replace(Fore.YELLOW, '')
                padding = max_length - len(padded_line)
                print(Fore.YELLOW + f"│ {line}{' ' * padding} │{Fore.YELLOW}")
            print(Fore.YELLOW + bottom_border)

        def main():
            clear_screen()
            time.sleep(1)
            clear_screen()

            panel = Panel(r"""                                                       
                ___                                         
    _________ _/ (_)  ______________ _____  ____  ___  _____
   / ___/ __ `/ / /  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
  (__  ) /_/ / / /  (__  ) /__/ /_/ / / / / / / /  __/ /    
 /____/\__, /_/_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
         /_/                                                

                    """,
            style="bold green",
            border_style="blue",
            expand=False
            )
            rich_print(panel, "\n")

            print(Fore.GREEN + "Welcome to the SQL Testing Tool!\n")

            urls = prompt_for_urls()
            payloads = prompt_for_payloads()
            
            cookie = input("[?] Enter the cookie to include in the GET request (press Enter if none): ").strip() or None

            threads = int(input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip() or 5)
            print(f"\n{Fore.YELLOW}[i] Loading, Please Wait...")
            time.sleep(1)
            clear_screen()
            print(f"{Fore.CYAN}[i] Starting scan...\n")
            vulnerable_urls = []
            first_vulnerability_prompt = True

            single_url_scan = len(urls) == 1
            start_time = time.time()
            total_scanned = 0
            total_found = 0
                
            get_random_user_agent()
            try:
                if threads == 0:
                    for url in urls:
                        box_content = f" → Scanning URL: {url} "
                        box_width = max(len(box_content) + 2, 40)
                        print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
                        print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
                        print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")
                        for payload in payloads:
                            success, url_with_payload, response_time, error_message, vulnerability_detected = perform_request(url, payload, cookie)

                            if vulnerability_detected:
                                stripped_payload = url_with_payload.replace(url, '')
                                encoded_stripped_payload = quote(stripped_payload, safe='')
                                encoded_url = f"{url}{encoded_stripped_payload}"
                                if single_url_scan:
                                    print(f"{Fore.YELLOW}[→] Scanning with payload: {stripped_payload}")
                                    encoded_url_with_payload = encoded_url
                                else:
                                    list_stripped_payload = url_with_payload
                                    for u in urls:
                                        list_stripped_payload = list_stripped_payload.replace(u, '')
                                    encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                    encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                    print(f"{Fore.YELLOW}[→] Scanning with payload: {list_stripped_payload}")
                                print(f"{Fore.GREEN}[✓]{Fore.CYAN} Vulnerable: {Fore.GREEN}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                                vulnerable_urls.append(url_with_payload)
                                total_found += 1
                                
                            else:
                                stripped_payload = url_with_payload.replace(url, '')
                                encoded_stripped_payload = quote(stripped_payload, safe='')
                                encoded_url = f"{url}{encoded_stripped_payload}"
                                if single_url_scan:
                                    print(f"{Fore.YELLOW}[→] Scanning with payload: {stripped_payload}")
                                    encoded_url_with_payload = encoded_url
                                else:
                                    list_stripped_payload = url_with_payload
                                    for u in urls:
                                        list_stripped_payload = list_stripped_payload.replace(u, '')
                                    encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                    encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                    print(f"{Fore.YELLOW}[→] Scanning with payload: {list_stripped_payload}")
                                print(f"{Fore.RED}[✗]{Fore.CYAN} Not Vulnerable: {Fore.RED}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                            total_scanned += 1
                            
                else:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                        for url in urls:
                            box_content = f" → Scanning URL: {url} "
                            box_width = max(len(box_content) + 2, 40)
                            print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
                            print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
                            print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")
                            
                            futures = []
                            for payload in payloads:
                                futures.append(executor.submit(perform_request, url, payload, cookie))

                            for future in concurrent.futures.as_completed(futures):
                                success, url_with_payload, response_time, error_message, vulnerability_detected = future.result()

                                if vulnerability_detected:
                                    stripped_payload = url_with_payload.replace(url, '')
                                    encoded_stripped_payload = quote(stripped_payload, safe='')
                                    encoded_url = f"{url}{encoded_stripped_payload}"
                                    if single_url_scan:
                                        print(f"{Fore.YELLOW}[→] Scanning with payload: {stripped_payload}")
                                        encoded_url_with_payload = encoded_url
                                    else:
                                        list_stripped_payload = url_with_payload
                                        for u in urls:
                                            list_stripped_payload = list_stripped_payload.replace(u, '')
                                        encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                        encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                        print(f"{Fore.YELLOW}[→] Scanning with payload: {list_stripped_payload}")
                                    print(f"{Fore.GREEN}[✓]{Fore.CYAN} Vulnerable: {Fore.GREEN}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                                    vulnerable_urls.append(url_with_payload)
                                    total_found += 1
                                    if single_url_scan and first_vulnerability_prompt:
                                        continue_scan = input(f"{Fore.CYAN}\n[?] Vulnerability found. Do you want to continue testing other payloads? (y/n, press Enter for n): ").strip().lower()
                                        if continue_scan != 'y':
                                            break
                                        first_vulnerability_prompt = False

                                else:
                                    stripped_payload = url_with_payload.replace(url, '')
                                    encoded_stripped_payload = quote(stripped_payload, safe='')
                                    encoded_url = f"{url}{encoded_stripped_payload}"
                                    if single_url_scan:
                                        print(f"{Fore.YELLOW}[→] Scanning with payload: {stripped_payload}")
                                        encoded_url_with_payload = encoded_url
                                    else:
                                        list_stripped_payload = url_with_payload
                                        for u in urls:
                                            list_stripped_payload = list_stripped_payload.replace(u, '')
                                        encoded_stripped_payload = quote(list_stripped_payload, safe='')

                                        encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                                        print(f"{Fore.YELLOW}[→] Scanning with payload: {list_stripped_payload}")
                                    print(f"{Fore.RED}[✗]{Fore.CYAN} Not Vulnerable: {Fore.RED}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                                total_scanned += 1

                print_scan_summary(total_found, total_scanned, start_time)
            except Exception as e:
                print(f"{Fore.RED}An error occurred: {str(e)}")
            finally:
                if 'executor' in locals():
                    executor.shutdown(wait=False)
                os._exit(0)

        if __name__ == "__main__":
            try:
                main()
            except KeyboardInterrupt:
                os._exit(0)