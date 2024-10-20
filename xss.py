#!/usr/bin/python3

from colorama import init, Fore, Style
import os
import requests
import subprocess
import time
import asyncio
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService  # Correct import
from selenium.webdriver.chrome.service import Service  # Added this import
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from rich.console import Console

# Initialize Colorama and Console
init(autoreset=True)
console = Console()

# Define colors
class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'

def load_payloads(payload_file):
    try:
        with open(payload_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        console.print(Fore.RED + f"[!] Error loading payloads: {e}")
        os._exit(0)

def generate_payload_urls(url, payload):
    url_combinations = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params.keys():
        modified_params = query_params.copy()
        modified_params[key] = [payload]
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        url_combinations.append(modified_url)
    return url_combinations

async def check_vulnerability(url, payloads, vulnerable_urls, total_scanned, driver):
    for payload in payloads:
        payload_urls = generate_payload_urls(url, payload)
        if not payload_urls:
            continue
        for payload_url in payload_urls:
            console.print(Fore.YELLOW + f"[→] Scanning payload: {payload}")
            try:
                driver.get(payload_url)
                total_scanned[0] += 1
                try:
                    WebDriverWait(driver, 10).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    alert_text = alert.text

                    if alert_text:
                        result = Fore.GREEN + f"[✓]{Fore.CYAN} Vulnerable: {Fore.GREEN}{payload_url} {Fore.CYAN} - Alert Text: {alert_text}"
                        console.print(result)
                        vulnerable_urls.append(payload_url)
                        alert.accept()
                    else:
                        result = Fore.RED + f"[✗]{Fore.CYAN} Not Vulnerable: {Fore.RED}{payload_url}"
                        console.print(result)

                except TimeoutException:
                    result = Fore.RED + f"[✗]{Fore.CYAN} Not Vulnerable: {Fore.RED}{payload_url}"
                    console.print(result)

            except UnexpectedAlertPresentException:
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    result = Fore.CYAN + f"[!] Unexpected Alert: {Fore.LIGHTBLACK_EX}{payload_url} {Fore.CYAN} - Alert: {Fore.GREEN} Might be Vulnerable!"
                    console.print(result)
                    alert.accept()
                except Exception as inner_e:
                    console.print(Fore.RED + f"[!] Error handling unexpected alert: {inner_e}")

    total_scanned[0] += len(payloads)

async def scan(urls, payloads, vulnerable_urls, total_scanned, concurrency, driver):
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    for url in urls:
        tasks.append(bound_check(url, semaphore, payloads, vulnerable_urls, total_scanned, driver))
    await asyncio.gather(*tasks)

async def bound_check(url, semaphore, payloads, vulnerable_urls, total_scanned, driver):
    async with semaphore:
        await check_vulnerability(url, payloads, vulnerable_urls, total_scanned, driver)

def run_scan(urls, payload_file, concurrency):
    payloads = load_payloads(payload_file)
    vulnerable_urls = []
    total_scanned = [0]
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    driver_service = ChromeService(ChromeDriverManager().install())  # Changed this line
    driver = webdriver.Chrome(service=driver_service, options=chrome_options)
    
    try:
        asyncio.run(scan(urls, payloads, vulnerable_urls, total_scanned, concurrency, driver))
    except Exception as e:
        console.print(Fore.RED + f"[!] Error during scan: {e}")
    finally:
        driver.quit()
    
    return vulnerable_urls, total_scanned[0]

def print_scan_summary(total_found, total_scanned, start_time):
    summary = [
        "→ Scanning finished.",
        f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}",
        f"• Total scanned: {total_scanned}",
        f"• Time taken: {int(time.time() - start_time)} seconds"
    ]
    for line in summary:
        console.print(Fore.YELLOW + line)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear_screen()
    console.print(Fore.CYAN + "XSS Scanner")
    console.print(Fore.YELLOW + "====================")
    
    urls = input("Enter the URLs separated by newlines: ").strip().splitlines()
    payload_file = input("Enter the path of the payload file: ")
    concurrency = int(input("Enter the number of concurrent threads (default: 5): ") or 5)

    start_time = time.time()
    vulnerable_urls, total_found = run_scan(urls, payload_file, concurrency)
    print_scan_summary(total_found, len(urls), start_time)

if __name__ == "__main__":
    main()
