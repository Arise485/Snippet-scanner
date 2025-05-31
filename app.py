from flask import Flask, request, jsonify
from flask_cors import CORS # Import CORS
import re
import requests # For fetching content from URLs
from bs4 import BeautifulSoup # For parsing HTML from URLs

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# --- OWASP Vulnerability Scanning Logic ---
# These functions are simplified for demonstration purposes.
# In a real application, these would be more robust and comprehensive.

def check_xss_injection(content, line_number=None):
    """
    Checks for potential Cross-Site Scripting (XSS) and other injection vulnerabilities.
    Looks for direct DOM manipulation with untrusted input (innerHTML, document.write) or eval().
    """
    issues = []
    # Regex to find innerHTML/document.write being assigned or called with potentially untrusted sources
    # This regex is more specific to catch common patterns where user input might be involved.
    if re.search(r'(innerHTML|document\.write)\s*=\s*[^;]*(\bwindow\.location\.(?:hash|search)|[\'"`][^\'"`]*\+[^;]*\buser_input\b|\binputElement\.value\b|\burlParams\.get\b|\b\.value\b)', content, re.IGNORECASE) or \
       re.search(r'document\.write\s*\([^)]*\bwindow\.location\.(?:hash|search)\b[^)]*\)', content, re.IGNORECASE) or \
       'eval(' in content:
        issues.append({
            'severity': 'High',
            'issue': 'Potential Injection (XSS/Code Injection)',
            'description': 'Potential unsafe `innerHTML`, `document.write`, or `eval()` usage found. This may lead to Cross-Site Scripting (XSS) or arbitrary code execution if untrusted input is used directly.',
            'suggestion': 'Always sanitize and encode all user-supplied data before inserting it into the DOM or using it in dynamic code. Use `textContent` instead of `innerHTML` when not inserting HTML. Avoid `eval()` whenever possible.',
            'owasp_category': 'A03:2021 - Injection',
            'line_number': line_number # Placeholder for line number
        })
    return issues

def check_cryptographic_failures(content, line_number=None):
    """
    Checks for client-side storage/exposure of sensitive data in plain text.
    """
    issues = []
    # Look for keywords like 'api_key', 'secret', 'token', 'password' followed by assignment to a string literal
    if re.search(r'(api_key|secret|token|password|credential)\s*=\s*["\'][^"\']*["\']', content, re.IGNORECASE):
        issues.append({
            'severity': 'High',
            'issue': 'Hardcoded Sensitive Data',
            'description': 'Sensitive data (e.g., API keys, secrets, tokens, or default passwords) appears to be hardcoded directly in client-side code. This exposes confidential information to anyone viewing the page source.',
            'suggestion': 'Sensitive data should never be hardcoded in client-side code. Use secure server-side methods to manage and retrieve secrets (e.g., environment variables, secure vault services) and transmit them only when absolutely necessary, via secure channels and HTTPS.',
            'owasp_category': 'A02:2021 - Cryptographic Failures',
            'line_number': line_number
        })
    return issues

def check_broken_access_control(content, line_number=None):
    """
    Checks for client-side only access control enforcement indicators.
    """
    issues = []
    # Look for 'admin' role checks combined with client-side UI changes (simplified heuristic)
    # This pattern suggests that access decisions might be made only on the client.
    if re.search(r'if\s*\((?:user|role|isAdmin)\.(?:role|type|status|is_admin)\s*===?\s*["\']admin["\']\)\s*{[^}]*(?:style\.display\s*=\s*["\']none["\']|disabled\s*=\s*true|classList\.add\s*\([^\)]*hidden\b)', content, re.IGNORECASE | re.DOTALL):
        issues.append({
            'severity': 'High',
            'issue': 'Client-Side Access Control Enforcement',
            'description': 'Access control logic (e.g., checking for "admin" role) appears to be enforced solely on the client-side. This can be easily bypassed by attackers manipulating browser code or network requests.',
            'suggestion': 'Always enforce access control and authorization decisions on the server-side. Client-side logic should only be for UI presentation, not security enforcement. All sensitive operations must be validated on the server.',
            'owasp_category': 'A01:2021 - Broken Access Control',
            'line_number': line_number
        })
    return issues

def check_vulnerable_components(content, line_number=None):
    """
    Performs a very basic check for known vulnerable library versions in script tags.
    This is illustrative and not a substitute for a dedicated Software Composition Analysis (SCA) tool.
    """
    issues = []
    # Illustrative vulnerable jQuery versions (in a real scenario, this would be from a CVE database)
    # This covers common vulnerable ranges.
    vulnerable_jquery_regex = r'jquery-(1\.\d+\.\d+|2\.\d+\.\d+|3\.0\.\d+|3\.1\.\d+|3\.2\.\d+|3\.3\.\d+)\.min\.js'

    soup = BeautifulSoup(content, 'html.parser')
    for script_tag in soup.find_all('script', src=True):
        src = script_tag['src']
        if re.search(vulnerable_jquery_regex, src, re.IGNORECASE):
            match = re.search(r'jquery-(\d+\.\d+\.\d+)', src, re.IGNORECASE)
            version = match.group(1) if match else 'unknown'
            issues.append({
                'severity': 'Medium',
                'issue': 'Vulnerable jQuery Version Detected',
                'description': f'An old or potentially vulnerable version of jQuery ({version}) was detected. These versions have known security vulnerabilities.',
                'suggestion': 'Update jQuery to the latest stable version (e.g., 3.7.1+ or newer) or a more modern framework. Regularly check for known CVEs related to your specific library versions.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'line_number': line_number # Line number for script tag might be harder to get precisely
            })
    return issues

def check_insecure_design_misconfiguration(content, line_number=None):
    """
    Checks for basic indicators of insecure design or misconfiguration.
    """
    issues = []
    # Indicator for debug mode left on
    if 'debug=true' in content.lower():
         issues.append({
            'severity': 'Low',
            'issue': 'Potential Debug Mode Indicator',
            'description': 'The string "debug=true" was found in the code, which might indicate a debug mode is enabled that could expose sensitive information or functionality in production.',
            'suggestion': 'Ensure debug modes are disabled in production environments. Implement robust logging and monitoring without exposing sensitive information to end-users.',
            'owasp_category': 'A05:2021 - Security Misconfiguration',
            'line_number': line_number
        })
    return issues

def check_software_data_integrity_failures(content, line_number=None):
    """
    Checks for insecure loading of external scripts (e.g., over HTTP instead of HTTPS).
    """
    issues = []
    # Look for script tags loading from 'http://' (insecure)
    if re.search(r'<script\s+src=["\']http://', content, re.IGNORECASE):
        issues.append({
            'severity': 'High',
            'issue': 'Insecure Script Loading (HTTP)',
            'description': 'A script is being loaded over insecure HTTP. This makes it vulnerable to tampering (e.g., Man-in-the-Middle attacks) during transit, potentially injecting malicious code.',
            'suggestion': 'Always load scripts and other critical resources over HTTPS (`https://`). Consider using Subresource Integrity (SRI) for critical third-party scripts to ensure their integrity.',
            'owasp_category': 'A08:2021 - Software and Data Integrity Failures',
            'line_number': line_number
        })
    return issues

# --- Main Scan Orchestrator ---
def perform_scan(content_to_scan):
    """
    Orchestrates the scanning process by calling individual check functions.
    For line numbers, a simple approach is to iterate through lines.
    A more advanced SAST would use an AST for precise line/column.
    """
    all_vulnerabilities = []
    lines = content_to_scan.splitlines()

    for i, line in enumerate(lines):
        # Pass line number to each check function
        all_vulnerabilities.extend(check_xss_injection(line, i + 1))
        all_vulnerabilities.extend(check_cryptographic_failures(line, i + 1))
        all_vulnerabilities.extend(check_broken_access_control(line, i + 1))
        # Note: Vulnerable components and insecure script loading are typically file-level,
        # so passing line number here might be less precise for the *exact* line of the script tag.
        # For simplicity, we'll still pass the current line.
        all_vulnerabilities.extend(check_vulnerable_components(line, i + 1))
        all_vulnerabilities.extend(check_insecure_design_misconfiguration(line, i + 1))
        all_vulnerabilities.extend(check_software_data_integrity_failures(line, i + 1))

    # Remove duplicates if multiple regexes match the same line for the same issue
    # (Though with current regexes, this might not be strictly necessary)
    unique_vulnerabilities = []
    seen = set()
    for vul in all_vulnerabilities:
        # Create a tuple of immutable fields to represent uniqueness
        issue_id = (vul.get('issue'), vul.get('description'), vul.get('line_number'))
        if issue_id not in seen:
            unique_vulnerabilities.append(vul)
            seen.add(issue_id)

    return unique_vulnerabilities

# --- Flask API Endpoint ---

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """
    API endpoint to receive code snippets or URLs for scanning.
    Expects a JSON payload with either 'code_snippet' or 'url'.
    Returns scan results in JSON format.
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid JSON payload. Please provide "code_snippet" or "url".'}), 400

    code_snippet = data.get('code_snippet')
    url = data.get('url')
    content_to_scan = ""
    
    if code_snippet:
        content_to_scan = code_snippet
    elif url:
        try:
            # Fetch content from the URL
            # Added a timeout to prevent hanging on unresponsive URLs
            response = requests.get(url, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            content_to_scan = response.text
            # For URL scanning, we assume we're interested in the HTML content
            # If the response is not HTML, we'll still try to scan for JS within it.
        except requests.exceptions.RequestException as e:
            return jsonify({
                'status': 'error',
                'message': f'Failed to fetch content from URL: {e}',
                'vulnerabilities': []
            }), 400
    else:
        return jsonify({'error': 'Missing "code_snippet" or "url" in the request payload.'}), 400

    # Perform the scan on the obtained content
    results = perform_scan(content_to_scan)

    return jsonify({
        'status': 'success',
        'summary': f"{len(results)} potential vulnerability(s) detected.",
        'vulnerabilities': results
    }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
