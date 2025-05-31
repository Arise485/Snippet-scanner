from flask import Flask, request, jsonify
from flask_cors import CORS # Import CORS
import re
import requests # For fetching content from URLs
from bs4 import BeautifulSoup # For parsing HTML from URLs

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# --- OWASP Vulnerability Scanning Logic (Enhanced for broader pattern detection) ---
# NOTE: This scanner uses pattern matching and is a simplified demonstration.
# A true multi-language SAST tool requires advanced parsing, data flow analysis,
# and language-specific engines, far beyond the scope of this single script.
# It will produce false positives and false negatives.

# Helper to classify severity for OWASP categories
def get_owasp_severity(category):
    category_map = {
        'A01:2021 - Broken Access Control': 'High',
        'A02:2021 - Cryptographic Failures': 'High',
        'A03:2021 - Injection': 'High',
        'A04:2021 - Insecure Design': 'Medium',
        'A05:2021 - Security Misconfiguration': 'Medium',
        'A06:2021 - Vulnerable and Outdated Components': 'Medium',
        'A07:2021 - Identification and Authentication Failures': 'High',
        'A08:2021 - Software and Data Integrity Failures': 'High',
        'A09:2021 - Security Logging and Monitoring Failures': 'Low', # Hard to prove impact statically
        'A10:2021 - Server-Side Request Forgery (SSRF)': 'High',
    }
    return category_map.get(category, 'Info')


def check_a03_injection(content, line_number=None):
    """
    A03:2021 - Injection
    Checks for potential SQL, NoSQL, OS Command, LDAP, XSS, and other injection vulnerabilities.
    Looks for dangerous function calls with potentially untrusted input, common patterns.
    This is highly simplified and illustrative.
    """
    issues = []

    # SQL/NoSQL Injection (simplified: looks for common query patterns without parameterization)
    sql_patterns = [
        r'\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*\b(?:[\'"].*?[\'"]\s*\+|\+?\s*[\'"].*?[\'"])\b', # concat in queries
        r'\b(?:mysql_query|mysqli_query|pg_query|db\.collection\.[find|update|remove])\s*\(.*?\b\$\w+\b', # PHP/JS query with variable
        r'\b(?:createStatement|prepareStatement|execute|executeQuery|executeUpdate)\b.*\b\+\s*\w+\b', # Java/C# JDBC/ORM issues
        r'\b(?:exec|system|popen|passthru|shell_exec|subprocess\.run|os\.system)\b.*\b\$\w+\b', # OS Command Injection
        r'\bformat\s*\(.*?\s*{}\s*\+\s*\w+\b', # Python format string potential injection
        r'\bprintf\s*\(.*?\s*(%[diouxXcbsn])\b', # C/C++ format string vulnerability
        r'\bconcat\(.+?\)', # Generic string concat often used in injections
    ]
    for pattern in sql_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A03:2021 - Injection'),
                'issue': 'Potential SQL/Command/Format String Injection',
                'description': 'Identified patterns that may indicate unsafe use of concatenated strings in database queries or OS commands. This could lead to SQL Injection, OS Command Injection, or other code execution if untrusted input is not properly sanitized or parameterized.',
                'suggestion': 'Always use parameterized queries (prepared statements) for database interactions. Avoid building shell commands with user input. Use safe functions for string formatting and always validate and sanitize all user-supplied data.',
                'owasp_category': 'A03:2021 - Injection',
                'line_number': line_number
            })
            break # Flag once per line

    # Cross-Site Scripting (XSS) - client-side DOM/script injection
    xss_patterns = [
        r'(document\.write|innerHTML|outerHTML|eval|setTimeout|setInterval|script\.text|script\.src)\s*=\s*[^;]*(\bwindow\.location\.(?:hash|search)|[\'"`][^\'"`]*\+[^;]*\buser_input\b|\binputElement\.value\b|\burlParams\.get\b|\b\.value\b|\b\.data\b|\b\.name\b)', # DOM XSS
        r'<(script|img|body|svg|link)[^>]*?(src|href|onload|onerror|onclick|style|background)=[\'"]?javascript:', # Reflected/Stored XSS common attributes
        r'location\.href\s*=\s*[\'"`][^\'"`]*\+[^;]*\buser_input\b', # Redirect XSS
    ]
    for pattern in xss_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A03:2021 - Injection'),
                'issue': 'Potential Cross-Site Scripting (XSS)',
                'description': 'Potential unsafe use of direct DOM manipulation or untrusted data in script/HTML attributes. This may lead to Cross-Site Scripting (XSS) if user-supplied input is not properly encoded/sanitized.',
                'suggestion': 'Always sanitize and encode all user-supplied data before inserting it into the DOM. Use `textContent` instead of `innerHTML` when not inserting HTML. Implement Content Security Policy (CSP).',
                'owasp_category': 'A03:2021 - Injection',
                'line_number': line_number
            })
            break # Flag once per line

    return issues

def check_a02_cryptographic_failures(content, line_number=None):
    """
    A02:2021 - Cryptographic Failures
    Checks for hardcoded sensitive data, weak crypto indicators, or insecure storage.
    """
    issues = []

    # Hardcoded sensitive data (broader keywords)
    hardcoded_patterns = [
        r'(api_key|secret|token|password|credential|private_key|aws_access_key|stripe_key|db_password)\s*=\s*["\'][^"\']*["\']', # Direct assignment
        r'define\s*\([\s\'"](?:API_KEY|SECRET|PASSWORD)[\'"],\s*[\'"].*?[\'"]\s*\)', # PHP define
        r'\bkey\s*:\s*["\'][^"\']*["\']', # Generic key:value pair
        r'localStorage\.setItem\s*\([\s\'"](?:api_key|secret|token|password)[\'"]', # Insecure client-side storage
        r'sessionStorage\.setItem\s*\([\s\'"](?:api_key|secret|token|password)[\'"]',
        r'document\.cookie\s*=\s*[\'"].*?(?:token|password|secret)=[^;]+',
    ]
    for pattern in hardcoded_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A02:2021 - Cryptographic Failures'),
                'issue': 'Hardcoded Sensitive Data / Insecure Client-Side Storage',
                'description': 'Sensitive data (e.g., API keys, secrets, passwords) appears to be hardcoded or stored insecurely on the client-side. This exposes confidential information.',
                'suggestion': 'Sensitive data should never be hardcoded or stored directly on the client. Use secure server-side methods (environment variables, vault services). Transmit secrets only when necessary via HTTPS. For client-side tokens, use HttpOnly, Secure cookies.',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'line_number': line_number
            })
            break

    # Weak/Deprecated Crypto (very basic, looks for algorithm names)
    weak_crypto_patterns = [
        r'\b(?:md5|sha1)\b(?![^\(]*\w+\(\w*\))', # Detect md5/sha1 calls (avoiding things like "md5_file")
        r'\b(?:des|rc4|blowfish)\b', # Weak ciphers
        r'\b(?:http\:\/\/)(?!localhost|127\.0\.0\.1)', # Non-HTTPS communication in code
    ]
    for pattern in weak_crypto_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A02:2021 - Cryptographic Failures'),
                'issue': 'Weak/Deprecated Cryptography or Insecure Communication',
                'description': 'Detected use of weak/deprecated cryptographic algorithms (e.g., MD5, SHA1) or communication over plain HTTP. This can compromise data confidentiality and integrity.',
                'suggestion': 'Use strong, modern cryptographic algorithms (e.g., SHA-256+, AES-256, Argon2). Always use HTTPS for all communication. Ensure proper key management.',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'line_number': line_number
            })
            break

    return issues

def check_a01_broken_access_control(content, line_number=None):
    """
    A01:2021 - Broken Access Control
    Checks for client-side enforcement indicators and insecure direct object references.
    """
    issues = []

    # Client-side UI element control based on roles (broader detection)
    client_side_control_patterns = [
        r'\bif\s*\((?:user|role|isAdmin|isAuthenticated)\.[\w.]+\s*===?\s*[\'"](?:admin|guest|user)[\'"]\)\s*\{[^}]*(?:style\.display\s*=\s*[\'"]none[\'"]|hidden\s*=\s*true|disabled\s*=\s*true|readOnly\s*=\s*true|classList\.add\s*\([^\)]*hidden\b|\.remove\(\))',
        r'\b(?:localStorage|sessionStorage|document\.cookie)\b[^;]*(?:role|isAdmin|permissions)\b', # Storing roles/permissions client-side
        r'\$.ajax\([^)]*url:\s*[\'"].*?/admin/', # jQuery AJAX calls to admin paths without explicit data/auth
    ]
    for pattern in client_side_control_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            issues.append({
                'severity': get_owasp_severity('A01:2021 - Broken Access Control'),
                'issue': 'Client-Side Access Control Enforcement or Insecure Role Storage',
                'description': 'Access control logic (e.g., checking for specific roles or permissions) appears to be enforced primarily on the client-side, or sensitive role information is stored client-side. This can be easily bypassed by attackers manipulating browser code or network requests. Content may be delivered to unauthorized users and merely hidden.',
                'suggestion': 'Always enforce access control and authorization decisions on the server-side. Client-side logic should only be for UI presentation, not security enforcement. All sensitive operations and content access must be validated on the server. Never store sensitive role/permission data in client-side storage.',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'line_number': line_number
            })
            break

    # Insecure Direct Object Reference (IDOR) - simplified regex for common patterns
    # Very hard to detect accurately via static regex, relies on URL patterns or DB query patterns
    idor_patterns = [
        r'\b(?:id|user_id|account_id|doc_id|file_id)=\s*[\'"]?\d+[\'"]?\b', # common URL params, expecting sequential IDs
        r'\/(?:user|account|order|document)\/\d+', # RESTful path with sequential IDs
    ]
    for pattern in idor_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            # This is extremely prone to false positives, as these are normal parameters.
            # It flags *potential* IDOR if not properly validated server-side.
            issues.append({
                'severity': get_owasp_severity('A01:2021 - Broken Access Control'),
                'issue': 'Potential Insecure Direct Object Reference (IDOR)',
                'description': 'References to direct object IDs (e.g., `user_id=123`) found. If these identifiers are predictable and not properly validated server-side to ensure the requesting user is authorized to access *that specific resource*, an attacker could bypass authorization by changing the ID.',
                'suggestion': 'Always validate that the authenticated user is authorized to access the specific resource identified by any ID in the request. Use non-sequential or GUIDs where possible, and always implement strong server-side authorization checks.',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'line_number': line_number
            })
            break

    return issues

def check_a06_vulnerable_components(content, line_number=None):
    """
    A06:2021 - Vulnerable and Outdated Components
    Performs a very basic check for known vulnerable library versions in script tags or common package managers.
    This is illustrative and not a substitute for a dedicated SCA (Software Composition Analysis) tool.
    """
    issues = []
    # Illustrative vulnerable library versions (in a real scenario, this would be from a CVE database)
    vulnerable_libs = {
        'jquery': r'jquery-(1\.\d+\.\d+|2\.\d+\.\d+|3\.0\.\d+|3\.1\.\d+|3\.2\.\d+|3\.3\.\d+)(?:\.min)?\.js',
        'angularjs': r'angular(?:js)?-(1\.[0-5]\.\d+)(?:\.min)?\.js', # Older Angular versions
        'react': r'react-(0\.\d+\.\d+|15\.\d+\.\d+)(?:\.min)?\.js', # Older React versions (highly simplified)
        # More could be added based on common vulnerable versions
    }

    # For HTML/JS files, check script tags
    soup = BeautifulSoup(content, 'html.parser')
    for script_tag in soup.find_all('script', src=True):
        src = script_tag['src'].lower()
        for lib_name, pattern in vulnerable_libs.items():
            match = re.search(pattern, src, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else 'unknown'
                issues.append({
                    'severity': get_owasp_severity('A06:2021 - Vulnerable and Outdated Components'),
                    'issue': f'Vulnerable {lib_name.capitalize()} Version Detected',
                    'description': f'An old or potentially vulnerable version of {lib_name.capitalize()} ({version}) was detected via script include. These versions have known security vulnerabilities.',
                    'suggestion': f'Update {lib_name.capitalize()} to the latest stable version. Regularly use a Software Composition Analysis (SCA) tool (e.g., Retire.js, OWASP Dependency-Check) to scan for known CVEs in your dependencies.',
                    'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                    'line_number': line_number # Best effort line number for script tag
                })

    # For other file types, look for package manager config (very basic)
    if any(ext in request.path for ext in ['.json', '.xml', '.csproj', '.gradle', '.pom', 'package.json']): # Heuristic for file type
        # Python: requirements.txt, setup.py
        if re.search(r'(django|flask|requests|numpy|pandas)==(1\.\d+|2\.[0-3])', content, re.IGNORECASE): # Example older versions
             issues.append({
                'severity': get_owasp_severity('A06:2021 - Vulnerable and Outdated Components'),
                'issue': 'Potential Outdated Python Package',
                'description': 'Detected an outdated Python package. Ensure all dependencies are up-to-date and free from known vulnerabilities.',
                'suggestion': 'Use `pip list --outdated` and `pip install --upgrade` to update packages. Regularly check PyPI and CVE databases.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'line_number': line_number
            })
        # Node.js: package.json
        if re.search(r'"(express|lodash|react)"\s*:\s*"(\^?[0-3]\.\d+\.\d+)"', content, re.IGNORECASE): # Example older Node.js packages
             issues.append({
                'severity': get_owasp_severity('A06:2021 - Vulnerable and Outdated Components'),
                'issue': 'Potential Outdated Node.js Package',
                'description': 'Detected an outdated Node.js package. Ensure all dependencies are up-to-date and free from known vulnerabilities.',
                'suggestion': 'Use `npm audit` or `yarn audit` to identify and fix vulnerabilities. Regularly update your project dependencies.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'line_number': line_number
            })
        # Java: pom.xml (Maven), build.gradle (Gradle)
        if re.search(r'<artifactId>(spring-core|log4j|jackson-databind)</artifactId>\s*<version>(\[?[1-2]\.\d+|[2-3]\.[0-9]\.\d+)</version>', content, re.IGNORECASE): # Example older Java libs
            issues.append({
                'severity': get_owasp_severity('A06:2021 - Vulnerable and Outdated Components'),
                'issue': 'Potential Outdated Java Library',
                'description': 'Detected an outdated Java library. Ensure all dependencies are up-to-date and free from known vulnerabilities.',
                'suggestion': 'Use tools like OWASP Dependency-Check or Snyk to scan your Java dependencies. Regularly update your project dependencies.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'line_number': line_number
            })
        # PHP: composer.json
        if re.search(r'"(laravel/framework|symfony/symfony|guzzlehttp/guzzle)"\s*:\s*"(\^?[0-5]\.\d+)"', content, re.IGNORECASE): # Example older PHP frameworks
            issues.append({
                'severity': get_owasp_severity('A06:2021 - Vulnerable and Outdated Components'),
                'issue': 'Potential Outdated PHP Package',
                'description': 'Detected an outdated PHP package. Ensure all dependencies are up-to-date and free from known vulnerabilities.',
                'suggestion': 'Use `composer outdated` and `composer update`. Regularly check Packagist and CVE databases.',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'line_number': line_number
            })


    return issues

def check_a05_security_misconfiguration(content, line_number=None):
    """
    A05:2021 - Security Misconfiguration
    Checks for common misconfigurations like debug mode, verbose errors, default credentials.
    """
    issues = []

    misconfig_patterns = [
        r'(debug|dev|test)\s*=\s*(?:true|1)', # Debug mode indicators
        r'(display_errors|expose_php)\s*=\s*(?:on|true)', # PHP verbose errors
        r'(e\.printStackTrace|console\.log\(error|printStackTrace)', # Excessive error logging to client
        r'(?:username|user|admin)\s*=\s*["\']admin["\']\s*and\s*(?:password|pass)\s*=\s*["\']password["\']', # Default credentials
        r'\bsecret_key\s*=\s*["\']your_secret_key_here["\']', # Default secret key
        r'\.(bak|old|temp|zip|rar|7z|tar\.gz)', # Backup files or temporary files mentioned in code
        r'\b(?:phpinfo\(\)|var_dump|print_r|die\("debug"\))', # Debug functions left in production code
    ]
    for pattern in misconfig_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A05:2021 - Security Misconfiguration'),
                'issue': 'Potential Security Misconfiguration',
                'description': 'Indicators of debug mode, verbose error messages, or default/weak credentials found. These misconfigurations can expose sensitive information, bypass security controls, or aid attackers.',
                'suggestion': 'Ensure debug modes are disabled in production. Disable verbose error reporting on public-facing sites. Never use default credentials. Securely manage all configuration settings.',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'line_number': line_number
            })
            break

    return issues

def check_a08_software_data_integrity_failures(content, line_number=None):
    """
    A08:2021 - Software and Data Integrity Failures
    Checks for insecure loading of external scripts (e.g., over HTTP instead of HTTPS)
    and lack of Subresource Integrity (SRI) for critical third-party resources.
    Also looks for insecure updates/deserialization indicators.
    """
    issues = []
    # Insecure script loading (HTTP)
    if re.search(r'<script\s+src=["\']http://(?!localhost|127\.0\.0\.1)', content, re.IGNORECASE):
        issues.append({
            'severity': get_owasp_severity('A08:2021 - Software and Data Integrity Failures'),
            'issue': 'Insecure Script Loading (HTTP)',
            'description': 'A script is being loaded over insecure HTTP. This makes it vulnerable to tampering (e.g., Man-in-the-Middle attacks) during transit, potentially injecting malicious code.',
            'suggestion': 'Always load scripts and other critical resources over HTTPS (`https://`).',
            'owasp_category': 'A08:2021 - Software and Data Integrity Failures',
            'line_number': line_number
        })

    # Missing Subresource Integrity (SRI) for CDN scripts
    # This is a heuristic and can have false positives. It looks for common CDNs but no SRI.
    if re.search(r'<script\s+src=["\']https:\/\/(?:cdn\.)?(?:jsdelivr\.net|cdnjs\.cloudflare\.com|ajax\.googleapis\.com)[^>]*?>(?!.*integrity=")', content, re.IGNORECASE):
        issues.append({
            'severity': get_owasp_severity('A08:2021 - Software and Data Integrity Failures'),
            'issue': 'Missing Subresource Integrity (SRI) for CDN Script',
            'description': 'A script is loaded from a CDN without Subresource Integrity (SRI). This means if the CDN is compromised, the script could be maliciously altered without detection.',
            'suggestion': 'Implement Subresource Integrity (SRI) on all scripts loaded from third-party CDNs to ensure their integrity. Example: `<script src="..." integrity="sha256-..." crossorigin="anonymous"></script>`',
            'owasp_category': 'A08:2021 - Software and Data Integrity Failures',
            'line_number': line_number
        })

    # Insecure Deserialization (very hard to detect purely by regex, looks for patterns)
    deserialization_patterns = [
        r'\b(?:unserialize|pickle\.load|ObjectInputStream\.readObject|json\.loads)\b', # Common deserialization functions
        r'\b(?:base64_decode)\b', # Can be used before unserialize
    ]
    for pattern in deserialization_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A08:2021 - Software and Data Integrity Failures'),
                'issue': 'Potential Insecure Deserialization',
                'description': 'Detected use of deserialization functions. If untrusted data is deserialized without proper validation and sanitization, it can lead to remote code execution, denial-of-service, or other attacks.',
                'suggestion': 'Avoid deserializing untrusted data. If necessary, use secure, integrity-checked serialization formats (e.g., JSON with schema validation). Implement strict type checking and restrict gadgets if using object deserialization.',
                'owasp_category': 'A08:2021 - Software and Data Integrity Failures',
                'line_number': line_number
            })
            break

    return issues

def check_a07_identification_authentication_failures(content, line_number=None):
    """
    A07:2021 - Identification and Authentication Failures
    Checks for common weak password patterns (client-side), lack of MFA mentions,
    and potential session management issues (very basic).
    """
    issues = []

    # Weak password patterns (client-side/hardcoded)
    weak_password_patterns = [
        r'password\s*=\s*["\'](?:123456|password|admin|test|qwerty)[\'"]',
        r'confirmPassword', # No confirmation field in frontend
        r'password\.length\s*<\s*(?:6|8)', # Client-side password length checks (too low)
    ]
    for pattern in weak_password_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A07:2021 - Identification and Authentication Failures'),
                'issue': 'Weak Password Handling / Hardcoded Weak Password',
                'description': 'Detected patterns indicating hardcoded weak passwords, or client-side validation for passwords that might be too lenient. This can lead to easily guessable credentials and account compromise.',
                'suggestion': 'Enforce strong, server-side password policies (minimum length, complexity, no common patterns). Never hardcode passwords. Implement multi-factor authentication (MFA) and account lockout mechanisms.',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures',
                'line_number': line_number
            })
            break

    # Lack of secure cookie flags (HttpOnly, Secure, SameSite) - client-side
    if re.search(r'document\.cookie\s*=\s*[\'"][^;]+(?:session|token)=[^;]+(?!;\s*httponly)(?!;\s*secure)(?!;\s*samesite)', content, re.IGNORECASE):
        issues.append({
            'severity': get_owasp_severity('A07:2021 - Identification and Authentication Failures'),
            'issue': 'Insecure Cookie Attributes',
            'description': 'Cookies appear to be set without `HttpOnly`, `Secure`, or `SameSite` attributes. This can expose session tokens to XSS attacks, man-in-the-middle attacks, or CSRF.',
            'suggestion': 'Always set `HttpOnly` to prevent client-side script access, `Secure` for HTTPS-only transmission, and `SameSite=Lax` or `Strict` to mitigate CSRF. Validate session tokens on every request.',
            'owasp_category': 'A07:2021 - Identification and Authentication Failures',
            'line_number': line_number
        })

    return issues

def check_a04_insecure_design(content, line_number=None):
    """
    A04:2021 - Insecure Design
    This category is very hard for static analysis without architectural context.
    We'll look for very simple indicators like explicit comments related to bypassing
    security, or exposed internal APIs.
    """
    issues = []
    insecure_design_patterns = [
        r'//\s*TODO:\s*Add\s*(?:auth|validation|sanitization)\s*here', # Unfinished security
        r'//\s*Bypass\s*(?:security|auth|validation)', # Explicit bypass comments
        r'\/api\/v1\/internal\b', # Exposed internal API paths (heuristic)
    ]
    for pattern in insecure_design_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A04:2021 - Insecure Design'),
                'issue': 'Potential Insecure Design Pattern',
                'description': 'Detected patterns that might indicate an insecure design choice or an incomplete security implementation (e.g., TODO comments for missing security, exposed internal API paths).',
                'suggestion': 'Review application architecture for security vulnerabilities. Ensure security requirements are explicitly defined and implemented throughout the design phase (Security by Design). Address all pending security TODOs before deployment.',
                'owasp_category': 'A04:2021 - Insecure Design',
                'line_number': line_number
            })
            break
    return issues

def check_a09_security_logging_monitoring_failures(content, line_number=None):
    """
    A09:2021 - Security Logging and Monitoring Failures
    Extremely difficult for static analysis. This will be very basic.
    Looks for lack of specific logging calls around sensitive operations.
    """
    issues = []
    # Very crude heuristic: looking for operations without explicit logging related to security.
    # This is prone to false positives and negatives.
    sensitive_operations = [
        r'\b(?:login|register|changePassword|deleteUser)\b', # Common sensitive ops
        r'\b(?:updateUserRole|grantPermission)\b', # Admin ops
    ]
    logging_keywords = r'(?:log|audit|logger|print|console\.log|syslog|error_log)'

    for op_pattern in sensitive_operations:
        # Check if sensitive operation is NOT immediately followed by a logging keyword on the same line
        # This is a very weak heuristic. A proper check would require AST.
        if re.search(op_pattern, content, re.IGNORECASE) and not re.search(op_pattern + r'.*?' + logging_keywords, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A09:2021 - Security Logging and Monitoring Failures'),
                'issue': 'Potential Lack of Security Logging',
                'description': 'A sensitive operation might not be adequately logged. Insufficient logging and monitoring can mask breaches, delay detection, and impede incident response.',
                'suggestion': 'Ensure all critical security events (logins, failed attempts, access control violations, data modifications) are logged with sufficient context. Implement robust monitoring, alerting, and incident response plans.',
                'owasp_category': 'A09:2021 - Security Logging and Monitoring Failures',
                'line_number': line_number
            })
            break # Flag once per line

    return issues

def check_a10_ssrf(content, line_number=None):
    """
    A10:2021 - Server-Side Request Forgery (SSRF)
    Checks for patterns where server-side requests are made to user-supplied URLs without validation.
    This is relevant for the scanner's own backend logic when scanning URLs.
    """
    issues = []
    # This check specifically targets the *user's code* that the scanner is analyzing,
    # looking for patterns that might lead to SSRF in *their* application.
    # It's NOT about the scanner's own SSRF vulnerability (which is handled by `requests.get` implicitly).

    ssrf_patterns = [
        r'\b(?:curl|file_get_contents|fsockopen|HttpRequest|WebClient\.DownloadString|HttpURLConnection\.openConnection|requests\.get)\b.*?\b(url|uri|host)\b', # Common HTTP client functions
        r'\bredirect\s*=\s*\$\w+', # Open redirects which can lead to SSRF if used internally
    ]
    for pattern in ssrf_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({
                'severity': get_owasp_severity('A10:2021 - Server-Side Request Forgery (SSRF)'),
                'issue': 'Potential Server-Side Request Forgery (SSRF)',
                'description': 'Detected server-side functions (e.g., cURL, `requests.get`) that might accept and process user-supplied URLs without sufficient validation. An attacker could force the server to make requests to internal network resources or other external systems.',
                'suggestion': 'Always validate user-supplied URLs rigorously. Implement a whitelist of allowed domains/protocols. Disallow redirects to internal or blacklisted IPs. Consider network segmentation to prevent internal access.',
                'owasp_category': 'A10:2021 - Server-Side Request Forgery (SSRF)',
                'line_number': line_number
            })
            break
    return issues


# --- Main Scan Orchestrator ---
def perform_scan(content_to_scan):
    """
    Orchestrates the scanning process by calling individual check functions.
    For line numbers, a simple approach is to iterate through lines.
    """
    all_vulnerabilities = []
    lines = content_to_scan.splitlines()

    for i, line in enumerate(lines):
        # Pass line number to each check function
        all_vulnerabilities.extend(check_a03_injection(line, i + 1))
        all_vulnerabilities.extend(check_a02_cryptographic_failures(line, i + 1))
        all_vulnerabilities.extend(check_a01_broken_access_control(line, i + 1))
        all_vulnerabilities.extend(check_a06_vulnerable_components(line, i + 1)) # This function may need full content for script tags
        all_vulnerabilities.extend(check_a05_security_misconfiguration(line, i + 1))
        all_vulnerabilities.extend(check_a08_software_data_integrity_failures(line, i + 1)) # This function may need full content for script tags
        all_vulnerabilities.extend(check_a07_identification_authentication_failures(line, i + 1))
        all_vulnerabilities.extend(check_a04_insecure_design(line, i + 1))
        all_vulnerabilities.extend(check_a09_security_logging_monitoring_failures(line, i + 1))
        all_vulnerabilities.extend(check_a10_ssrf(line, i + 1))

    # Re-run file-level checks with full content to ensure BeautifulSoup works correctly
    # Note: BeautifulSoup only works on HTML content. For other languages, it will be skipped.
    all_vulnerabilities.extend(check_a06_vulnerable_components(content_to_scan, None)) # Pass None for line_number as it's file-level
    all_vulnerabilities.extend(check_a08_software_data_integrity_failures(content_to_scan, None))

    # Remove duplicates (important as checks might overlap or run on whole content/line)
    unique_vulnerabilities = []
    seen = set()
    for vul in all_vulnerabilities:
        # Create a tuple of immutable fields to represent uniqueness
        # Combining issue, description, and line number for uniqueness
        issue_id = (vul.get('issue'), vul.get('description'), vul.get('line_number'), vul.get('owasp_category'))
        if issue_id not in seen:
            unique_vulnerabilities.append(vul)
            seen.add(issue_id)

    return unique_vulnerabilities

# --- Flask API Endpoint ---

@app.route('/scan', methods=['POST'])
def scan_endpoint():
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
            # Basic URL validation for SSRF prevention in the scanner itself
            # IMPORTANT: This is a minimal example. A robust SSRF defense needs a whitelist,
            # strict IP blocking (private, loopback), and careful handling of redirects.
            parsed_url = requests.utils.urlparse(url)
            if parsed_url.scheme not in ['http', 'https']:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid URL scheme. Only http or https are allowed.',
                    'vulnerabilities': []
                }), 400
            # You might want to add more checks here, e.g., to prevent internal IP ranges
            # For demonstration, we'll proceed, but be aware of SSRF risk if this were
            # production and allowed arbitrary URLs.

            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content_to_scan = response.text
        except requests.exceptions.RequestException as e:
            return jsonify({
                'status': 'error',
                'message': f'Failed to fetch content from URL: {e}',
                'vulnerabilities': []
            }), 400
    else:
        return jsonify({'error': 'Missing "code_snippet" or "url" in the request payload.'}), 400

    results = perform_scan(content_to_scan)

    return jsonify({
        'status': 'success',
        'summary': f"{len(results)} potential vulnerability(s) detected.",
        'vulnerabilities': results
    }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5050)
