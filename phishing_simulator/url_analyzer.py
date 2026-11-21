"""
URL Analyzer Module
===================
Analyzes URLs for phishing indicators using multiple detection techniques.

Detection Techniques:
- Typosquatting detection (domain similarity to known brands)
- Homoglyph attack detection (unicode lookalike characters)
- URL structure analysis (suspicious patterns, excessive depth)
- IP-based URL detection
- URL shortener detection
- Domain entropy analysis (randomness indicates DGA)
- Subdomain abuse detection
- TLD reputation analysis
"""

import re
import math
import hashlib
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


@dataclass
class Finding:
    """A single finding from URL analysis."""
    category: str           # e.g., "typosquatting", "structure", "entropy"
    severity: str           # LOW, MEDIUM, HIGH, CRITICAL
    description: str        # Human-readable description
    score_impact: int       # Points added to risk score (0-25)
    details: Optional[str] = None  # Additional technical details


@dataclass
class DomainInfo:
    """Information extracted from the domain."""
    full_domain: str
    registered_domain: str
    tld: str
    subdomains: List[str]
    is_ip: bool
    entropy: float


@dataclass
class URLAnalysisResult:
    """Complete result of URL analysis."""
    url: str
    risk_score: int                     # 0-100
    risk_level: str                     # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    findings: List[Finding] = field(default_factory=list)
    domain_info: Optional[DomainInfo] = None
    is_shortened: bool = False
    has_ssl: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def summary(self) -> str:
        """Generate a human-readable summary."""
        return (
            f"URL Risk Assessment: {self.risk_level} ({self.risk_score}/100)\n"
            f"Findings: {len(self.findings)} issue(s) detected\n"
            f"SSL: {'Yes' if self.has_ssl else 'No'} | "
            f"Shortened: {'Yes' if self.is_shortened else 'No'}"
        )


class URLAnalyzer:
    """
    Comprehensive URL phishing detection engine.

    Analyzes URLs using multiple heuristic techniques to determine
    the likelihood that a URL is part of a phishing attack.

    Usage:
        analyzer = URLAnalyzer()
        result = analyzer.analyze_url("http://g00gle.com/login")
        print(result.risk_score, result.risk_level)
    """

    # Known legitimate brands and their domains
    KNOWN_BRANDS = {
        "google": ["google.com", "gmail.com", "youtube.com"],
        "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
        "apple": ["apple.com", "icloud.com"],
        "amazon": ["amazon.com", "aws.amazon.com"],
        "paypal": ["paypal.com"],
        "netflix": ["netflix.com"],
        "facebook": ["facebook.com", "fb.com"],
        "instagram": ["instagram.com"],
        "linkedin": ["linkedin.com"],
        "twitter": ["twitter.com", "x.com"],
        "dropbox": ["dropbox.com"],
        "chase": ["chase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com"],
        "github": ["github.com"],
        "slack": ["slack.com"],
        "zoom": ["zoom.us"],
    }

    # Suspicious TLDs often used in phishing
    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq",    # Free domains
        ".xyz", ".top", ".work", ".click",      # Cheap/abused TLDs
        ".link", ".info", ".bid", ".win",
        ".review", ".stream", ".racing",
        ".download", ".loan", ".date",
        ".faith", ".science", ".party",
    }

    # Known URL shortener domains
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "tiny.cc", "lnkd.in",
        "rb.gy", "cutt.ly", "shorturl.at", "v.gd", "t.ly",
    }

    # Homoglyph (lookalike) character mappings
    HOMOGLYPHS = {
        'a': ['а', 'ą', 'å', 'ä', 'á', 'à', 'ã'],  # Cyrillic а
        'e': ['е', 'ė', 'ę', 'ë', 'é', 'è'],         # Cyrillic е
        'o': ['о', 'ö', 'ó', 'ò', 'ø', '0'],          # Cyrillic о, zero
        'i': ['і', 'ï', 'í', 'ì', '1', 'l', '|'],     # Cyrillic і
        'l': ['1', 'I', '|', 'ı'],
        'c': ['с', 'ç'],                                # Cyrillic с
        'p': ['р'],                                      # Cyrillic р
        's': ['ş', 'ś', '$', '5'],
        'g': ['ğ', '9'],
        'n': ['ñ', 'ń'],
        't': ['ţ', 'ť', '+'],
        'u': ['ü', 'ú', 'ù', 'û'],
    }

    def __init__(self):
        self._all_brand_domains = set()
        for domains in self.KNOWN_BRANDS.values():
            self._all_brand_domains.update(domains)

    def analyze_url(self, url: str) -> URLAnalysisResult:
        """
        Perform comprehensive URL analysis for phishing indicators.

        Args:
            url: The URL to analyze

        Returns:
            URLAnalysisResult with risk score, level, and detailed findings
        """
        findings: List[Finding] = []

        # Normalize URL
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
        except Exception:
            return URLAnalysisResult(
                url=url, risk_score=100, risk_level="CRITICAL",
                findings=[Finding("parse_error", "CRITICAL",
                                   "URL could not be parsed", 100)]
            )

        domain = parsed.netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]  # Remove port

        # Extract domain info
        domain_info = self._extract_domain_info(domain)

        # Run all checks
        findings.extend(self._check_https(url, parsed))
        findings.extend(self._check_ip_based_url(domain))
        findings.extend(self._check_url_shortener(domain))
        findings.extend(self._check_suspicious_tld(domain_info))
        findings.extend(self._check_subdomain_abuse(domain_info))
        findings.extend(self._check_domain_similarity(domain))
        findings.extend(self._check_homoglyph_attack(domain))
        findings.extend(self._check_url_structure(url, parsed))
        findings.extend(self._check_entropy(domain_info))

        # Calculate total risk score
        raw_score = sum(f.score_impact for f in findings)
        risk_score = min(100, raw_score)

        # Determine risk level
        risk_level = self._score_to_level(risk_score)

        return URLAnalysisResult(
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            domain_info=domain_info,
            is_shortened=any(f.category == "url_shortener" for f in findings),
            has_ssl=parsed.scheme == "https",
        )

    def _extract_domain_info(self, domain: str) -> DomainInfo:
        """Extract structured information from domain."""
        parts = domain.split('.')
        is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))

        if is_ip:
            return DomainInfo(
                full_domain=domain,
                registered_domain=domain,
                tld="",
                subdomains=[],
                is_ip=True,
                entropy=self._calculate_entropy(domain),
            )

        tld = '.' + parts[-1] if parts else ''
        registered = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        subdomains = parts[:-2] if len(parts) > 2 else []

        return DomainInfo(
            full_domain=domain,
            registered_domain=registered,
            tld=tld,
            subdomains=subdomains,
            is_ip=False,
            entropy=self._calculate_entropy(registered.split('.')[0]),
        )

    def _check_https(self, url: str, parsed) -> List[Finding]:
        """Check if URL uses HTTPS."""
        findings = []
        if parsed.scheme != "https":
            findings.append(Finding(
                category="ssl",
                severity="MEDIUM",
                description="URL does not use HTTPS encryption",
                score_impact=10,
                details="Legitimate login pages almost always use HTTPS."
            ))
        return findings

    def _check_ip_based_url(self, domain: str) -> List[Finding]:
        """
        Detect IP-based URLs instead of domain names.

        Security Concept:
            Phishers often use raw IP addresses to avoid domain-based
            detection and to hide the true destination of links.
        """
        findings = []
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            findings.append(Finding(
                category="ip_based",
                severity="HIGH",
                description="URL uses an IP address instead of a domain name",
                score_impact=25,
                details=f"IP-based URL detected: {domain}. "
                        "Legitimate services use domain names."
            ))
        # Also check for hex/octal IP obfuscation
        elif re.match(r'^0x[0-9a-f]+$', domain, re.IGNORECASE):
            findings.append(Finding(
                category="ip_based",
                severity="CRITICAL",
                description="URL uses obfuscated IP address (hex encoding)",
                score_impact=30,
            ))
        return findings

    def _check_url_shortener(self, domain: str) -> List[Finding]:
        """
        Detect URL shortener usage.

        Security Concept:
            URL shorteners hide the true destination URL, making it
            impossible for users to verify where a link leads before clicking.
        """
        findings = []
        if domain in self.URL_SHORTENERS:
            findings.append(Finding(
                category="url_shortener",
                severity="MEDIUM",
                description=f"URL shortener detected: {domain}",
                score_impact=15,
                details="Shortened URLs hide the true destination and are "
                        "commonly used in phishing attacks."
            ))
        return findings

    def _check_suspicious_tld(self, domain_info: DomainInfo) -> List[Finding]:
        """
        Check for suspicious top-level domains.

        Security Concept:
            Certain TLDs are frequently abused for phishing because they
            offer free or very cheap domain registration.
        """
        findings = []
        if domain_info.tld in self.SUSPICIOUS_TLDS:
            findings.append(Finding(
                category="suspicious_tld",
                severity="MEDIUM",
                description=f"Suspicious TLD detected: {domain_info.tld}",
                score_impact=12,
                details=f"The TLD '{domain_info.tld}' is frequently used "
                        "in phishing attacks due to free/cheap registration."
            ))
        return findings

    def _check_subdomain_abuse(self, domain_info: DomainInfo) -> List[Finding]:
        """
        Detect excessive subdomain usage.

        Security Concept:
            Phishers add legitimate-looking subdomains to make URLs appear
            trustworthy, e.g., 'login.google.com.evil.com'
        """
        findings = []
        subs = domain_info.subdomains

        if len(subs) > 3:
            findings.append(Finding(
                category="subdomain_abuse",
                severity="HIGH",
                description=f"Excessive subdomains detected ({len(subs)} levels)",
                score_impact=20,
                details="Multiple subdomain levels are uncommon for legitimate "
                        "sites and may be used to hide the actual domain."
            ))
        elif len(subs) > 1:
            findings.append(Finding(
                category="subdomain_abuse",
                severity="LOW",
                description=f"Multiple subdomains detected ({len(subs)} levels)",
                score_impact=5,
            ))

        # Check if subdomains contain brand names (impersonation)
        for sub in subs:
            for brand in self.KNOWN_BRANDS:
                if brand in sub.lower() and domain_info.registered_domain not in self.KNOWN_BRANDS.get(brand, []):
                    findings.append(Finding(
                        category="brand_subdomain",
                        severity="HIGH",
                        description=f"Brand name '{brand}' found in subdomain "
                                    f"of non-brand domain",
                        score_impact=25,
                        details=f"Subdomain '{sub}' mimics '{brand}' but the "
                                f"actual domain is '{domain_info.registered_domain}'"
                    ))
                    break

        return findings

    def _check_domain_similarity(self, domain: str) -> List[Finding]:
        """
        Check domain similarity to known brands (typosquatting detection).

        Security Concept:
            Typosquatting registers domains that are slight misspellings of
            popular brands (e.g., 'googel.com', 'faceb00k.com') to catch
            users who mistype URLs or don't carefully inspect links.
        """
        findings = []
        # Extract the main domain name without TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return findings

        domain_name = parts[-2] if not re.match(r'^\d+$', parts[-2]) else domain

        for brand, legit_domains in self.KNOWN_BRANDS.items():
            # Skip if this IS the legitimate domain
            registered = '.'.join(parts[-2:])
            if registered in legit_domains:
                continue

            distance = self._levenshtein_distance(domain_name, brand)
            similarity = 1 - (distance / max(len(domain_name), len(brand)))

            if 0 < distance <= 2 and similarity >= 0.7:
                findings.append(Finding(
                    category="typosquatting",
                    severity="HIGH",
                    description=f"Domain '{domain_name}' is suspiciously similar "
                                f"to brand '{brand}' (edit distance: {distance})",
                    score_impact=25,
                    details=f"Levenshtein distance: {distance}, "
                            f"Similarity: {similarity:.0%}. "
                            f"This may be a typosquatting attempt."
                ))
            elif brand in domain_name and domain_name != brand:
                findings.append(Finding(
                    category="brand_embedding",
                    severity="MEDIUM",
                    description=f"Brand name '{brand}' embedded in domain "
                                f"'{domain_name}'",
                    score_impact=15,
                    details="Embedding brand names in domains is a common "
                            "phishing technique."
                ))

        return findings

    def _check_homoglyph_attack(self, domain: str) -> List[Finding]:
        """
        Detect homoglyph (lookalike character) attacks.

        Security Concept:
            Homoglyph attacks use characters that look identical to ASCII
            letters but are actually different Unicode characters. For example,
            Cyrillic 'а' looks like Latin 'a' but has a different code point.
            This is also known as an IDN homograph attack.
        """
        findings = []
        # Check for non-ASCII characters
        non_ascii = [c for c in domain if ord(c) > 127]
        if non_ascii:
            findings.append(Finding(
                category="homoglyph",
                severity="CRITICAL",
                description="Domain contains non-ASCII/Unicode characters "
                            "(possible homoglyph attack)",
                score_impact=30,
                details=f"Non-ASCII characters found: {non_ascii}. "
                        "This is a strong indicator of an IDN homograph attack."
            ))
            return findings

        # Check for common ASCII lookalike substitutions
        substitutions_found = []
        for char in domain:
            if char == '0' and any(b in domain.replace('0', 'o')
                                   for b in ['google', 'yahoo', 'facebook']):
                substitutions_found.append(('0', 'o'))
            elif char == '1' and any(b in domain.replace('1', 'l')
                                      for b in ['paypal', 'apple', 'linkedin']):
                substitutions_found.append(('1', 'l'))
            elif char == '5' and 's' not in domain:
                substitutions_found.append(('5', 's'))

        if substitutions_found:
            subs_str = ", ".join(f"'{a}'→'{b}'" for a, b in set(substitutions_found))
            findings.append(Finding(
                category="lookalike",
                severity="HIGH",
                description=f"Possible lookalike character substitutions: {subs_str}",
                score_impact=20,
                details="Common character substitutions detected that could "
                        "make the domain look like a legitimate brand."
            ))

        return findings

    def _check_url_structure(self, url: str, parsed) -> List[Finding]:
        """
        Analyze URL structure for suspicious patterns.

        Security Concept:
            Phishing URLs often have unusual structures: excessive path depth,
            suspicious query parameters, @ symbols (credential-like), or
            encoded characters used to obfuscate the true destination.
        """
        findings = []

        # Check for @ symbol in URL (can be used to mislead)
        if '@' in parsed.netloc:
            findings.append(Finding(
                category="structure",
                severity="CRITICAL",
                description="URL contains '@' symbol which can disguise "
                            "the actual destination",
                score_impact=30,
                details="The '@' makes the browser ignore everything before "
                        "it, so 'http://google.com@evil.com' goes to evil.com"
            ))

        # Check path depth
        path_parts = [p for p in parsed.path.split('/') if p]
        if len(path_parts) > 5:
            findings.append(Finding(
                category="structure",
                severity="LOW",
                description=f"Unusually deep URL path ({len(path_parts)} levels)",
                score_impact=5,
            ))

        # Check for suspicious file extensions in path
        suspicious_exts = ['.php', '.asp', '.cgi', '.exe', '.scr', '.bat']
        for ext in suspicious_exts:
            if ext in parsed.path.lower():
                findings.append(Finding(
                    category="structure",
                    severity="MEDIUM",
                    description=f"Suspicious file extension '{ext}' in URL path",
                    score_impact=10,
                ))
                break

        # Check for data URIs or javascript
        if url.lower().startswith(('javascript:', 'data:')):
            findings.append(Finding(
                category="structure",
                severity="CRITICAL",
                description="URL uses javascript: or data: protocol",
                score_impact=30,
            ))

        # Check for excessive query parameters
        params = parse_qs(parsed.query)
        if len(params) > 8:
            findings.append(Finding(
                category="structure",
                severity="LOW",
                description=f"Large number of query parameters ({len(params)})",
                score_impact=5,
            ))

        # Check for encoded characters that might hide the true URL
        if '%' in url:
            encoded_count = url.count('%')
            if encoded_count > 5:
                findings.append(Finding(
                    category="structure",
                    severity="MEDIUM",
                    description=f"Heavy URL encoding detected ({encoded_count} "
                                f"encoded characters)",
                    score_impact=10,
                    details="Excessive URL encoding can be used to obfuscate "
                            "the true destination."
                ))

        # Check URL length (very long URLs are suspicious)
        if len(url) > 200:
            findings.append(Finding(
                category="structure",
                severity="LOW",
                description=f"Unusually long URL ({len(url)} characters)",
                score_impact=5,
            ))

        return findings

    def _check_entropy(self, domain_info: DomainInfo) -> List[Finding]:
        """
        Check domain entropy (randomness).

        Security Concept:
            Domain Generation Algorithms (DGA) create random-looking domain
            names for malware command-and-control. High entropy in a domain
            name suggests it may be algorithmically generated.
        """
        findings = []
        entropy = domain_info.entropy

        if entropy > 4.0:
            findings.append(Finding(
                category="entropy",
                severity="HIGH",
                description=f"High domain name entropy ({entropy:.2f}) suggests "
                            "algorithmically generated domain",
                score_impact=20,
                details="Domain names with high entropy (randomness) are often "
                        "generated by malware or used for short-lived phishing."
            ))
        elif entropy > 3.5:
            findings.append(Finding(
                category="entropy",
                severity="LOW",
                description=f"Moderately high domain entropy ({entropy:.2f})",
                score_impact=5,
            ))

        return findings

    # -------------------------------------------------------------------------
    # Utility methods
    # -------------------------------------------------------------------------

    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Higher entropy indicates more randomness/unpredictability.
        Normal English words have entropy around 2.5-3.5.
        Random strings have entropy > 4.0.

        Args:
            string: Input string to analyze

        Returns:
            Shannon entropy value (float)
        """
        if not string:
            return 0.0

        # Count character frequencies
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1

        length = len(string)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein (edit) distance between two strings.

        The edit distance is the minimum number of single-character edits
        (insertions, deletions, substitutions) needed to transform one
        string into the other.

        Args:
            s1: First string
            s2: Second string

        Returns:
            Integer edit distance
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost is 0 if characters match, 1 otherwise
                cost = 0 if c1 == c2 else 1
                current_row.append(min(
                    current_row[j] + 1,        # Insertion
                    previous_row[j + 1] + 1,   # Deletion
                    previous_row[j] + cost,     # Substitution
                ))
            previous_row = current_row

        return previous_row[-1]

    @staticmethod
    def _score_to_level(score: int) -> str:
        """Convert numeric risk score to risk level string."""
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


# ---------------------------------------------------------------------------
# Convenience function for quick analysis
# ---------------------------------------------------------------------------

def quick_analyze(url: str) -> Dict:
    """Quick URL analysis returning a simple dictionary."""
    analyzer = URLAnalyzer()
    result = analyzer.analyze_url(url)
    return {
        "url": result.url,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "has_ssl": result.has_ssl,
        "is_shortened": result.is_shortened,
        "findings_count": len(result.findings),
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "description": f.description,
            }
            for f in result.findings
        ],
    }
