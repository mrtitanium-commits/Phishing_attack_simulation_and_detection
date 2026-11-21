"""
Email Analyzer Module
=====================
Analyzes email content to detect phishing attempts using multiple techniques.

Detection Techniques:
- Sender reputation analysis
- SPF/DKIM/DMARC validation (simulated)
- Subject line analysis (urgency, threats, rewards)
- Body content analysis
- Social engineering tactic detection
- URL extraction and analysis
- Attachment risk assessment
- Grammar quality checking
- Brand impersonation detection
"""

import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


class RiskLevel(Enum):
    """Risk classification levels."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EmailFinding:
    """A finding from email analysis."""
    category: str
    severity: str
    description: str
    weight: float           # Weight for final score calculation (0.0-1.0)
    details: Optional[str] = None


@dataclass
class SocialEngineeringTactic:
    """Detected social engineering tactic."""
    tactic: str             # authority, urgency, scarcity, social_proof, reciprocity, fear
    confidence: float       # 0.0-1.0
    indicators: List[str]   # Phrases that triggered detection
    description: str        # Educational description of the tactic


@dataclass
class EmailAnalysisResult:
    """Complete result of email analysis."""
    risk_score: int                                     # 0-100
    risk_level: str                                     # SAFE/LOW/MEDIUM/HIGH/CRITICAL
    findings: List[EmailFinding] = field(default_factory=list)
    social_engineering_tactics: List[SocialEngineeringTactic] = field(default_factory=list)
    urls_found: List[str] = field(default_factory=list)
    recommended_action: str = ""
    sender_analysis: Optional[Dict] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def summary(self) -> str:
        return (
            f"Email Risk: {self.risk_level} ({self.risk_score}/100)\n"
            f"Findings: {len(self.findings)} | "
            f"SE Tactics: {len(self.social_engineering_tactics)} | "
            f"URLs: {len(self.urls_found)}\n"
            f"Action: {self.recommended_action}"
        )


class EmailAnalyzer:
    """
    Comprehensive email phishing detection engine.

    Analyzes email headers, subject lines, body content, and embedded
    URLs to determine the likelihood of a phishing attempt.

    Usage:
        analyzer = EmailAnalyzer()
        result = analyzer.analyze_email(
            subject="Urgent: Reset your password now!",
            body="Click here to verify your account...",
            sender="security@g00gle-support.com"
        )
    """

    # Urgency indicators in subject/body
    URGENCY_WORDS = [
        "urgent", "immediately", "right away", "asap", "right now",
        "within 24 hours", "within 48 hours", "expires", "expiring",
        "last chance", "final warning", "act now", "hurry", "limited time",
        "don't delay", "time sensitive", "deadline", "overdue",
    ]

    # Threat indicators
    THREAT_WORDS = [
        "suspended", "terminated", "closed", "blocked", "locked",
        "unauthorized", "compromised", "breach", "violated",
        "legal action", "penalty", "consequence", "restriction",
        "deactivate", "disable", "revoke", "loss of access",
    ]

    # Reward/too-good-to-be-true indicators
    REWARD_WORDS = [
        "congratulations", "winner", "won", "prize", "reward",
        "free", "gift card", "bonus", "exclusive offer", "selected",
        "lucky", "jackpot", "claim your", "you've been chosen",
    ]

    # Suspicious sender patterns
    SUSPICIOUS_SENDER_PATTERNS = [
        r'\d{3,}@',              # Many digits before @
        r'.*noreply.*@(?!google|microsoft|apple|amazon)',  # noreply from unknown
        r'.*@.*\.tk$',           # .tk domain
        r'.*@.*\.ml$',           # .ml domain
        r'.*@.*-.*-.*\.',        # Multiple hyphens in domain
        r'^[a-z]{20,}@',         # Very long local part
    ]

    # Known brands for impersonation detection
    KNOWN_BRANDS = {
        "google": {"domains": ["google.com", "gmail.com"], "keywords": ["google", "gmail", "g suite"]},
        "microsoft": {"domains": ["microsoft.com", "outlook.com"], "keywords": ["microsoft", "outlook", "office 365"]},
        "apple": {"domains": ["apple.com", "icloud.com"], "keywords": ["apple", "icloud", "apple id"]},
        "paypal": {"domains": ["paypal.com"], "keywords": ["paypal"]},
        "amazon": {"domains": ["amazon.com"], "keywords": ["amazon", "prime", "aws"]},
        "netflix": {"domains": ["netflix.com"], "keywords": ["netflix"]},
        "facebook": {"domains": ["facebook.com", "fb.com"], "keywords": ["facebook", "meta"]},
        "linkedin": {"domains": ["linkedin.com"], "keywords": ["linkedin"]},
        "chase": {"domains": ["chase.com"], "keywords": ["chase", "jpmorgan"]},
        "wellsfargo": {"domains": ["wellsfargo.com"], "keywords": ["wells fargo"]},
    }

    # High-risk attachment types
    HIGH_RISK_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
                             ".js", ".hta", ".msi", ".dll"]
    MEDIUM_RISK_EXTENSIONS = [".doc", ".docm", ".xls", ".xlsm", ".ppt",
                               ".pptm", ".zip", ".rar", ".7z", ".iso"]

    def __init__(self):
        pass

    def analyze_email(
        self,
        subject: str,
        body: str,
        sender: str,
        headers: Optional[Dict[str, str]] = None,
        attachments: Optional[List[str]] = None,
    ) -> EmailAnalysisResult:
        """
        Perform comprehensive email phishing analysis.

        Args:
            subject: Email subject line
            body: Email body (plain text or HTML)
            sender: Sender email address
            headers: Optional email headers dict
            attachments: Optional list of attachment filenames

        Returns:
            EmailAnalysisResult with detailed findings
        """
        findings: List[EmailFinding] = []
        se_tactics: List[SocialEngineeringTactic] = []

        # Strip HTML from body for text analysis
        clean_body = self._strip_html(body)
        full_text = f"{subject} {clean_body}"

        # 1. Sender analysis
        sender_findings, sender_info = self._check_sender_reputation(sender)
        findings.extend(sender_findings)

        # 2. Header analysis (SPF/DKIM/DMARC)
        if headers:
            findings.extend(self._check_spf_dkim_dmarc(headers))

        # 3. Subject line analysis
        findings.extend(self._analyze_subject_line(subject))

        # 4. Body content analysis
        findings.extend(self._analyze_body_content(clean_body))

        # 5. Social engineering detection
        se_tactics = self._detect_social_engineering(full_text)

        # 6. URL extraction and analysis
        urls = self._extract_urls(body)
        url_findings = self._analyze_extracted_urls(urls, sender)
        findings.extend(url_findings)

        # 7. Attachment analysis
        if attachments:
            findings.extend(self._check_attachment_risk(attachments))

        # 8. Grammar/spelling check
        findings.extend(self._check_grammar_quality(clean_body))

        # 9. Brand impersonation check
        findings.extend(self._check_brand_impersonation(sender, full_text))

        # 10. Calculate overall risk
        risk_score = self._calculate_overall_risk(findings, se_tactics)
        risk_level = self._score_to_level(risk_score)
        recommended_action = self._get_recommendation(risk_level)

        return EmailAnalysisResult(
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            social_engineering_tactics=se_tactics,
            urls_found=urls,
            recommended_action=recommended_action,
            sender_analysis=sender_info,
        )

    def _check_sender_reputation(self, sender: str) -> Tuple[List[EmailFinding], Dict]:
        """
        Analyze sender email address for suspicious patterns.

        Security Concept:
            Phishing emails often come from addresses that mimic legitimate
            senders but have subtle differences (extra characters, different
            domain, free email providers for corporate communications).
        """
        findings = []
        info = {"address": sender, "flags": []}

        if not sender or '@' not in sender:
            findings.append(EmailFinding(
                "sender", "HIGH",
                "Invalid or missing sender email address", 0.8
            ))
            return findings, info

        local_part, domain = sender.rsplit('@', 1)

        # Check against suspicious patterns
        for pattern in self.SUSPICIOUS_SENDER_PATTERNS:
            if re.match(pattern, sender, re.I):
                findings.append(EmailFinding(
                    "sender", "MEDIUM",
                    f"Sender matches suspicious pattern",
                    0.5,
                    f"Pattern: {pattern}"
                ))
                info["flags"].append("suspicious_pattern")
                break

        # Check for free email providers used in business context
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com",
                          "outlook.com", "aol.com", "protonmail.com"]
        if domain.lower() in free_providers:
            findings.append(EmailFinding(
                "sender", "LOW",
                f"Sender uses free email provider ({domain})",
                0.3,
                "Corporate/official communications rarely use free email."
            ))
            info["flags"].append("free_provider")

        # Check for display name vs email mismatch patterns
        if '+' in local_part or '..' in local_part:
            findings.append(EmailFinding(
                "sender", "LOW",
                "Unusual characters in sender local part",
                0.2
            ))

        return findings, info

    def _check_spf_dkim_dmarc(self, headers: Dict[str, str]) -> List[EmailFinding]:
        """
        Simulate SPF/DKIM/DMARC validation.

        Security Concepts:
            - SPF (Sender Policy Framework): Verifies the sender's IP is
              authorized to send for the domain
            - DKIM (DomainKeys Identified Mail): Cryptographically verifies
              the email hasn't been tampered with
            - DMARC (Domain-based Message Authentication): Policy framework
              that uses SPF and DKIM results

        In production, these would be validated against actual DNS records.
        """
        findings = []

        # Check for simulated auth headers
        spf_status = headers.get("X-SPF-Status", headers.get("Received-SPF", ""))
        dkim_status = headers.get("X-DKIM-Status", headers.get("DKIM-Signature", ""))
        dmarc_status = headers.get("X-DMARC-Status", "")

        if "fail" in spf_status.lower():
            findings.append(EmailFinding(
                "authentication", "HIGH",
                "SPF check FAILED - sender IP not authorized for domain",
                0.8,
                "SPF failure means the email server is not authorized to "
                "send emails for this domain."
            ))

        if "fail" in dkim_status.lower():
            findings.append(EmailFinding(
                "authentication", "HIGH",
                "DKIM check FAILED - email signature invalid",
                0.8,
                "DKIM failure means the email may have been tampered with."
            ))

        if not spf_status and not dkim_status:
            findings.append(EmailFinding(
                "authentication", "MEDIUM",
                "No email authentication headers present (SPF/DKIM)",
                0.4,
                "Legitimate senders typically have SPF and DKIM configured."
            ))

        # Check for simulation marker
        if headers.get("X-PhishGuard") == "SIMULATION - NOT A REAL PHISHING EMAIL":
            findings.append(EmailFinding(
                "simulation", "LOW",
                "PhishGuard simulation marker detected",
                0.0,
                "This email is a known simulation."
            ))

        return findings

    def _analyze_subject_line(self, subject: str) -> List[EmailFinding]:
        """
        Analyze the email subject line for phishing indicators.

        Common phishing subject patterns:
        - Excessive urgency or threats
        - ALL CAPS or excessive punctuation
        - Action required / account suspended language
        - RE: or FWD: to fake ongoing conversations
        """
        findings = []
        subject_lower = subject.lower()

        # Check urgency words in subject
        urgency_found = [w for w in self.URGENCY_WORDS if w in subject_lower]
        if len(urgency_found) >= 2:
            findings.append(EmailFinding(
                "subject", "HIGH",
                f"Subject contains multiple urgency indicators",
                0.7,
                f"Found: {', '.join(urgency_found)}"
            ))
        elif urgency_found:
            findings.append(EmailFinding(
                "subject", "MEDIUM",
                f"Subject contains urgency language: '{urgency_found[0]}'",
                0.4
            ))

        # Check threat words
        threat_found = [w for w in self.THREAT_WORDS if w in subject_lower]
        if threat_found:
            findings.append(EmailFinding(
                "subject", "MEDIUM",
                f"Subject contains threat language",
                0.5,
                f"Found: {', '.join(threat_found[:3])}"
            ))

        # Check for ALL CAPS
        caps_ratio = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)
        if caps_ratio > 0.6 and len(subject) > 10:
            findings.append(EmailFinding(
                "subject", "MEDIUM",
                "Subject uses excessive capitalization",
                0.3,
                f"Capitalization ratio: {caps_ratio:.0%}"
            ))

        # Check for excessive punctuation
        punct_count = sum(1 for c in subject if c in '!?⚠️🔒')
        if punct_count > 3:
            findings.append(EmailFinding(
                "subject", "LOW",
                f"Subject has excessive punctuation/emojis ({punct_count})",
                0.2
            ))

        # Check for fake reply/forward markers
        if re.match(r'^(RE|FW|FWD):\s', subject, re.I):
            findings.append(EmailFinding(
                "subject", "LOW",
                "Subject suggests a reply/forward (may be faked)",
                0.2,
                "Phishers add RE:/FWD: to make emails look like ongoing conversations."
            ))

        return findings

    def _analyze_body_content(self, body: str) -> List[EmailFinding]:
        """Analyze email body content for phishing indicators."""
        findings = []
        body_lower = body.lower()

        # Check for urgency in body
        urgency_count = sum(1 for w in self.URGENCY_WORDS if w in body_lower)
        if urgency_count >= 3:
            findings.append(EmailFinding(
                "body", "HIGH",
                f"Body contains excessive urgency language ({urgency_count} indicators)",
                0.6
            ))

        # Check for credential requests
        credential_phrases = [
            "enter your password", "verify your password",
            "confirm your credentials", "update your password",
            "provide your login", "enter your ssn",
            "social security number", "credit card number",
            "bank account", "routing number",
        ]
        cred_found = [p for p in credential_phrases if p in body_lower]
        if cred_found:
            findings.append(EmailFinding(
                "body", "HIGH",
                "Email requests sensitive credential information",
                0.8,
                f"Requests found: {', '.join(cred_found[:3])}"
            ))

        # Check for generic greetings (phishing often lacks personalization)
        generic_greetings = ["dear customer", "dear user", "dear member",
                              "dear valued", "dear account holder", "dear sir/madam"]
        if any(g in body_lower for g in generic_greetings):
            findings.append(EmailFinding(
                "body", "LOW",
                "Email uses generic greeting (lacks personalization)",
                0.2,
                "Legitimate organizations usually address you by name."
            ))

        # Check for "click here" or "click below"
        if "click here" in body_lower or "click below" in body_lower:
            findings.append(EmailFinding(
                "body", "MEDIUM",
                "Email contains generic 'click here' call-to-action",
                0.3,
                "Legitimate emails usually use descriptive link text."
            ))

        return findings

    def _detect_social_engineering(self, text: str) -> List[SocialEngineeringTactic]:
        """
        Detect social engineering manipulation tactics.

        Six Key Social Engineering Principles (Cialdini):
        1. Authority - Impersonating figures of authority
        2. Urgency - Creating time pressure
        3. Scarcity - Limited availability
        4. Social Proof - Others are doing it
        5. Reciprocity - Offering something first
        6. Fear - Threatening consequences
        """
        tactics = []
        text_lower = text.lower()

        # 1. AUTHORITY - Impersonating authority figures
        authority_indicators = [
            "ceo", "director", "manager", "administrator", "it department",
            "security team", "compliance", "legal team", "board of directors",
            "official notice", "mandatory", "policy update",
        ]
        authority_found = [i for i in authority_indicators if i in text_lower]
        if authority_found:
            tactics.append(SocialEngineeringTactic(
                tactic="authority",
                confidence=min(1.0, len(authority_found) * 0.3),
                indicators=authority_found,
                description="AUTHORITY: The email impersonates a figure of authority "
                            "(CEO, IT dept, security team) to make the request seem "
                            "legitimate and harder to question."
            ))

        # 2. URGENCY - Time pressure
        urgency_found = [w for w in self.URGENCY_WORDS if w in text_lower]
        if urgency_found:
            tactics.append(SocialEngineeringTactic(
                tactic="urgency",
                confidence=min(1.0, len(urgency_found) * 0.25),
                indicators=urgency_found,
                description="URGENCY: Creates artificial time pressure to prevent "
                            "the victim from thinking critically or consulting others."
            ))

        # 3. SCARCITY - Limited availability
        scarcity_indicators = [
            "limited time", "only today", "exclusive", "last chance",
            "running out", "few remaining", "offer ends", "while supplies last",
        ]
        scarcity_found = [i for i in scarcity_indicators if i in text_lower]
        if scarcity_found:
            tactics.append(SocialEngineeringTactic(
                tactic="scarcity",
                confidence=min(1.0, len(scarcity_found) * 0.35),
                indicators=scarcity_found,
                description="SCARCITY: Creates a sense of limited availability "
                            "to rush the victim into action without verification."
            ))

        # 4. SOCIAL PROOF - Others are doing it
        social_proof_indicators = [
            "other employees", "your colleagues", "everyone in",
            "all users must", "company-wide", "all employees",
            "thousands of users", "other customers",
        ]
        social_found = [i for i in social_proof_indicators if i in text_lower]
        if social_found:
            tactics.append(SocialEngineeringTactic(
                tactic="social_proof",
                confidence=min(1.0, len(social_found) * 0.35),
                indicators=social_found,
                description="SOCIAL PROOF: Implies that others have already complied "
                            "with the request, making it seem normal and expected."
            ))

        # 5. RECIPROCITY - Offering something
        reciprocity_indicators = [
            "free", "gift", "reward", "bonus", "complimentary",
            "no cost", "as a thank you", "we'd like to offer",
        ]
        reciprocity_found = [i for i in reciprocity_indicators if i in text_lower]
        if reciprocity_found:
            tactics.append(SocialEngineeringTactic(
                tactic="reciprocity",
                confidence=min(1.0, len(reciprocity_found) * 0.3),
                indicators=reciprocity_found,
                description="RECIPROCITY: Offers something for free to create a "
                            "sense of obligation in the victim to reciprocate "
                            "(e.g., by clicking a link or providing information)."
            ))

        # 6. FEAR - Threatening consequences
        fear_indicators = [
            "account will be", "suspended", "terminated", "legal action",
            "unauthorized access", "security breach", "compromised",
            "data loss", "identity theft", "will be blocked",
        ]
        fear_found = [i for i in fear_indicators if i in text_lower]
        if fear_found:
            tactics.append(SocialEngineeringTactic(
                tactic="fear",
                confidence=min(1.0, len(fear_found) * 0.25),
                indicators=fear_found,
                description="FEAR: Threatens negative consequences to trigger an "
                            "emotional response that overrides rational thinking."
            ))

        return tactics

    def _extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from email content (both plain text and HTML).

        Extracts from:
        - Plain text URLs
        - HTML href attributes
        - HTML src attributes
        """
        urls = set()

        # Extract plain text URLs
        url_pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
        urls.update(re.findall(url_pattern, text))

        # Extract from HTML href/src attributes
        href_pattern = r'(?:href|src)=["\']?(https?://[^"\'>\s]+)'
        urls.update(re.findall(href_pattern, text, re.I))

        return list(urls)

    def _analyze_extracted_urls(self, urls: List[str],
                                 sender: str) -> List[EmailFinding]:
        """Analyze URLs found in the email."""
        findings = []

        if len(urls) == 0:
            return findings

        # Import URL analyzer for checking
        try:
            from .url_analyzer import URLAnalyzer
            url_analyzer = URLAnalyzer()
            has_analyzer = True
        except (ImportError, SystemError):
            has_analyzer = False

        # Check URL count
        if len(urls) > 10:
            findings.append(EmailFinding(
                "urls", "LOW",
                f"Email contains many URLs ({len(urls)})",
                0.2
            ))

        # Check for mismatched display text vs actual URL (HTML)
        # This is a simplified check
        sender_domain = sender.split('@')[-1] if '@' in sender else ""

        for url in urls[:5]:  # Check first 5 URLs
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                url_domain = parsed.netloc.lower()
            except Exception:
                continue

            # Check if URL domain matches sender domain
            if sender_domain and url_domain and sender_domain not in url_domain:
                findings.append(EmailFinding(
                    "urls", "MEDIUM",
                    f"URL domain ({url_domain}) doesn't match sender domain ({sender_domain})",
                    0.4
                ))
                break  # Only report once

            # Quick URL risk check if analyzer available
            if has_analyzer:
                result = url_analyzer.analyze_url(url)
                if result.risk_score > 50:
                    findings.append(EmailFinding(
                        "urls", "HIGH",
                        f"High-risk URL detected: {url_domain} "
                        f"(score: {result.risk_score})",
                        0.7
                    ))

        return findings

    def _check_attachment_risk(self, attachments: List[str]) -> List[EmailFinding]:
        """
        Assess risk of email attachments by file type.

        Security Concept:
            Phishing emails often contain malicious attachments disguised
            as invoices, documents, or other business files. Executable
            files and macro-enabled documents are highest risk.
        """
        findings = []

        for filename in attachments:
            filename_lower = filename.lower()

            # Check for high-risk extensions
            for ext in self.HIGH_RISK_EXTENSIONS:
                if filename_lower.endswith(ext):
                    findings.append(EmailFinding(
                        "attachment", "CRITICAL",
                        f"High-risk attachment: {filename} ({ext})",
                        0.9,
                        f"'{ext}' files can execute malicious code on your system."
                    ))
                    break

            # Check for medium-risk extensions
            for ext in self.MEDIUM_RISK_EXTENSIONS:
                if filename_lower.endswith(ext):
                    findings.append(EmailFinding(
                        "attachment", "MEDIUM",
                        f"Potentially risky attachment: {filename} ({ext})",
                        0.5,
                        f"'{ext}' files can contain malicious macros or content."
                    ))
                    break

            # Check for double extension tricks (e.g., invoice.pdf.exe)
            parts = filename.rsplit('.', 2)
            if len(parts) >= 3:
                findings.append(EmailFinding(
                    "attachment", "HIGH",
                    f"Double extension detected: {filename}",
                    0.8,
                    "Double extensions are used to disguise executable files "
                    "as harmless documents."
                ))

        return findings

    def _check_grammar_quality(self, text: str) -> List[EmailFinding]:
        """
        Basic grammar and spelling quality analysis.

        Many phishing emails contain grammar errors, unusual phrasing,
        or machine-translated text. This is a simplified heuristic check.
        """
        findings = []
        if len(text) < 50:
            return findings

        issues = 0

        # Check for common grammar issues
        grammar_patterns = [
            (r'\bi\b(?![\'.])', "lowercase 'i'"),
            (r'  +', "double spaces"),
            (r'[.!?]{3,}', "excessive punctuation"),
            (r'(?<![A-Z])[A-Z]{5,}(?![A-Z])', "random capitalization"),
            (r'\bdear\s+(?:sir|madam)\s*[,/]\s*(?:sir|madam)', "generic salutation"),
        ]

        for pattern, description in grammar_patterns:
            if re.search(pattern, text):
                issues += 1

        # Check sentence structure (very basic)
        sentences = re.split(r'[.!?]+', text)
        short_sentences = sum(1 for s in sentences if 0 < len(s.strip()) < 10)
        if short_sentences > len(sentences) * 0.5 and len(sentences) > 3:
            issues += 1

        if issues >= 3:
            findings.append(EmailFinding(
                "grammar", "MEDIUM",
                f"Multiple grammar/formatting issues detected ({issues})",
                0.4,
                "Poor grammar is common in phishing emails, especially those "
                "that are machine-translated or hastily crafted."
            ))
        elif issues >= 1:
            findings.append(EmailFinding(
                "grammar", "LOW",
                f"Minor grammar/formatting issues ({issues})",
                0.1
            ))

        return findings

    def _check_brand_impersonation(self, sender: str,
                                     text: str) -> List[EmailFinding]:
        """
        Detect attempts to impersonate known brands.

        Checks if the email references a brand but doesn't come from
        that brand's legitimate domain.
        """
        findings = []
        sender_domain = sender.split('@')[-1].lower() if '@' in sender else ""
        text_lower = text.lower()

        for brand, info in self.KNOWN_BRANDS.items():
            # Check if brand is mentioned in text
            brand_mentioned = any(kw in text_lower for kw in info["keywords"])
            # Check if sender is from legitimate domain
            from_legit = any(d in sender_domain for d in info["domains"])

            if brand_mentioned and not from_legit and sender_domain:
                findings.append(EmailFinding(
                    "brand_impersonation", "HIGH",
                    f"Possible {brand.title()} impersonation - sender domain "
                    f"'{sender_domain}' is not an official {brand.title()} domain",
                    0.7,
                    f"Official domains: {', '.join(info['domains'])}"
                ))
                break  # Only report the most prominent brand

        return findings

    def _calculate_overall_risk(self, findings: List[EmailFinding],
                                 se_tactics: List[SocialEngineeringTactic]) -> int:
        """
        Calculate overall risk score using weighted findings.

        The score considers:
        - Individual finding weights
        - Number and confidence of social engineering tactics
        - Cumulative effect of multiple indicators
        """
        if not findings and not se_tactics:
            return 0

        # Base score from findings (weighted)
        finding_score = sum(f.weight * 30 for f in findings)

        # SE tactics add to score
        se_score = sum(t.confidence * 15 for t in se_tactics)

        # Synergy bonus: multiple different categories compound the risk
        categories = set(f.category for f in findings)
        synergy = len(categories) * 2

        total = finding_score + se_score + synergy
        return min(100, int(total))

    @staticmethod
    def _score_to_level(score: int) -> str:
        """Convert score to risk level."""
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

    @staticmethod
    def _get_recommendation(risk_level: str) -> str:
        """Get action recommendation based on risk level."""
        recommendations = {
            "SAFE": "Email appears safe. Standard precautions apply.",
            "LOW": "Exercise normal caution. Verify sender if unexpected.",
            "MEDIUM": "Suspicious indicators found. Verify with sender through "
                      "a separate channel before taking any action.",
            "HIGH": "Likely phishing attempt. Do NOT click links or download "
                    "attachments. Report to IT security team.",
            "CRITICAL": "CRITICAL THREAT: Almost certainly a phishing attack. "
                        "Report immediately. Do not interact with this email."
        }
        return recommendations.get(risk_level, recommendations["MEDIUM"])

    @staticmethod
    def _strip_html(text: str) -> str:
        """Remove HTML tags from text."""
        clean = re.sub(r'<[^>]+>', ' ', text)
        clean = re.sub(r'\s+', ' ', clean)
        return clean.strip()
