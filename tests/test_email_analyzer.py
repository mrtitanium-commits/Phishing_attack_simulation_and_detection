"""
Unit Tests for Email Analyzer Module
"""

import pytest
from phishing_simulator.email_analyzer import EmailAnalyzer


class TestEmailAnalyzer:

    def test_phishing_email_high_risk(self, email_analyzer, sample_phishing_email):
        res = email_analyzer.analyze_email(
            subject=sample_phishing_email["subject"],
            body=sample_phishing_email["body"],
            sender=sample_phishing_email["sender"],
            headers=sample_phishing_email["headers"]
        )
        assert res.risk_score >= 50
        assert res.risk_level in ["HIGH", "CRITICAL"]

    def test_legitimate_email_low_risk(self, email_analyzer, sample_legit_email):
        res = email_analyzer.analyze_email(
            subject=sample_legit_email["subject"],
            body=sample_legit_email["body"],
            sender=sample_legit_email["sender"],
            headers=sample_legit_email["headers"]
        )
        assert res.risk_score <= 25
        assert res.risk_level in ["SAFE", "LOW"]

    def test_social_engineering_urgency_detection(self, email_analyzer):
        body = "URGENT ACTION REQUIRED: You must act within 24 hours or face immediate termination!"
        res = email_analyzer.analyze_email(
            subject="Final Notice",
            body=body,
            sender="admin@notice-board.com"
        )
        tactics = [t.tactic for t in res.social_engineering_tactics]
        assert "urgency" in tactics or "fear" in tactics

    def test_social_engineering_authority_detection(self, email_analyzer):
        body = "This is the CEO and Board of Directors. Mandatory IT security compliance directive."
        res = email_analyzer.analyze_email(
            subject="Official Notice from CEO",
            body=body,
            sender="ceo-office@company-memo.net"
        )
        tactics = [t.tactic for t in res.social_engineering_tactics]
        assert "authority" in tactics

    def test_credential_request_flagged(self, email_analyzer):
        body = "Please confirm your login password and credit card number to verify account."
        res = email_analyzer.analyze_email(
            subject="Verify credentials",
            body=body,
            sender="verify@bank-support.org"
        )
        assert any("credential" in f.description.lower() for f in res.findings)

    def test_attachment_high_risk_executable(self, email_analyzer):
        res = email_analyzer.analyze_email(
            subject="Invoice",
            body="See attached invoice.",
            sender="billing@supplier.com",
            attachments=["invoice_4201.exe"]
        )
        assert any(f.category == "attachment" and f.severity == "CRITICAL" for f in res.findings)

    def test_attachment_double_extension(self, email_analyzer):
        res = email_analyzer.analyze_email(
            subject="Document",
            body="Review attached doc.",
            sender="support@vendor.com",
            attachments=["document.pdf.exe"]
        )
        assert any("double extension" in f.description.lower() for f in res.findings)

    def test_brand_impersonation_detection(self, email_analyzer):
        res = email_analyzer.analyze_email(
            subject="PayPal Security Alert",
            body="Unusual activity detected on your PayPal account.",
            sender="security@paypa1-update.tk"
        )
        assert any(f.category == "brand_impersonation" for f in res.findings)

    def test_url_extraction(self, email_analyzer):
        text = "Visit https://google.com and http://example.org/test for details."
        urls = email_analyzer._extract_urls(text)
        assert len(urls) >= 2
        assert "https://google.com" in urls
        assert "http://example.org/test" in urls

    def test_spf_fail_header_detection(self, email_analyzer):
        headers = {"X-SPF-Status": "fail (ip not authorized)"}
        findings = email_analyzer._check_spf_dkim_dmarc(headers)
        assert any("SPF check FAILED" in f.description for f in findings)
