"""
Unit Tests for URL Analyzer Module
"""

import pytest
from phishing_simulator.url_analyzer import URLAnalyzer, quick_analyze


class TestURLAnalyzer:

    def test_legitimate_google_url(self, url_analyzer):
        res = url_analyzer.analyze_url("https://accounts.google.com/signin")
        assert res.risk_score <= 15
        assert res.risk_level in ["SAFE", "LOW"]
        assert res.has_ssl is True

    def test_ip_based_url_flagged(self, url_analyzer):
        res = url_analyzer.analyze_url("http://192.168.1.1/login.php")
        assert res.risk_score >= 25
        assert any(f.category == "ip_based" for f in res.findings)

    def test_typosquatting_detection(self, url_analyzer):
        res = url_analyzer.analyze_url("http://g00gle.com/login")
        assert res.risk_score >= 25
        assert any(f.category in ["typosquatting", "lookalike"] for f in res.findings)

    def test_suspicious_tld_flagged(self, url_analyzer):
        res = url_analyzer.analyze_url("http://secure-login.tk")
        assert any(f.category == "suspicious_tld" for f in res.findings)

    def test_shortened_url_flagged(self, url_analyzer):
        res = url_analyzer.analyze_url("https://bit.ly/3xPqR9a")
        assert res.is_shortened is True
        assert any(f.category == "url_shortener" for f in res.findings)

    def test_at_symbol_disguise(self, url_analyzer):
        res = url_analyzer.analyze_url("http://google.com@evil-attacker.com/signin")
        assert res.risk_score >= 30
        assert any(f.category == "structure" and "@" in f.description for f in res.findings)

    def test_subdomain_abuse_brand_impersonation(self, url_analyzer):
        res = url_analyzer.analyze_url("http://paypal.com.verify-login.xyz")
        assert any(f.category in ["brand_subdomain", "brand_embedding"] for f in res.findings)

    def test_missing_https_flagged(self, url_analyzer):
        res = url_analyzer.analyze_url("http://some-site.com/login")
        assert res.has_ssl is False
        assert any(f.category == "ssl" for f in res.findings)

    def test_high_entropy_detection(self, url_analyzer):
        res = url_analyzer.analyze_url("http://q9x82z7w4v1k0p8m2b.biz/auth")
        assert any(f.category == "entropy" for f in res.findings)

    def test_excessive_subdomains(self, url_analyzer):
        res = url_analyzer.analyze_url("http://a.b.c.d.e.example.com/test")
        assert any(f.category == "subdomain_abuse" for f in res.findings)

    def test_quick_analyze_helper(self):
        data = quick_analyze("https://apple.com")
        assert "risk_score" in data
        assert "risk_level" in data
        assert "findings" in data

    def test_levenshtein_distance(self, url_analyzer):
        dist = url_analyzer._levenshtein_distance("google", "googel")
        assert dist == 2
        dist_same = url_analyzer._levenshtein_distance("paypal", "paypal")
        assert dist_same == 0

    def test_shannon_entropy(self, url_analyzer):
        low_ent = url_analyzer._calculate_entropy("aaaaaaa")
        high_ent = url_analyzer._calculate_entropy("q9x82z7w4v1k")
        assert low_ent == 0.0
        assert high_ent > 3.0

    def test_suspicious_extension_in_path(self, url_analyzer):
        res = url_analyzer.analyze_url("http://files-download.com/setup.exe")
        assert any("file extension" in f.description for f in res.findings)
