"""
Pytest Fixtures for PhishGuard Tests
"""

import pytest
import os
import tempfile
import sqlite3

from phishing_simulator.url_analyzer import URLAnalyzer
from phishing_simulator.email_analyzer import EmailAnalyzer
from phishing_simulator.ml_detector import PhishingMLDetector
from phishing_simulator.campaign_manager import CampaignManager


@pytest.fixture
def url_analyzer():
    return URLAnalyzer()


@pytest.fixture
def email_analyzer():
    return EmailAnalyzer()


@pytest.fixture
def ml_detector():
    detector = PhishingMLDetector()
    detector.train([])
    return detector


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_phishguard.db"
    return str(db_file)


@pytest.fixture
def campaign_mgr(temp_db):
    return CampaignManager(db_path=temp_db)


@pytest.fixture
def sample_phishing_email():
    return {
        "subject": "URGENT: Your account has been suspended!",
        "sender": "security@g00gle-update.tk",
        "body": "Your account has been suspended due to unauthorized access. Click here immediately http://192.168.1.1/login or your account will be deleted in 24 hours.",
        "headers": {"Reply-To": "attacker@evil.com"}
    }


@pytest.fixture
def sample_legit_email():
    return {
        "subject": "Weekly Team Meeting Minutes",
        "sender": "alex.smith@company.com",
        "body": "Hi team, please find the attached notes from our sprint review. Reach out if you have questions.",
        "headers": {}
    }
