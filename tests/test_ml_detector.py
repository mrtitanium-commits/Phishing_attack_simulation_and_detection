"""
Unit Tests for Machine Learning Detector Module
"""

import pytest
from phishing_simulator.ml_detector import PhishingMLDetector, FEATURE_NAMES


class TestMLDetector:

    def test_feature_extraction_vector_length(self, ml_detector, sample_phishing_email):
        vec = ml_detector.extract_features(sample_phishing_email)
        assert len(vec) == len(FEATURE_NAMES)
        assert isinstance(vec, list)
        assert all(isinstance(val, float) for val in vec)

    def test_training_and_accuracy(self, ml_detector):
        metrics = ml_detector.train([])
        assert "accuracy" in metrics
        assert metrics["accuracy"] >= 0.70

    def test_prediction_output_format(self, ml_detector, sample_phishing_email):
        res = ml_detector.predict(sample_phishing_email)
        assert hasattr(res, "is_phishing")
        assert hasattr(res, "confidence")
        assert hasattr(res, "risk_level")
        assert isinstance(res.is_phishing, bool)
        assert 0.0 <= res.confidence <= 1.0

    def test_phishing_sample_classified_as_phishing(self, ml_detector):
        sample = {
            "subject": "URGENT: Your account has been suspended! Immediate action required",
            "body": "Click http://192.168.1.1/login immediately to verify your credentials. If you do not respond within 24 hours your account will be permanently closed.",
            "sender": "security@g00gle-update.tk",
            "headers": {"Reply-To": "attacker@evil.com"},
            "attachments": ["update.exe"]
        }
        res = ml_detector.predict(sample)
        assert res.is_phishing is True

    def test_legit_sample_classified_as_safe(self, ml_detector):
        sample = {
            "subject": "Sprint planning notes and backlog",
            "body": "Hi team, here is the backlog grooming summary for our next iteration.",
            "sender": "alex@company.com",
            "headers": {},
            "attachments": []
        }
        res = ml_detector.predict(sample)
        assert res.is_phishing is False

    def test_model_save_and_load(self, ml_detector, tmp_path):
        model_file = str(tmp_path / "test_model.pkl")
        ml_detector.save_model(model_file)
        
        new_detector = PhishingMLDetector()
        new_detector.load_model(model_file)
        assert new_detector.is_trained is True
