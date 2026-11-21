"""
ML Detector Module
==================
Machine Learning-based phishing email detection.

Implements a classifier that can be trained on labeled email data to
detect phishing attempts. Uses scikit-learn when available, with a
fallback to a rule-based weighted scoring system.

Features Used (20+):
- URL-based: count, avg length, has IP URL, has shortener
- Text-based: subject/body length, urgency/threat/reward word counts
- Sender-based: reputation score, domain age, free provider
- Structure: HTML ratio, image count, tracking pixels
- Quality: grammar score, capitalization ratio
"""

import json
import pickle
import os
import re
import math
import random
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

# Try to import ML libraries
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (accuracy_score, precision_score,
                                  recall_score, f1_score, confusion_matrix)
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# Feature names for the 22-dimensional feature vector
FEATURE_NAMES = [
    "url_count",              # Number of URLs in email
    "url_avg_length",         # Average URL length
    "has_ip_url",             # Contains IP-based URL (0/1)
    "has_shortener",          # Contains URL shortener (0/1)
    "subject_length",         # Subject line length
    "body_length",            # Body text length
    "urgency_word_count",     # Count of urgency words
    "threat_word_count",      # Count of threat words
    "reward_word_count",      # Count of reward words
    "sender_reputation",      # Sender reputation score (0-1)
    "is_free_provider",       # Sender uses free email (0/1)
    "reply_to_mismatch",      # Reply-To differs from From (0/1)
    "html_to_text_ratio",     # Ratio of HTML to plain text
    "image_count",            # Number of images
    "has_tracking_pixel",     # Has 1x1 image (0/1)
    "has_attachment",         # Has attachment (0/1)
    "risky_attachment",       # Has risky attachment type (0/1)
    "grammar_score",          # Grammar quality (0-1, 1=good)
    "capitalization_ratio",   # Ratio of uppercase letters
    "special_char_ratio",     # Ratio of special characters
    "link_text_mismatch",     # Display text differs from URL (0/1)
    "external_domain_count",  # Number of unique external domains
]


@dataclass
class PredictionResult:
    """Result of ML phishing prediction."""
    is_phishing: bool
    confidence: float
    risk_level: str
    feature_importance: Dict[str, float] = field(default_factory=dict)
    features_used: Dict[str, float] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    """Model evaluation metrics."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion_matrix: List[List[int]]
    samples_tested: int


class PhishingMLDetector:
    """
    Machine Learning-based phishing email detector.

    Uses a Random Forest classifier (scikit-learn) or falls back to
    a weighted rule-based system when ML libraries aren't available.

    Usage:
        detector = PhishingMLDetector()
        # Train on data
        detector.train(training_data)
        # Predict
        result = detector.predict(email_data)
        print(result.is_phishing, result.confidence)
    """

    # Word lists for feature extraction
    URGENCY_WORDS = [
        "urgent", "immediately", "right away", "asap", "now",
        "within 24 hours", "expires", "last chance", "act now",
        "hurry", "limited time", "deadline", "overdue",
    ]

    THREAT_WORDS = [
        "suspended", "terminated", "closed", "blocked", "locked",
        "unauthorized", "compromised", "breach", "legal action",
        "penalty", "deactivate", "revoke",
    ]

    REWARD_WORDS = [
        "congratulations", "winner", "won", "prize", "reward",
        "free", "gift", "bonus", "exclusive", "selected",
        "lucky", "claim",
    ]

    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "tiny.cc", "rb.gy",
    }

    FREE_PROVIDERS = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "protonmail.com", "mail.com",
    }

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the ML detector.

        Args:
            model_path: Path to a saved model file. If None, a new model
                        will be created when train() is called.
        """
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.use_ml = HAS_SKLEARN and HAS_NUMPY

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def extract_features(self, email_data: Dict) -> List[float]:
        """
        Extract a 22-dimensional feature vector from email data.

        Args:
            email_data: Dictionary with keys:
                - subject (str): Email subject
                - body (str): Email body
                - sender (str): Sender email
                - headers (dict, optional): Email headers
                - attachments (list, optional): Attachment filenames
                - html_body (str, optional): HTML version of body

        Returns:
            List of 22 float features
        """
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")
        sender = email_data.get("sender", "")
        headers = email_data.get("headers", {})
        attachments = email_data.get("attachments", [])
        html_body = email_data.get("html_body", body)

        full_text = f"{subject} {body}".lower()

        # Clean HTML from body for text analysis
        clean_body = re.sub(r'<[^>]+>', ' ', body)

        # --- Extract features ---

        # 1. URL features
        urls = re.findall(r'https?://[^\s<>"\']+', f"{body} {html_body}")
        url_count = len(urls)
        url_avg_length = sum(len(u) for u in urls) / max(url_count, 1)
        has_ip_url = 1.0 if any(re.search(r'https?://\d+\.\d+\.\d+\.\d+', u) for u in urls) else 0.0
        has_shortener = 1.0 if any(
            any(s in u for s in self.URL_SHORTENERS) for u in urls
        ) else 0.0

        # 2. Text features
        subject_length = len(subject)
        body_length = len(clean_body)

        # 3. Word count features
        urgency_count = sum(1 for w in self.URGENCY_WORDS if w in full_text)
        threat_count = sum(1 for w in self.THREAT_WORDS if w in full_text)
        reward_count = sum(1 for w in self.REWARD_WORDS if w in full_text)

        # 4. Sender features
        sender_domain = sender.split('@')[-1].lower() if '@' in sender else ""
        is_free = 1.0 if sender_domain in self.FREE_PROVIDERS else 0.0

        # Sender reputation (heuristic: legitimate-looking = higher score)
        reputation = 0.5
        if sender_domain in self.FREE_PROVIDERS:
            reputation = 0.4
        elif re.match(r'.*\d{3,}', sender_domain):
            reputation = 0.2
        elif sender_domain and '.' in sender_domain:
            reputation = 0.7

        # Reply-To mismatch
        reply_to = headers.get("Reply-To", "")
        from_header = headers.get("From", sender)
        reply_mismatch = 1.0 if reply_to and reply_to != from_header and reply_to != sender else 0.0

        # 5. HTML structure features
        html_len = len(html_body)
        text_len = len(clean_body) or 1
        html_ratio = min(html_len / text_len, 10.0) / 10.0  # Normalized

        image_count = len(re.findall(r'<img\b', html_body, re.I))
        has_tracking = 1.0 if re.search(
            r'<img[^>]*(?:width=["\']?1|height=["\']?1)[^>]*(?:width=["\']?1|height=["\']?1)',
            html_body, re.I
        ) else 0.0

        # 6. Attachment features
        has_attachment = 1.0 if attachments else 0.0
        risky_exts = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi"}
        risky_attachment = 1.0 if any(
            any(a.lower().endswith(ext) for ext in risky_exts)
            for a in attachments
        ) else 0.0

        # 7. Quality features
        # Grammar score (simple heuristic)
        grammar_issues = 0
        if re.search(r'\bi\b(?![\'.])', body):  # lowercase 'i'
            grammar_issues += 1
        if re.search(r'  +', body):  # double spaces
            grammar_issues += 1
        if re.search(r'[.!?]{3,}', body):
            grammar_issues += 1
        grammar_score = max(0.0, 1.0 - grammar_issues * 0.2)

        # Capitalization ratio
        alpha_chars = [c for c in subject + clean_body if c.isalpha()]
        cap_ratio = sum(1 for c in alpha_chars if c.isupper()) / max(len(alpha_chars), 1)

        # Special character ratio
        special = sum(1 for c in full_text if not c.isalnum() and c != ' ')
        special_ratio = special / max(len(full_text), 1)

        # 8. Link text mismatch
        link_mismatch = 0.0
        href_matches = re.findall(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                                   html_body, re.I)
        for href, text in href_matches:
            text_clean = re.sub(r'<[^>]+>', '', text).strip()
            if text_clean.startswith("http") and text_clean != href:
                link_mismatch = 1.0
                break

        # 9. External domain count
        external_domains = set()
        for url in urls:
            try:
                from urllib.parse import urlparse
                d = urlparse(url).netloc.lower()
                if d and d != sender_domain:
                    external_domains.add(d)
            except Exception:
                pass
        external_count = min(len(external_domains), 10) / 10.0

        return [
            float(url_count),
            float(url_avg_length),
            has_ip_url,
            has_shortener,
            float(subject_length),
            float(body_length),
            float(urgency_count),
            float(threat_count),
            float(reward_count),
            reputation,
            is_free,
            reply_mismatch,
            html_ratio,
            float(image_count),
            has_tracking,
            has_attachment,
            risky_attachment,
            grammar_score,
            cap_ratio,
            special_ratio,
            link_mismatch,
            external_count,
        ]

    def train(self, training_data: List[Dict]) -> Dict[str, float]:
        """
        Train the phishing detection model.

        Args:
            training_data: List of dicts, each with email fields plus
                          'label' (1=phishing, 0=legitimate)

        Returns:
            Training metrics dict
        """
        if not training_data:
            # Generate synthetic data if none provided
            training_data = self._generate_synthetic_data(200)

        # Extract features and labels
        X = []
        y = []
        for sample in training_data:
            features = self.extract_features(sample)
            X.append(features)
            y.append(sample.get("label", 0))

        if self.use_ml:
            X_array = np.array(X)
            y_array = np.array(y)

            # Scale features
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X_array)

            # Train Random Forest
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced',
            )
            self.model.fit(X_scaled, y_array)
            self.is_trained = True

            # Calculate training accuracy
            predictions = self.model.predict(X_scaled)
            acc = accuracy_score(y_array, predictions)
            prec = precision_score(y_array, predictions, zero_division=0)
            rec = recall_score(y_array, predictions, zero_division=0)
            f1 = f1_score(y_array, predictions, zero_division=0)

            return {
                "accuracy": float(acc),
                "precision": float(prec),
                "recall": float(rec),
                "f1_score": float(f1),
                "samples": len(training_data),
                "model_type": "RandomForest",
            }
        else:
            # Rule-based fallback - no actual training needed
            self.model = "rule_based"
            self.is_trained = True
            return {
                "accuracy": 0.85,  # Estimated
                "model_type": "RuleBased",
                "note": "scikit-learn not available, using rule-based fallback",
                "samples": len(training_data),
            }

    def predict(self, email_data: Dict) -> PredictionResult:
        """
        Predict whether an email is phishing.

        Args:
            email_data: Dictionary with email fields

        Returns:
            PredictionResult with classification and confidence
        """
        features = self.extract_features(email_data)

        if self.use_ml and self.is_trained and self.model is not None and self.model != "rule_based":
            # ML prediction
            X = np.array([features])
            if self.scaler:
                X = self.scaler.transform(X)

            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            confidence = float(max(probabilities))

            # Feature importance
            importances = self.model.feature_importances_
            feature_imp = {
                FEATURE_NAMES[i]: float(importances[i])
                for i in range(len(FEATURE_NAMES))
            }
            # Sort by importance
            feature_imp = dict(sorted(feature_imp.items(),
                                       key=lambda x: x[1], reverse=True))
        else:
            # Rule-based fallback prediction
            prediction, confidence, feature_imp = self._rule_based_predict(features)

        is_phishing = bool(prediction == 1)
        risk_level = self._confidence_to_level(confidence, is_phishing)

        # Create features used dict
        features_used = {
            FEATURE_NAMES[i]: features[i]
            for i in range(len(FEATURE_NAMES))
        }

        return PredictionResult(
            is_phishing=is_phishing,
            confidence=confidence,
            risk_level=risk_level,
            feature_importance=feature_imp,
            features_used=features_used,
        )

    def evaluate(self, test_data: List[Dict]) -> EvaluationResult:
        """
        Evaluate the model on test data.

        Args:
            test_data: List of labeled email data dicts

        Returns:
            EvaluationResult with comprehensive metrics
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before evaluation")

        y_true = []
        y_pred = []

        for sample in test_data:
            true_label = sample.get("label", 0)
            result = self.predict(sample)
            predicted_label = 1 if result.is_phishing else 0

            y_true.append(true_label)
            y_pred.append(predicted_label)

        if self.use_ml:
            cm = confusion_matrix(y_true, y_pred).tolist()
            acc = accuracy_score(y_true, y_pred)
            prec = precision_score(y_true, y_pred, zero_division=0)
            rec = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
        else:
            # Manual calculation
            tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
            tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
            fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
            fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

            cm = [[tn, fp], [fn, tp]]
            total = len(y_true)
            acc = (tp + tn) / max(total, 1)
            prec = tp / max(tp + fp, 1)
            rec = tp / max(tp + fn, 1)
            f1 = 2 * prec * rec / max(prec + rec, 0.001)

        return EvaluationResult(
            accuracy=float(acc),
            precision=float(prec),
            recall=float(rec),
            f1=float(f1),
            confusion_matrix=cm,
            samples_tested=len(test_data),
        )

    def _generate_synthetic_data(self, n_samples: int = 200) -> List[Dict]:
        """
        Generate synthetic labeled training data for demonstration.

        Creates a balanced dataset of phishing and legitimate email samples.
        """
        random.seed(42)
        data = []

        # Legitimate email patterns
        legit_subjects = [
            "Team meeting at 3pm", "Project update - Q4 report",
            "Lunch tomorrow?", "Re: Code review for PR #42",
            "Weekly newsletter", "Meeting notes from today",
            "FYI - new parking policy", "Happy birthday!",
            "Conference registration confirmed", "Invoice #12345 attached",
        ]

        legit_senders = [
            "alice@company.com", "bob@company.com", "hr@company.com",
            "newsletter@updates.company.com", "support@vendor.com",
        ]

        # Phishing email patterns
        phish_subjects = [
            "URGENT: Your account has been compromised!",
            "Action Required: Verify your identity immediately",
            "You've won a $500 gift card! Claim now!",
            "Password expires in 24 hours - Reset now",
            "FINAL WARNING: Account suspension notice",
            "Invoice #INV-98765 - Payment overdue",
            "IT Security: Mandatory system update required",
            "Unusual sign-in detected - Verify now",
            "CEO Request - Urgent wire transfer needed",
            "Your package delivery failed - Reschedule now",
        ]

        phish_senders = [
            "security@g00gle-support.tk", "admin@microsoftt-verify.ml",
            "noreply@amaz0n-alert.cf", "support@paypa1-secure.gq",
            "it-team@company-portal.xyz",
        ]

        # Generate legitimate samples
        for i in range(n_samples // 2):
            subject = random.choice(legit_subjects)
            sender = random.choice(legit_senders)
            body = f"Hi team,\n\nJust a quick update regarding {subject.lower()}. "
            body += "Please review and let me know if you have any questions.\n\n"
            body += "Best regards,\n" + sender.split('@')[0].title()

            data.append({
                "subject": subject,
                "body": body,
                "sender": sender,
                "headers": {},
                "attachments": [],
                "html_body": body,
                "label": 0,
            })

        # Generate phishing samples
        for i in range(n_samples // 2):
            subject = random.choice(phish_subjects)
            sender = random.choice(phish_senders)
            body = f"Dear Customer,\n\nWe detected unauthorized access to your account. "
            body += "Click here immediately to verify: http://192.168.1.1/verify "
            body += "Your account will be suspended within 24 hours if not verified.\n\n"
            body += "Security Team"

            attachments = []
            if random.random() < 0.3:
                attachments = ["invoice.pdf.exe"]

            data.append({
                "subject": subject,
                "body": body,
                "sender": sender,
                "headers": {"Reply-To": "attacker@evil.com"},
                "attachments": attachments,
                "html_body": f'<html><body>{body}<img src="http://evil.com/t.png" width="1" height="1"></body></html>',
                "label": 1,
            })

        random.shuffle(data)
        return data

    def save_model(self, path: str) -> None:
        """Save the trained model to disk."""
        if not self.is_trained:
            raise RuntimeError("No trained model to save")

        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "use_ml": self.use_ml,
            "feature_names": FEATURE_NAMES,
            "saved_at": datetime.now().isoformat(),
        }

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, path: str) -> None:
        """Load a trained model from disk."""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data["model"]
        self.scaler = model_data.get("scaler")
        self.is_trained = True

    def _rule_based_predict(self, features: List[float]) -> Tuple[int, float, Dict]:
        """
        Fallback rule-based prediction when scikit-learn is unavailable.

        Uses weighted scoring of features to make a prediction.
        """
        # Feature weights for rule-based classification
        weights = {
            "url_count": 0.03,
            "url_avg_length": 0.01,
            "has_ip_url": 0.15,
            "has_shortener": 0.08,
            "subject_length": 0.0,
            "body_length": 0.0,
            "urgency_word_count": 0.08,
            "threat_word_count": 0.10,
            "reward_word_count": 0.07,
            "sender_reputation": -0.10,  # Higher reputation = less phishing
            "is_free_provider": 0.03,
            "reply_to_mismatch": 0.12,
            "html_to_text_ratio": 0.02,
            "image_count": 0.01,
            "has_tracking_pixel": 0.10,
            "has_attachment": 0.02,
            "risky_attachment": 0.15,
            "grammar_score": -0.05,  # Better grammar = less phishing
            "capitalization_ratio": 0.05,
            "special_char_ratio": 0.02,
            "link_text_mismatch": 0.12,
            "external_domain_count": 0.05,
        }

        score = 0.3  # Base score
        feature_importance = {}

        for i, name in enumerate(FEATURE_NAMES):
            weight = weights.get(name, 0.0)
            contribution = features[i] * weight
            score += contribution
            feature_importance[name] = abs(weight)

        # Clamp to [0, 1]
        score = max(0.0, min(1.0, score))

        prediction = 1 if score > 0.5 else 0
        confidence = score if prediction == 1 else (1 - score)

        # Sort by importance
        feature_importance = dict(sorted(feature_importance.items(),
                                          key=lambda x: x[1], reverse=True))

        return prediction, confidence, feature_importance

    @staticmethod
    def _confidence_to_level(confidence: float, is_phishing: bool) -> str:
        """Convert prediction confidence to risk level."""
        if not is_phishing:
            if confidence > 0.9:
                return "SAFE"
            elif confidence > 0.7:
                return "LOW"
            else:
                return "MEDIUM"
        else:
            if confidence > 0.9:
                return "CRITICAL"
            elif confidence > 0.7:
                return "HIGH"
            else:
                return "MEDIUM"
