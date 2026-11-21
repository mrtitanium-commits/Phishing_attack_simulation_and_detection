"""
Configuration module for PhishGuard.
Provides settings for database, model paths, Flask server, and logging.
"""

import os

# Project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    """Base configuration."""

    BASE_DIR = BASE_DIR
    PACKAGE_DIR = PACKAGE_DIR

    # Database
    DATABASE_PATH = os.path.join(PACKAGE_DIR, "data", "phishguard.db")

    # ML Model
    MODEL_PATH = os.path.join(PACKAGE_DIR, "data", "phishing_model.pkl")

    # Templates
    TEMPLATE_DIR = os.path.join(PACKAGE_DIR, "templates")
    EMAIL_TEMPLATE_DIR = os.path.join(TEMPLATE_DIR, "emails")
    HTML_TEMPLATE_DIR = os.path.join(TEMPLATE_DIR, "html")

    # Data files
    DATA_DIR = os.path.join(PACKAGE_DIR, "data")
    PATTERNS_FILE = os.path.join(DATA_DIR, "phishing_patterns.json")
    TRAINING_DATA_FILE = os.path.join(DATA_DIR, "training_data.json")
    QUIZ_FILE = os.path.join(DATA_DIR, "quiz_questions.json")

    # Flask
    FLASK_HOST = "127.0.0.1"
    FLASK_PORT = 5000
    SECRET_KEY = "phishguard-dev-secret-key-change-in-production"
    DEBUG = False

    # Logging
    LOG_LEVEL = "INFO"
    LOG_FILE = os.path.join(BASE_DIR, "phishguard.log")

    # Simulation
    TRACKING_DOMAIN = "http://localhost:5000/track"
    LANDING_DOMAIN = "http://localhost:5000/landing"


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    LOG_LEVEL = "DEBUG"


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    LOG_LEVEL = "WARNING"
    SECRET_KEY = os.environ.get("PHISHGUARD_SECRET_KEY", Config.SECRET_KEY)


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DATABASE_PATH = ":memory:"
    LOG_LEVEL = "DEBUG"


# Configuration map
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config(env=None):
    """Get configuration based on environment."""
    if env is None:
        env = os.environ.get("PHISHGUARD_ENV", "default")
    return config_map.get(env, DevelopmentConfig)()
