# config.py
import os
import dotenv

# Load environment variables from .env file if it exists
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

basedir = os.path.abspath(os.path.dirname(__file__))

# Check if we're in production
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'agenagn.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Configuration - MUST be set in production
    _jwt_secret = os.environ.get('JWT_SECRET_KEY') or os.environ.get('JWT_SECRET')
    JWT_SECRET_KEY = _jwt_secret or 'your-secret-key-change-this-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours (1 day)
    
    # CORS / Allowed Origins - MUST be restricted in production
    _allowed_origins = os.environ.get('ALLOWED_ORIGINS')
    ALLOWED_ORIGINS = _allowed_origins if _allowed_origins is not None else ('*' if not IS_PRODUCTION else '')

    # Google OAuth
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    # Public callback on your API domain
    GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'https://api.dteshager.com/api/oauth/google/callback')
    # Comma-separated list of allowed app redirect URIs for deep linking
    APP_REDIRECT_ALLOWLIST = [
        uri.strip() for uri in os.environ.get(
            'APP_REDIRECT_ALLOWLIST', 'agenagn://oauth,com.agenagn.app://oauth'
        ).split(',') if uri.strip()
    ]

# Validate production requirements after class definition
if IS_PRODUCTION:
    # Enforce secret key in production
    if not Config.JWT_SECRET_KEY or Config.JWT_SECRET_KEY == 'your-secret-key-change-this-in-production':
        raise ValueError(
            "JWT_SECRET_KEY environment variable must be set in production. "
            "Generate one using: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    
    # Enforce CORS restriction in production
    if not Config.ALLOWED_ORIGINS or Config.ALLOWED_ORIGINS == '*':
        raise ValueError(
            "ALLOWED_ORIGINS environment variable must be set to specific domains in production. "
            "Example: ALLOWED_ORIGINS=https://api.dteshager.com,https://dteshager.com"
        )
