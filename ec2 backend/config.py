# config.py
print("Loaded config.py from:", __file__)
import os

import dotenv
# Load environment variables from .env file if it exists
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'agenagn.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.environ.get('JWT_SECRET') or 'your-secret-key-change-this-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours (1 day)

    # CORS / Allowed Origins
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*')

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
