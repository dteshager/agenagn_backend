# config.py
print("Loaded config.py from:", __file__)
import os

import dotenv
# Load environment variables from .env file if it exists
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'agenagn.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.environ.get('JWT_SECRET') or 'your-secret-key-change-this-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours (1 day)
