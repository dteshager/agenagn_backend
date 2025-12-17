"""
Script to create an admin user for testing
Usage: python create_admin_user.py

The script reads admin credentials from environment variables:
- ADMIN_EMAIL: Admin user email address
- ADMIN_PASS: Admin user password

You can also override via command line arguments:
python create_admin_user.py email@example.com password username
"""
import os
import dotenv
from app import create_app
from models import db, User
from werkzeug.security import generate_password_hash

# Load environment variables from .env file
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

def create_admin_user(email, password, username=None):
    """Create an admin user"""
    app, socketio = create_app()  # create_app returns (app, socketio) tuple
    with app.app_context():
        try:
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                # Update existing user to admin
                existing_user.is_admin = True
                if password:
                    existing_user.password = generate_password_hash(password)
                if username and not existing_user.username:
                    existing_user.username = username
                existing_user.is_email_verified = True
                db.session.commit()
                print(f"✓ Existing user {email} updated to admin")
                return existing_user
            else:
                # Create new admin user
                if not username:
                    username = email.split('@')[0]  # Use email prefix as username
                
                hashed_password = generate_password_hash(password)
                admin_user = User(
                    username=username,
                    email=email,
                    password=hashed_password,
                    is_admin=True,
                    is_email_verified=True,
                    auth_provider='email'
                )
                db.session.add(admin_user)
                db.session.commit()
                print(f"✓ Admin user created successfully!")
                print(f"  Email: {email}")
                print(f"  Username: {username}")
                print(f"  Password: {password}")
                return admin_user
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    import sys
    
    # Get credentials from environment variables (from .env file)
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASS')
    admin_username = os.environ.get('ADMIN_USERNAME')  # Optional, will use email prefix if not set
    
    # Allow overriding via command line arguments (takes priority)
    if len(sys.argv) > 1:
        admin_email = sys.argv[1]
    if len(sys.argv) > 2:
        admin_password = sys.argv[2]
    if len(sys.argv) > 3:
        admin_username = sys.argv[3]
    
    # Validate required credentials
    if not admin_email:
        print("✗ Error: ADMIN_EMAIL environment variable is required")
        print("  Please set ADMIN_EMAIL in your .env file or pass it as a command line argument")
        sys.exit(1)
    
    if not admin_password:
        print("✗ Error: ADMIN_PASS environment variable is required")
        print("  Please set ADMIN_PASS in your .env file or pass it as a command line argument")
        sys.exit(1)
    
    # If username not provided, use email prefix
    if not admin_username:
        admin_username = admin_email.split('@')[0]
    
    print("Creating admin user...")
    print(f"Email: {admin_email}")
    print(f"Username: {admin_username}")
    print()
    
    create_admin_user(admin_email, admin_password, admin_username)
    print()
    print("You can now log in with these credentials in the admin login screen!")

