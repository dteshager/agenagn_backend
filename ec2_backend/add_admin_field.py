"""
Migration script to add is_admin field to User model
Run this script once to add the is_admin column to existing databases
"""
from app import create_app
from models import db, User

def add_admin_field():
    """Add is_admin column to User table if it doesn't exist"""
    app = create_app()
    with app.app_context():
        try:
            # Check if column exists by trying to query it
            try:
                db.session.execute(db.text("SELECT is_admin FROM user LIMIT 1"))
                print("✓ is_admin column already exists")
            except Exception:
                # Column doesn't exist, add it
                print("Adding is_admin column to User table...")
                db.session.execute(db.text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0 NOT NULL"))
                db.session.commit()
                print("✓ is_admin column added successfully")
            
            # Optionally, set a specific user as admin
            # Uncomment and modify the email below to make a user an admin
            admin_email = "agenagnteam@gmail.com"  # Change this to your admin email
            admin_user = User.query.filter_by(email=admin_email).first()
            if admin_user:
                admin_user.is_admin = True
                db.session.commit()
                print(f"✓ User {admin_email} set as admin")
            else:
                print(f"✗ User {admin_email} not found")
            
        except Exception as e:
            print(f"Error: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    add_admin_field()



