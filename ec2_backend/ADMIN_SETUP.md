# Admin Setup Guide

## Database Migration

The `is_admin` field has been added to the User model. If you have an existing database, you need to add this column.

### Option 1: Using the Migration Script

Run the migration script:
```bash
cd Backend
python add_admin_field.py
```

### Option 2: Manual SQL (SQLite)

If using SQLite, you can run:
```sql
ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0 NOT NULL;
```

### Option 3: Manual SQL (PostgreSQL/MySQL)

For PostgreSQL:
```sql
ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT FALSE NOT NULL;
```

For MySQL:
```sql
ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE NOT NULL;
```

## Setting a User as Admin

### Option 1: Using Python Script

Edit `add_admin_field.py` and uncomment the section at the bottom, then set the admin email:
```python
admin_email = "your-admin@email.com"  # Change this to your admin email
admin_user = User.query.filter_by(email=admin_email).first()
if admin_user:
    admin_user.is_admin = True
    db.session.commit()
    print(f"✓ User {admin_email} set as admin")
```

Then run:
```bash
python add_admin_field.py
```

### Option 2: Using SQL

```sql
UPDATE user SET is_admin = 1 WHERE email = 'your-admin@email.com';
```

### Option 3: Using Flask Shell

```bash
python
>>> from app import create_app
>>> from models import db, User
>>> app = create_app()
>>> with app.app_context():
...     user = User.query.filter_by(email='your-admin@email.com').first()
...     user.is_admin = True
...     db.session.commit()
...     print("Admin set successfully")
```

## Admin Endpoints

### 1. Admin Login
**POST** `/api/admin/login`
```json
{
  "email": "admin@example.com",
  "password": "password"
}
```

**Response:**
```json
{
  "message": "Admin login successful",
  "token": "jwt_token_here",
  "user_id": 1,
  "email": "admin@example.com",
  "username": "admin",
  "is_admin": true
}
```

### 2. Check Admin Status
**GET** `/api/admin/check`
- Requires JWT token in Authorization header
- Returns: `{"is_admin": true/false}`

### 3. Delete Any Post (Admin Only)
**DELETE** `/api/admin/posts/<post_id>`
- Requires JWT token in Authorization header
- Requires admin privileges
- Deletes the post and all associated data (likes, saves, images, chat rooms, etc.)

**Response:**
```json
{
  "message": "Post deleted successfully"
}
```

## Security Notes

1. **Never commit admin credentials** to version control
2. **Use strong passwords** for admin accounts
3. **Limit admin access** to trusted users only
4. **Monitor admin actions** - consider adding logging for admin deletions
5. **Use HTTPS** in production to protect admin login credentials

## Testing Admin Functionality

1. Set a test user as admin using one of the methods above
2. Use the admin login endpoint to get a JWT token
3. Use the token to access admin endpoints
4. Test deleting a post using the admin delete endpoint



