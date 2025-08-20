from datetime import datetime, timezone
from email.policy import default

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=True)  # Made nullable for Google OAuth users
    google_id = db.Column(db.String(100), unique=True, nullable=True)  # Google user ID
    profile_picture = db.Column(db.String(500), nullable=True)  # Google profile picture
    auth_provider = db.Column(db.String(20), default='email')  # 'email' or 'google'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # Email verification fields
    is_email_verified = db.Column(db.Boolean, default=False)
    email_verification_code = db.Column(db.String(10), nullable=True)
    email_verification_expires_at = db.Column(db.DateTime, nullable=True)
   
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    post_type = db.Column(db.String(20), nullable=False)  # 'housing', 'jobs', 'services'
    location = db.Column(db.String(100), nullable=True)  # For all post types
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # Relationship to author
    user = db.relationship('User', backref=db.backref('posts', lazy=True))
    # Relationship to images (optional)
    images = db.relationship('PostImage', backref='post', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Post {self.title}>'

class PendingUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    verification_code = db.Column(db.String(10), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<PendingUser {self.email}>'

class PendingEmailChange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    new_email = db.Column(db.String(30), nullable=False)
    verification_code = db.Column(db.String(10), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('pending_email_changes', lazy=True))

    def __repr__(self):
        return f'<PendingEmailChange {self.new_email} for user {self.user_id}>'

class PostImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    image_url = db.Column(db.String(500), nullable=False)  # Full S3 URL
    image_filename = db.Column(db.String(200), nullable=False)  # Original filename
    s3_key = db.Column(db.String(500), nullable=True)  # S3 key for deletion
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class SavedPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    saved_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    user = db.relationship('User', backref=db.backref('saved_posts', lazy=True))

#New Chat Model
class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    #Relationships
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])
    post = db.relationship('Post')
    messages = db.relationship('Message', backref='chat_room', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    #Relationships
    sender = db.relationship('User', backref='messages')

    
    def __repr__(self):
        return f'<PostImage {self.image_filename}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    message_preview = db.Column(db.Text, nullable=False)
    post_title = db.Column(db.String(100), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_notifications')
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_notifications')
    chat_room = db.relationship('ChatRoom', backref='notifications')

class PostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = db.relationship('User', backref=db.backref('post_likes', lazy=True))
    post = db.relationship('Post', backref=db.backref('likes', lazy=True))
    
    # Ensure a user can only like a post once
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)

class PostReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    reason = db.Column(db.String(50), nullable=False)  # 'spam', 'inappropriate', 'fake', 'other'
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'reviewed', 'resolved', 'dismissed'
    admin_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    reporter = db.relationship('User', backref=db.backref('post_reports', lazy=True))
    post = db.relationship('Post', backref=db.backref('reports', lazy=True))