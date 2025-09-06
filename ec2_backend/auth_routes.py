# auth_routes.py
from flask import Blueprint, request, jsonify
from sqlalchemy import and_, or_
from sqlalchemy.sql.functions import current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Post, PostImage, SavedPost, Notification, Message, ChatRoom, PendingUser, PendingEmailChange, PostLike, PostReport
from datetime import datetime, timedelta, timezone
import os
import uuid
from flask_jwt_extended import (jwt_required, get_jwt_identity, JWTManager,
                                create_access_token, create_refresh_token)
from s3_utils import upload_file_to_s3, delete_file_from_s3, test_s3_connection
auth_bp = Blueprint('auth', __name__)
from urllib.parse import urlencode
import json as _json
import secrets
import requests as _requests
from config import Config

# Configuration for file uploads
MAX_IMAGES = 3

# Ensure we compare timezone-aware UTC datetimes even if DB returned naive values
def as_aware_utc(dt: datetime) -> datetime:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Basic validation
    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password are required'}), 400

    # Enforce uniqueness with specific errors
    existing_username = User.query.filter_by(username=username).first()
    if existing_username:
        return jsonify({'error': 'Username already in use', 'code': 'username_taken'}), 409

    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        return jsonify({'error': 'Email already in use', 'code': 'email_taken'}), 409

    # Remove existing pending registration for same email
    existing_pending = PendingUser.query.filter_by(email=email).first()
    if existing_pending:
        db.session.delete(existing_pending)
        db.session.commit()

    # Create pending user with verification code
    code = str(uuid.uuid4().int)[:6]
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    hashed_password = generate_password_hash(password)

    pending = PendingUser(
        username=username,
        email=email,
        password_hash=hashed_password,
        verification_code=code,
        expires_at=expires_at,
        attempts=0,
    )
    db.session.add(pending)
    db.session.commit()

    try:
        from email_utils import send_verification_email
        send_verification_email(email, code)
        return jsonify({'message': 'Verification code sent', 'email': email, 'expires_in_minutes': 15}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to send verification email: {str(e)}'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        # creating JWT access token for the user
        access_token = create_access_token(identity=str(user.id))

        return jsonify({'message': 'Login successful',
                        'token': access_token,
                        'user_id': user.id, 'email': user.email, 'username': user.username}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/google-login', methods=['POST'])
def google_login():
    print("🔐 Backend - Google login endpoint called")
    print("🔐 Backend - Request method:", request.method)
    print("🔐 Backend - Request headers:", dict(request.headers))
    
    data = request.json
    print("🔐 Backend - Request data:", data)
    
    google_user_data = data.get('user')  # This will contain the user data from frontend
    id_token = data.get('id_token')  # Google ID token for verification

    print("🔐 Backend - Google user data:", google_user_data)
    print("🔐 Backend - Has ID token:", bool(id_token))

    if not google_user_data:
        print("❌ Backend - No Google user data provided")
        return jsonify({'error': 'Google user data is required'}), 400
    
    try:
        google_id = google_user_data.get('id')
        email = google_user_data.get('email')
        name = google_user_data.get('name', f'user_{google_id}')
        picture = google_user_data.get('picture')

        print("🔐 Backend - Extracted data:", {
            'google_id': google_id,
            'email': email,
            'name': name,
            'has_picture': bool(picture)
        })

        if not email:
            print("❌ Backend - No email provided")
            return jsonify({'error': 'Email is required from Google'}), 400

        if id_token:
            print("🔐 Backend - ID token received, would verify with Google here")
            # You can add Google token verification here later

        # Check if user exists by email or google_id
        user = User.query.filter(
            (User.email == email) | (User.google_id == google_id)
        ).first()

        print("🔐 Backend - User lookup result:", "Found" if user else "Not found")

        if not user:
            # Create new user
            print("🔐 Backend - Creating new user")
            user = User(
                username=name,
                email=email,
                google_id=google_id,
                profile_picture=picture,
                auth_provider='google',
                password=None  # No password for Google users
            )
            db.session.add(user)
            db.session.commit()
            print("🔐 Backend - New user created with ID:", user.id)
        else:
            # Update existing user's Google info if they logged in with Google before
            print("🔐 Backend - Updating existing user")
            if not user.google_id:
                user.google_id = google_id
                user.auth_provider = 'google'
            if picture and not user.profile_picture:
                user.profile_picture = picture
            db.session.commit()
            print("🔐 Backend - User updated")

        # Create JWT access token
        access_token = create_access_token(identity=str(user.id))
        print("🔐 Backend - JWT token created for user ID:", user.id)

        response_data = {
            'message': 'Google login successful',
            'token': access_token,
            'user_id': user.id,
            'email': user.email,
            'username': user.username,
            'profile_picture': user.profile_picture,
            'auth_provider': user.auth_provider
        }
        
        print("🔐 Backend - Sending success response:", response_data)
        return jsonify(response_data), 200

    except Exception as e:
        print(f"❌ Backend - Google login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Google login failed'}), 500

    except ValueError as e:
        print(f"❌ Backend - ValueError: {str(e)}")
        return jsonify({'error': f'Invalid token: {str(e)}'}), 400


@auth_bp.route('/oauth/google/start', methods=['GET'])
def oauth_google_start():
    """Start Google OAuth and redirect the user to Google's consent page.

    Optional query param: app_redirect (deep link, e.g., agenagn://oauth).
    The value must begin with an entry in Config.APP_REDIRECT_ALLOWLIST.
    """
    try:
        app_redirect = request.args.get('app_redirect') or 'agenagn://oauth'

        allowlist = set(Config.APP_REDIRECT_ALLOWLIST or [])
        if not any(app_redirect.startswith(allowed) for allowed in allowlist):
            return jsonify({'error': 'Invalid app redirect URI'}), 400

        if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_REDIRECT_URI:
            return jsonify({'error': 'Google OAuth not configured on server'}), 500

        state_obj = {
            'app_redirect': app_redirect,
            'nonce': secrets.token_urlsafe(16)
        }
        state = _json.dumps(state_obj, separators=(',', ':'))

        params = {
            'client_id': Config.GOOGLE_CLIENT_ID,
            'redirect_uri': Config.GOOGLE_REDIRECT_URI,
            'response_type': 'code',
            'scope': 'openid email profile',
            'access_type': 'offline',
            'include_granted_scopes': 'true',
            'state': state,
            'prompt': 'select_account'
        }
        auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)
        return "", 302, {'Location': auth_url}
    except Exception as e:
        return jsonify({'error': f'Failed to start Google OAuth: {str(e)}'}), 500


@auth_bp.route('/oauth/google/callback', methods=['GET'])
def oauth_google_callback():
    """Handle Google OAuth callback: exchange code, upsert user, deep link back with JWT."""
    try:
        code = request.args.get('code')
        state_raw = request.args.get('state')
        error = request.args.get('error')
        if error:
            return jsonify({'error': f'Google OAuth error: {error}'}), 400
        if not code:
            return jsonify({'error': 'Authorization code missing'}), 400

        try:
            state = _json.loads(state_raw) if state_raw else {}
        except Exception:
            state = {}

        app_redirect = state.get('app_redirect') or 'agenagn://oauth'
        allowlist = set(Config.APP_REDIRECT_ALLOWLIST or [])
        if not any(app_redirect.startswith(allowed) for allowed in allowlist):
            return jsonify({'error': 'Invalid app redirect URI'}), 400

        if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_CLIENT_SECRET or not Config.GOOGLE_REDIRECT_URI:
            return jsonify({'error': 'Google OAuth not configured on server'}), 500

        token_resp = _requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'code': code,
                'client_id': Config.GOOGLE_CLIENT_ID,
                'client_secret': Config.GOOGLE_CLIENT_SECRET,
                'redirect_uri': Config.GOOGLE_REDIRECT_URI,
                'grant_type': 'authorization_code'
            },
            timeout=15
        )
        if token_resp.status_code != 200:
            return jsonify({'error': 'Failed to exchange code for tokens', 'details': token_resp.text}), 400

        token_data = token_resp.json()
        id_token_str = token_data.get('id_token')
        if not id_token_str:
            return jsonify({'error': 'No ID token returned from Google'}), 400

        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests

        verified = google_id_token.verify_oauth2_token(
            id_token_str,
            google_requests.Request(),
            Config.GOOGLE_CLIENT_ID
        )

        if verified.get('iss') not in ['accounts.google.com', 'https://accounts.google.com']:
            return jsonify({'error': 'Invalid token issuer'}), 401

        email = verified.get('email')
        if not email:
            return jsonify({'error': 'Email is required from Google'}), 400

        if not verified.get('email_verified', False):
            return jsonify({'error': 'Google email not verified'}), 400

        google_id = verified['sub']
        name = verified.get('name', f'user_{google_id}')
        picture = verified.get('picture')

        user = User.query.filter(
            (User.email == email) | (User.google_id == google_id)
        ).first()

        if not user:
            user = User(
                username=name,
                email=email,
                google_id=google_id,
                profile_picture=picture,
                auth_provider='google',
                password=None,
                is_email_verified=True
            )
            db.session.add(user)
            db.session.commit()
        else:
            updated = False
            if not user.google_id:
                user.google_id = google_id
                user.auth_provider = 'google'
                user.is_email_verified = True
                updated = True
            if picture and not user.profile_picture:
                user.profile_picture = picture
                updated = True
            if updated:
                db.session.commit()

        access_token = create_access_token(identity=str(user.id))

        qs = urlencode({
            'token': access_token,
            'user_id': user.id,
            'email': user.email,
            'username': user.username,
            'profile_picture': user.profile_picture or ''
        })
        redirect_url = f"{app_redirect}?{qs}"
        return "", 302, {'Location': redirect_url}
    except Exception as e:
        return jsonify({'error': f'Google OAuth callback failed: {str(e)}'}), 500

@auth_bp.route('/refresh-token', methods=['POST'])
@jwt_required()
def refresh_token():
    try:
        # Get the current user's ID from the JWT token
        current_user_id = get_jwt_identity()
        user = db.session.get(User, int(current_user_id))
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Create a new access token
        new_access_token = create_access_token(identity=str(user.id))
        
        return jsonify({
            'message': 'Token refreshed successfully',
            'token': new_access_token,
            'user_id': user.id,
            'email': user.email,
            'username': user.username
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to refresh token: {str(e)}'}), 500

@auth_bp.route('/CreatePost', methods=['POST'])
@jwt_required()
def create_post():
    # Find user by email
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Get form data
        title = request.form.get('title')
        content = request.form.get('content')
        post_type = request.form.get('post_type')
        location = request.form.get('location')

        if not title or not content or not post_type:
            return jsonify({'error': 'Title, content, and post type are required'}), 400



        # Create new post
        new_post = Post(
            title=title,
            content=content,
            post_type=post_type,
            location=location,
            user_id=user.id

        )
        
        db.session.add(new_post)
        db.session.flush()  # This gives us the post ID

        # Handle image uploads to S3
        uploaded_files = request.files.getlist('images')
        if uploaded_files and len(uploaded_files) > MAX_IMAGES:
            return jsonify({'error': f'Maximum {MAX_IMAGES} images allowed'}), 400

        for uploaded_file in uploaded_files:
            if uploaded_file and uploaded_file.filename != '':
                try:
                    # Upload to S3
                    upload_result = upload_file_to_s3(uploaded_file, uploaded_file.filename, 'post-images')
                    
                    if upload_result['success']:
                        # Save image record to database
                        post_image = PostImage(
                            post_id=new_post.id,
                            image_url=upload_result['s3_url'],
                            image_filename=upload_result['filename'],
                            s3_key=upload_result['s3_key']
                        )
                        db.session.add(post_image)
                    else:
                        # If S3 upload fails, rollback and return error
                        db.session.rollback()
                        return jsonify({'error': f'Image upload failed: {upload_result["error"]}'}), 500
                        
                except Exception as e:
                    db.session.rollback()
                    return jsonify({'error': f'Image upload error: {str(e)}'}), 500

        db.session.commit()
        return jsonify({'message': 'Post created successfully'}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create post: {str(e)}'}), 500

@auth_bp.route('/posts/<post_type>', methods=['GET'])
def get_posts_by_type(post_type):
    posts = Post.query.filter_by(post_type=post_type).order_by(Post.created_at.desc()).all()
    posts_data = []
    
    for post in posts:
        # Get all images for this post
        images = [{'url': img.image_url, 'filename': img.image_filename} for img in post.images]
        
        # Get like count
        like_count = PostLike.query.filter_by(post_id=post.id).count()
        
        posts_data.append({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'post_type': post.post_type,
            'location': post.location,
            'images': images,
            'created_at': post.created_at.isoformat() if post.created_at else None,
            'user_name': post.user.username,
            'user_id': post.user_id,
            'like_count': like_count
        })
    
    return jsonify({'posts': posts_data}), 200

@auth_bp.route('/posts/single/<int:post_id>', methods=['GET'])
def get_single_post(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    # Get all images for this post
    images = [{'url': img.image_url, 'filename': img.image_filename} for img in post.images]
    
    # Get like count
    like_count = PostLike.query.filter_by(post_id=post.id).count()
    
    post_data = {
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'post_type': post.post_type,
        'location': post.location,
        'images': images,
        'created_at': post.created_at.isoformat() if post.created_at else None,
        'user_name': post.user.username,
        'user_id': post.user_id,
        'like_count': like_count
    }
    
    return jsonify({'post': post_data}), 200

@auth_bp.route('/chat/messages/<int:room_id>', methods=['GET'])
def get_chat_messages(room_id):
    try:
        # Check if chat room exists
        chat_room = db.session.get(ChatRoom, room_id)
        if not chat_room:
            return jsonify({'error': 'Chat room not found'}), 404
        
        messages = Message.query.filter_by(chat_room_id=room_id).order_by(Message.timestamp.desc()).all()
        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': msg.id,
                'content': msg.content,
                'sender_id': msg.sender_id,
                'sender_name': msg.sender.username,
                'timestamp': msg.timestamp.isoformat() + 'Z'  # Add 'Z' to indicate UTC
            })
        return jsonify({'messages': messages_data}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch messages: {str(e)}'}), 500

@auth_bp.route('/chat/room/<int:room_id>/other-user/<int:current_user_id>', methods=['GET'])
def get_other_user_in_chat(room_id, current_user_id):
    try:
        chat_room = ChatRoom.query.get(room_id)
        if not chat_room:
            return jsonify({'error': 'Chat room not found'}), 404
        
        # Determine the other user in the chat
        print(f"Chat room: user1_id={chat_room.user1_id}, user2_id={chat_room.user2_id}")
        print(f"Current user ID: {current_user_id}")
        
        if chat_room.user1_id == current_user_id:
            other_user_id = chat_room.user2_id
            print(f"Current user is user1, other user is user2: {other_user_id}")
        elif chat_room.user2_id == current_user_id:
            other_user_id = chat_room.user1_id
            print(f"Current user is user2, other user is user1: {other_user_id}")
        else:
            print(f"Current user {current_user_id} is not in this chat room!")
            return jsonify({'error': 'User not in this chat room'}), 400
        
        other_user = db.session.get(User, other_user_id)
        if not other_user:
            return jsonify({'error': 'Other user not found'}), 404
        
        return jsonify({
            'other_user': {
                'id': other_user.id,
                'username': other_user.username
            }
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get other user: {str(e)}'}), 500

@auth_bp.route('/posts/by-user', methods=['GET'])
@jwt_required()
def get_posts_by_user():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = db.session.get(User, int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).all()
    posts_data = []

    for post in posts:
        images = [{'url': img.image_url, 'filename': img.image_filename} for img in post.images]

        posts_data.append({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'post_type': post.post_type,
            'location': post.location,
            'images': images,
            'created_at': post.created_at.isoformat() if post.created_at else None,
            'user_name': post.user.username,
            'user_id': post.user_id
        })

    return jsonify({'posts': posts_data}), 200

@auth_bp.route('/posts/search', methods=['GET'])
def search():
    raw_query = request.args.get('query', '')
    category = request.args.get('category', '')
    limit = request.args.get('limit', type=int) or 50
    limit = max(1, min(limit, 100))

    if not raw_query or not raw_query.strip():
        return jsonify({'posts': []}), 200

    # Tokenize and remove simple stopwords
    import re
    tokens = re.findall(r"[\w']+", raw_query.lower())
    stopwords = {"in", "the", "a", "an", "and", "or", "for", "with", "to", "of", "on"}
    tokens = [t for t in tokens if t not in stopwords]
    if not tokens:
        return jsonify({'posts': []}), 200

    # For each token, match in title/content anywhere, and location with prefix or anywhere
    per_token_filters = []
    for tok in tokens:
        per_token_filters.append(
            or_(
                Post.title.ilike(f'%{tok}%'),
                Post.content.ilike(f'%{tok}%'),
                Post.location.ilike(f'%{tok}%'),
                Post.location.ilike(f'{tok}%')
            )
        )

    combined_filter = and_(*per_token_filters)
    if category and category != 'all':
        combined_filter = and_(combined_filter, Post.post_type == category)

    posts = (
        Post.query
        .filter(combined_filter)
        .order_by(Post.created_at.desc())
        .limit(limit)
        .all()
    )

    posts_data = []
    for post in posts:
        images = [{'url': img.image_url, 'filename': img.image_filename} for img in post.images]
        posts_data.append({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'post_type': post.post_type,
            'location': post.location,
            'images': images,
            'created_at': post.created_at.isoformat() if post.created_at else None,
            'user_name': post.user.username,
            'user_id': post.user_id
        })

    return jsonify({'posts': posts_data}), 200


@auth_bp.route('/posts/suggest', methods=['GET'])
def suggest():
    raw_query = request.args.get('query', '')
    category = request.args.get('category', '')
    limit = request.args.get('limit', type=int) or 5
    limit = max(1, min(limit, 20))

    if not raw_query or not raw_query.strip():
        return jsonify({'suggestions': []}), 200

    import re
    tokens = re.findall(r"[\w']+", raw_query.lower())
    stopwords = {"in", "the", "a", "an", "and", "or", "for", "with", "to", "of", "on"}
    tokens = [t for t in tokens if t not in stopwords]
    if not tokens:
        return jsonify({'suggestions': []}), 200

    per_token_filters = []
    for tok in tokens:
        per_token_filters.append(
            or_(
                Post.title.ilike(f'%{tok}%'),
                Post.content.ilike(f'%{tok}%'),
                Post.location.ilike(f'%{tok}%'),
                Post.location.ilike(f'{tok}%')
            )
        )

    combined_filter = and_(*per_token_filters)
    if category and category != 'all':
        combined_filter = and_(combined_filter, Post.post_type == category)

    posts = (
        Post.query
        .filter(combined_filter)
        .order_by(Post.created_at.desc())
        .limit(limit)
        .all()
    )

    suggestions = [{
        'id': p.id,
        'title': p.title,
        'location': p.location,
        'post_type': p.post_type
    } for p in posts]

    return jsonify({'suggestions': suggestions}), 200



@auth_bp.route('/posts/saved', methods=['GET'])
@jwt_required()
def get_saved_posts():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    saved_posts = SavedPost.query.filter_by(user_id=user.id).order_by(SavedPost.saved_at.desc()).all()
    saved_posts_data = []
    for saved_post in saved_posts:
        post = db.session.get(Post, saved_post.post_id)
        if post:
            images = [{'url': img.image_url, 'filename': img.image_filename} for img in post.images]
            saved_posts_data.append({
                'id': post.id,
                'title': post.title,
                'content': post.content,
                'post_type': post.post_type,
                'location': post.location,
                'images': images,
                'created_at': post.created_at.isoformat() if post.created_at else None,
                'saved_at': saved_post.saved_at.isoformat() if saved_post.saved_at else None,
                'user_name': post.user.username,
                'user_id': post.user_id
            })
    
    return jsonify({'posts': saved_posts_data}), 200

@auth_bp.route('/posts/save', methods=['POST'])
@jwt_required()
def save_post():

    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        post_id = data.get('post_id')
        
        if not post_id:
            return jsonify({'error': 'Post ID is required'}), 400

        # Find user by username
        # user = User.query.filter_by(username=user_name).first()
        # if not user:
        #     return jsonify({'error': 'User not found'}), 400
        
        # Check if post exists
        post = db.session.get(Post, post_id)
        if not post:
            return jsonify({'error': 'Post not found'}), 400
        
        # Check if already saved
        existing_save = SavedPost.query.filter_by(user_id=user.id, post_id=post_id).first()
        if existing_save:
            return jsonify({'error': 'Post already saved', 'saved': True}), 200
        
        # Save the post
        saved_post = SavedPost(user_id=user.id, post_id=post_id)
        db.session.add(saved_post)
        db.session.commit()
        
        return jsonify({'message': 'Post saved successfully', 'saved': True}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to save post: {str(e)}'}), 500

@auth_bp.route('/posts/unsave', methods=['POST'])
@jwt_required()
def unsave_post():

    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        post_id = data.get('post_id')
        
        if not post_id:
            return jsonify({'error': 'Post ID is required'}), 400
        
        # Find user by username
        # user = User.query.filter_by(username=user_name).first()
        # if not user:
        #     return jsonify({'error': 'User not found'}), 400
        
        # Find and remove saved post
        saved_post = SavedPost.query.filter_by(user_id=user.id, post_id=post_id).first()
        if not saved_post:
            return jsonify({'error': 'Post not saved', 'saved': False}), 200
        
        db.session.delete(saved_post)
        db.session.commit()
        
        return jsonify({'message': 'Post unsaved successfully', 'saved': False}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to unsave post: {str(e)}'}), 500

@auth_bp.route('/posts/check-saved', methods=['POST'])
def check_saved_posts():
    try:
        data = request.json
        user_name = data.get('user_name')
        post_ids = data.get('post_ids', [])
        
        if not user_name or not post_ids:
            return jsonify({'error': 'Username and post IDs are required'}), 400
        
        # Find user by username
        user = User.query.filter_by(username=user_name).first()
        if not user:
            return jsonify({'error': 'User not found'}), 400
        
        # Check which posts are saved
        saved_posts = SavedPost.query.filter(
            SavedPost.user_id == user.id,
            SavedPost.post_id.in_(post_ids)
        ).all()
        
        saved_post_ids = [sp.post_id for sp in saved_posts]
        
        return jsonify({'saved_posts': saved_post_ids}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to check saved posts: {str(e)}'}), 500

@auth_bp.route('/posts/delete', methods=['DELETE'])
@jwt_required()
def delete_post():

    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        post_id = data.get('post_id')

        if not post_id:
            return jsonify({'error': 'Post ID is required'}), 400

        # Find user by email
        # user = User.query.filter_by(username=user_name).first()
        # if not user:
        #     return jsonify({'error': 'User not found'}), 404

        # Find the post
        post = Post.query.filter_by(id=post_id, user_id=user.id).first()
        if not post:
            return jsonify({'error': 'Post not found or does not belong to the user'}), 404

        # Remove dependent rows first to avoid FK constraint errors
        # 1) Likes, Saved, Reports
        PostLike.query.filter_by(post_id=post.id).delete(synchronize_session=False)
        SavedPost.query.filter_by(post_id=post.id).delete(synchronize_session=False)
        PostReport.query.filter_by(post_id=post.id).delete(synchronize_session=False)

        # 2) Chat rooms, their messages and notifications
        chat_rooms = ChatRoom.query.filter_by(post_id=post.id).all()
        for chat_room in chat_rooms:
            Message.query.filter_by(chat_room_id=chat_room.id).delete(synchronize_session=False)
            Notification.query.filter_by(chat_room_id=chat_room.id).delete(synchronize_session=False)
            db.session.delete(chat_room)

        # Delete associated images from S3
        for image in post.images:
            if image.s3_key:
                # Delete from S3
                delete_result = delete_file_from_s3(image.s3_key)
                if not delete_result['success']:
                    print(f"Warning: Failed to delete S3 file {image.s3_key}: {delete_result['error']}")
                    # Continue with post deletion even if S3 deletion fails

        # Delete the post
        db.session.delete(post)
        db.session.commit()

        return jsonify({'message': 'Post deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete post: {str(e)}'}), 500

@auth_bp.route('/UpdatePost', methods=['PUT'])
@jwt_required()
def update_post():

    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Handle both JSON and FormData requests
        if request.content_type and 'multipart/form-data' in request.content_type:
            # FormData request (with potential images)
            post_id = request.form.get('post_id')
            title = request.form.get('title')
            content = request.form.get('content')
            post_type = request.form.get('post_type')
            location = request.form.get('location')
        else:
            # JSON request (text-only updates)
            data = request.json
            post_id = data.get('post_id')
            title = data.get('title')
            content = data.get('content')
            post_type = data.get('post_type')
            location = data.get('location')

        if not post_id:
            return jsonify({'error': 'Post ID is required'}), 400

        # Find user by email
        # user = User.query.filter_by(username=user_name).first()
        # if not user:
        #     return jsonify({'error': 'User not found'}), 404

        # Find the post
        post = Post.query.filter_by(id=post_id, user_id=user.id).first()
        if not post:
            return jsonify({'error': 'Post not found or does not belong to the user'}), 404

        # Update post details
        post.title = title
        post.content = content
        post.post_type = post_type
        post.location = location

        # Handle image uploads to S3 if any (only for FormData requests)
        if request.content_type and 'multipart/form-data' in request.content_type:
            uploaded_files = request.files.getlist('images')
            if uploaded_files and len(uploaded_files) > MAX_IMAGES:
                return jsonify({'error': f'Maximum {MAX_IMAGES} images allowed'}), 400

            for uploaded_file in uploaded_files:
                if uploaded_file and uploaded_file.filename != '':
                    try:
                        # Upload to S3
                        upload_result = upload_file_to_s3(uploaded_file, uploaded_file.filename, 'post-images')
                        
                        if upload_result['success']:
                            # Save image record to database
                            post_image = PostImage(
                                post_id=post.id,
                                image_url=upload_result['s3_url'],
                                image_filename=upload_result['filename'],
                                s3_key=upload_result['s3_key']
                            )
                            db.session.add(post_image)
                        else:
                            # If S3 upload fails, rollback and return error
                            db.session.rollback()
                            return jsonify({'error': f'Image upload failed: {upload_result["error"]}'}), 500
                            
                    except Exception as e:
                        db.session.rollback()
                        return jsonify({'error': f'Image upload error: {str(e)}'}), 500

        db.session.commit()
        return jsonify({'message': 'Post updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update post: {str(e)}'}), 500

@auth_bp.route('/test-s3', methods=['GET'])
def test_s3():
    """Test S3 connection and configuration"""
    result = test_s3_connection()
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 500

@auth_bp.route('/UpdateAccount', methods=['PUT'])
@jwt_required()
def update_account():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        current_password = data.get('currentPassword')
        password = data.get('password')

        if not username or not email:
            return jsonify({'error': 'Username and email are required'}), 400

        if current_password:
            if not check_password_hash(user.password, current_password):
                return jsonify({'error': 'Current password is incorrect'}), 400

        # Check if username or email already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email),
            User.id != user.id
        ).first()

        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 400

        # If email changed, start email verification flow instead of applying immediately
        if email and email != user.email:
            # Block if another verified user already uses this email
            if User.query.filter(User.email == email, User.id != user.id).first():
                return jsonify({'error': 'Email already in use'}), 400

            # Remove existing pending change for this user
            existing_pending = PendingEmailChange.query.filter_by(user_id=user.id).first()
            if existing_pending:
                db.session.delete(existing_pending)
                db.session.commit()

            # Create pending change
            code = str(uuid.uuid4().int)[:6]
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
            pending = PendingEmailChange(
                user_id=user.id,
                new_email=email,
                verification_code=code,
                expires_at=expires_at,
                attempts=0,
            )
            db.session.add(pending)
            db.session.commit()

            # Send email to new address
            try:
                from email_utils import send_verification_email
                send_verification_email(email, code)
            except Exception as e:
                return jsonify({'error': f'Failed to send verification email: {str(e)}'}), 500

            # Apply other fields (username/password) immediately
            user.username = username
            if password:
                user.password = generate_password_hash(password)
            db.session.commit()

            return jsonify({'message': 'Verification code sent to new email. Please verify to complete change.'}), 202

        # No email change; update fields directly
        user.username = username
        if password:
            user.password = generate_password_hash(password)
        db.session.commit()
        return jsonify({'message': 'Account updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update account: {str(e)}'}), 500

@auth_bp.route('/DeleteAccount', methods=['DELETE'])
@jwt_required()
def delete_account():

    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json

        # 1) Delete all posts by the user and their images (S3 best-effort)
        posts = Post.query.filter_by(user_id=user.id).all()
        post_ids = [p.id for p in posts]

        # Remove dependent rows that reference these posts (other users' saves/likes/reports)
        if post_ids:
            SavedPost.query.filter(SavedPost.post_id.in_(post_ids)).delete(synchronize_session=False)
            PostLike.query.filter(PostLike.post_id.in_(post_ids)).delete(synchronize_session=False)
            PostReport.query.filter(PostReport.post_id.in_(post_ids)).delete(synchronize_session=False)

        for post in posts:
            for image in post.images:
                if image.s3_key:
                    delete_result = delete_file_from_s3(image.s3_key)
                    if not delete_result['success']:
                        print(f"Warning: Failed to delete S3 file {image.s3_key}: {delete_result['error']}")
            db.session.delete(post)

        # 2) Delete messages and notifications for any chat room involving the user
        chat_rooms = ChatRoom.query.filter(
            (ChatRoom.user1_id == user.id) | (ChatRoom.user2_id == user.id)
        ).all()
        for chat_room in chat_rooms:
            Message.query.filter_by(chat_room_id=chat_room.id).delete()
            Notification.query.filter_by(chat_room_id=chat_room.id).delete()
            db.session.delete(chat_room)

        # 3) Delete notifications where user is sender or recipient (not tied to chat)
        Notification.query.filter(
            (Notification.recipient_id == user.id) | (Notification.sender_id == user.id)
        ).delete()

        # 4) Delete likes and reports made by the user
        PostLike.query.filter_by(user_id=user.id).delete()
        PostReport.query.filter_by(reporter_id=user.id).delete()

        # 5) Delete saved posts
        SavedPost.query.filter_by(user_id=user.id).delete()

        # 6) Finally, delete the user account
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'Account deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete account: {str(e)}'}), 500

@auth_bp.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Get notifications for the current user
        notifications = Notification.query.filter_by(recipient_id=user.id).order_by(Notification.created_at.desc()).all()
        
        notifications_data = []
        for notification in notifications:
            # Get the post and sender information
            post = Post.query.get(notification.chat_room.post_id)
            sender = User.query.get(notification.sender_id)
            
            print(f"Notification {notification.id}: sender_id={notification.sender_id}, sender_name={sender.username}")
            print(f"Current user: {user.username}, Current user ID: {user.id}")
            
            notifications_data.append({
                'id': notification.id,
                'sender_name': sender.username,
                'sender_id': notification.sender_id,
                'message_preview': notification.message_preview,
                'post_title': notification.post_title,
                'post_id': post.id,
                'read': notification.read,
                'created_at': notification.created_at.isoformat(),
                'chat_room_id': notification.chat_room_id
            })
        
        return jsonify({'notifications': notifications_data}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to fetch notifications: {str(e)}'}), 500

@auth_bp.route('/notifications/mark-read', methods=['POST'])
@jwt_required()
def mark_notification_read():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        notification_id = data.get('notification_id')
        chat_room_id = data.get('chat_room_id')  # New parameter
        
        if not notification_id and not chat_room_id:
            return jsonify({'error': 'Either notification_id or chat_room_id is required'}), 400
        
        if chat_room_id:
            # Mark all notifications in this chat room as read
            notifications = Notification.query.filter_by(
                recipient_id=user.id, 
                chat_room_id=chat_room_id
            ).all()
            
            for notification in notifications:
                notification.read = True
            
            db.session.commit()
            
            return jsonify({
                'message': f'Marked {len(notifications)} notifications as read'
            }), 200
        else:
            # Mark single notification as read
            notification = Notification.query.filter_by(id=notification_id, recipient_id=user.id).first()
            if not notification:
                return jsonify({'error': 'Notification not found'}), 404
            
            notification.read = True
            db.session.commit()
            
            return jsonify({'message': 'Notification marked as read'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to mark notification as read: {str(e)}'}), 500

@auth_bp.route('/notifications/delete', methods=['POST'])
@jwt_required()
def delete_notification():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        notification_id = data.get('notification_id')
        
        if not notification_id:
            return jsonify({'error': 'Notification ID is required'}), 400
        
        # Find and delete notification
        notification = Notification.query.filter_by(id=notification_id, recipient_id=user.id).first()
        if not notification:
            return jsonify({'error': 'Notification not found'}), 404
        
        db.session.delete(notification)
        db.session.commit()
        
        return jsonify({'message': 'Notification deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete notification: {str(e)}'}), 500

@auth_bp.route('/notifications/delete-all', methods=['POST'])
@jwt_required()
def delete_all_notifications():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Get all chat rooms where this user is involved
        chat_rooms = ChatRoom.query.filter(
            (ChatRoom.user1_id == user.id) | (ChatRoom.user2_id == user.id)
        ).all()
        
        deleted_messages = 0
        deleted_notifications = 0
        deleted_chat_rooms = 0
        
        # Delete messages and notifications for each chat room
        for chat_room in chat_rooms:
            # Delete all messages in this chat room
            messages_deleted = Message.query.filter_by(chat_room_id=chat_room.id).delete()
            deleted_messages += messages_deleted
            
            # Delete all notifications for this chat room (for all users)
            notifications_deleted = Notification.query.filter_by(chat_room_id=chat_room.id).delete()
            deleted_notifications += notifications_deleted
            
            # Delete the chat room itself
            db.session.delete(chat_room)
            deleted_chat_rooms += 1
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully deleted {deleted_messages} messages, {deleted_notifications} notifications, and {deleted_chat_rooms} chat rooms'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete all conversations: {str(e)}'}), 500

@auth_bp.route('/notifications/delete-conversation', methods=['POST'])
@jwt_required()
def delete_conversation():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        print(f"Delete conversation request data: {data}")
        chat_room_id = data.get('chat_room_id')
        print(f"Chat room ID from request: {chat_room_id}")
        
        if not chat_room_id:
            return jsonify({'error': 'Chat room ID is required'}), 400
        
        # Check if chat room exists
        chat_room = ChatRoom.query.get(chat_room_id)
        if not chat_room:
            print(f"Chat room {chat_room_id} not found")
            return jsonify({'error': 'Chat room not found'}), 404
        
        print(f"Found chat room: {chat_room.id}, user1: {chat_room.user1_id}, user2: {chat_room.user2_id}")
        
        # Delete all messages in this chat room
        messages_to_delete = Message.query.filter_by(chat_room_id=chat_room_id).all()
        print(f"Found {len(messages_to_delete)} messages to delete")
        deleted_messages = Message.query.filter_by(chat_room_id=chat_room_id).delete()
        print(f"Deleted {deleted_messages} messages")
        
        # Delete all notifications for this chat room (for all users)
        notifications_to_delete = Notification.query.filter_by(
            chat_room_id=chat_room_id
        ).all()
        print(f"Found {len(notifications_to_delete)} notifications to delete")
        deleted_notifications = Notification.query.filter_by(
            chat_room_id=chat_room_id
        ).delete()
        print(f"Deleted {deleted_notifications} notifications")
        
        # Delete the chat room itself
        db.session.delete(chat_room)
        print(f"Marked chat room {chat_room_id} for deletion")
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully deleted conversation ({deleted_messages} messages, {deleted_notifications} notifications)'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting conversation: {str(e)}")
        print(f"Chat room ID: {chat_room_id}")
        print(f"User ID: {user.id}")
        return jsonify({'error': f'Failed to delete conversation: {str(e)}'}), 500

@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.json
    email = data.get('email')
    code = data.get('code')

    pending = PendingUser.query.filter_by(email=email).first()
    if not pending:
        return jsonify({'error': 'No pending registration found for this email'}), 404

    # Expired
    if datetime.now(timezone.utc) > as_aware_utc(pending.expires_at):
        db.session.delete(pending)
        db.session.commit()
        return jsonify({'error': 'Verification code expired'}), 400

    # Increment attempts and check
    pending.attempts = (pending.attempts or 0) + 1
    if pending.attempts > 3:
        db.session.delete(pending)
        db.session.commit()
        return jsonify({'error': 'Too many attempts. Please register again.'}), 400

    if str(code) != str(pending.verification_code):
        db.session.commit()  # persist attempt count
        return jsonify({'error': 'Invalid verification code'}), 400

    # Before creating the verified user, ensure final uniqueness
    if User.query.filter_by(username=pending.username).first():
        return jsonify({'error': 'Username already in use', 'code': 'username_taken'}), 409
    if User.query.filter_by(email=pending.email).first():
        return jsonify({'error': 'Email already in use', 'code': 'email_taken'}), 409

    # Create verified user
    new_user = User(
        username=pending.username,
        email=pending.email,
        password=pending.password_hash,
        auth_provider='email',
        is_email_verified=True
    )
    db.session.add(new_user)
    db.session.delete(pending)
    db.session.commit()

    return jsonify({'message': 'Email verified and account created', 'user_id': new_user.id}), 201

@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = request.json
    email = data.get('email')

    pending = PendingUser.query.filter_by(email=email).first()
    if not pending:
        return jsonify({'error': 'No pending registration found for this email'}), 404

    # Generate new code, reset attempts and expiry
    new_code = str(uuid.uuid4().int)[:6]
    pending.verification_code = new_code
    pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    pending.attempts = 0
    db.session.commit()

    try:
        from email_utils import send_verification_email
        send_verification_email(email, new_code)
        return jsonify({'message': 'Verification code resent', 'expires_in_minutes': 15}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to send verification email: {str(e)}'}), 500


@auth_bp.route('/verify-email-change', methods=['POST'])
@jwt_required()
def verify_email_change():
    data = request.json
    code = data.get('code')

    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    pending = PendingEmailChange.query.filter_by(user_id=user.id).first()
    if not pending:
        return jsonify({'error': 'No pending email change'}), 404

    # Expired
    if datetime.now(timezone.utc) > as_aware_utc(pending.expires_at):
        db.session.delete(pending)
        db.session.commit()
        return jsonify({'error': 'Verification code expired'}), 400

    # Attempts
    pending.attempts = (pending.attempts or 0) + 1
    if pending.attempts > 3:
        db.session.delete(pending)
        db.session.commit()
        return jsonify({'error': 'Too many attempts. Please try again later.'}), 400

    if str(code) != str(pending.verification_code):
        db.session.commit()
        return jsonify({'error': 'Invalid verification code'}), 400

    # Ensure target email still free
    if User.query.filter(User.email == pending.new_email, User.id != user.id).first():
        db.session.delete(pending)
        db.session.commit()
        return jsonify({'error': 'Email already in use'}), 400

    # Apply change
    user.email = pending.new_email
    db.session.delete(pending)
    db.session.commit()
    return jsonify({'message': 'Email updated successfully'}), 200

# Post Like Endpoints
@auth_bp.route('/posts/<int:post_id>/like', methods=['POST'])
@jwt_required()
def like_post(post_id):
    current_user_id = get_jwt_identity()
    user = db.session.get(User, int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Check if post exists
        post = db.session.get(Post, post_id)
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        # Check if user already liked this post
        existing_like = PostLike.query.filter_by(user_id=user.id, post_id=post_id).first()
        if existing_like:
            return jsonify({'error': 'Post already liked', 'liked': True}), 200

        # Create new like
        like = PostLike(user_id=user.id, post_id=post_id)
        db.session.add(like)
        db.session.commit()

        # Get updated like count
        like_count = PostLike.query.filter_by(post_id=post_id).count()

        return jsonify({
            'message': 'Post liked successfully',
            'liked': True,
            'like_count': like_count
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to like post: {str(e)}'}), 500

@auth_bp.route('/posts/<int:post_id>/unlike', methods=['DELETE'])
@jwt_required()
def unlike_post(post_id):
    current_user_id = get_jwt_identity()
    user = db.session.get(User, int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Find and remove the like
        like = PostLike.query.filter_by(user_id=user.id, post_id=post_id).first()
        if not like:
            return jsonify({'error': 'Post not liked', 'liked': False}), 200

        db.session.delete(like)
        db.session.commit()

        # Get updated like count
        like_count = PostLike.query.filter_by(post_id=post_id).count()

        return jsonify({
            'message': 'Post unliked successfully',
            'liked': False,
            'like_count': like_count
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to unlike post: {str(e)}'}), 500

@auth_bp.route('/posts/<int:post_id>/like-status', methods=['GET'])
@jwt_required()
def get_like_status(post_id):
    current_user_id = get_jwt_identity()
    user = db.session.get(User, int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Check if post exists
        post = db.session.get(Post, post_id)
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        # Check if user liked this post
        liked = PostLike.query.filter_by(user_id=user.id, post_id=post_id).first() is not None
        
        # Get like count
        like_count = PostLike.query.filter_by(post_id=post_id).count()

        return jsonify({
            'liked': liked,
            'like_count': like_count
        }), 200

    except Exception as e:
        return jsonify({'error': f'Failed to get like status: {str(e)}'}), 500

# Post Report Endpoints
@auth_bp.route('/posts/<int:post_id>/report', methods=['POST'])
@jwt_required()
def report_post(post_id):
    current_user_id = get_jwt_identity()
    user = db.session.get(User, int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        data = request.json
        reason = data.get('reason')
        description = data.get('description')

        if not reason or not description:
            return jsonify({'error': 'Reason and description are required'}), 400

        # Check if post exists
        post = db.session.get(Post, post_id)
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        # Check if user already reported this post
        existing_report = PostReport.query.filter_by(reporter_id=user.id, post_id=post_id).first()
        if existing_report:
            return jsonify({'error': 'Post already reported', 'reported': True}), 200

        # Create new report
        report = PostReport(
            reporter_id=user.id,
            post_id=post_id,
            reason=reason,
            description=description
        )
        db.session.add(report)
        db.session.commit()

        return jsonify({
            'message': 'Post reported successfully',
            'reported': True
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to report post: {str(e)}'}), 500

@auth_bp.route('/posts/<int:post_id>/report-status', methods=['GET'])
@jwt_required()
def get_report_status(post_id):
    current_user_id = get_jwt_identity()
    user = db.session.get(User, int(current_user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        # Check if post exists
        post = db.session.get(Post, post_id)
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        # Check if user reported this post
        reported = PostReport.query.filter_by(reporter_id=user.id, post_id=post_id).first() is not None

        return jsonify({
            'reported': reported
        }), 200

    except Exception as e:
        return jsonify({'error': f'Failed to get report status: {str(e)}'}), 500