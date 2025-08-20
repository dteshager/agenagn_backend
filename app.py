from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timezone
import json

from config import Config
from models import db



def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)
    
        # Configure CORS to allow all localhost origins and mobile device access
    CORS(app, origins=[
         "http://localhost:3000", "http://localhost:5000", "http://localhost:5173", "http://localhost:5174", 
         "http://localhost:5175", "http://localhost:5176", "http://localhost:5177", "http://localhost:5178", 
         "http://localhost:5179",
         "http://10.0.2.2:5000",      # Android Emulator
         "http://10.0.0.177:5000",    # Your computer's WiFi IP for physical device
         "http://192.168.1.177:5000", # Alternative IP format
         ], 
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization", "Accept"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    
    db.init_app(app)

    # Initialize Flask-JWT-Extended
    jwt = JWTManager(app)

    # Initialize SockerIO
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    with app.app_context():
        from models import User, Post, PostImage, ChatRoom, Message, Notification
        db.create_all()

        from auth_routes import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/api')

    # Store active users
    active_users = {}  #This might be better if it was a global variable.

    #Socket.IO event handlers
    @socketio.on('connect')
    def handle_connect():
        print(f'Client connected:  {request.sid}')

    @socketio.on('disconnect')
    def handle_disconnect():
        print(f'Client disconnected: {request.sid}')
        # Remove user from active users
        user_id = None
        for uid, sid in active_users.items():
            if sid == request.sid:
                user_id = uid
                break
        if user_id:
            del active_users[user_id]

    @socketio.on('join')
    def handle_join(data):
        user_id = data.get('user_id')
        username = data.get('username')
        active_users[user_id] = request.sid
        join_room(f'user_{user_id}')
        print(f'User {username} joined with ID: {user_id}')

    @socketio.on('start_chat')
    def handle_start_chat(data):
        user1_id = data.get('user1_id')
        user2_id = data.get('user2_id')
        post_id = data.get('post_id')
        
        print(f"Starting chat with: user1_id={user1_id}, user2_id={user2_id}, post_id={post_id}")
        


        # Convert to integers if they're strings
        if user1_id is not None:
            user1_id = int(user1_id)
        if user2_id is not None:
            user2_id = int(user2_id)
        if post_id is not None:
            post_id = int(post_id)

        # Create or retrieve chat room logic here
        chat_room = ChatRoom.query.filter(
            ((ChatRoom.user1_id == user1_id) & (ChatRoom.user2_id == user2_id) & (ChatRoom.post_id == post_id)) |
            ((ChatRoom.user1_id == user2_id) & (ChatRoom.user2_id == user1_id) & (ChatRoom.post_id == post_id))
        ).first()
        
        if chat_room:
            print(f"Found existing chat room: {chat_room.id}")
        else:
            print(f"Creating new chat room for users {user1_id} and {user2_id}, post {post_id}")
            chat_room = ChatRoom(user1_id=user1_id, user2_id=user2_id, post_id=post_id)
            db.session.add(chat_room)
            db.session.commit()
            print(f"Created chat room with ID: {chat_room.id}")

        # Join both users to chat room
        join_room(f'chat_{chat_room.id}')

        #Get existing messages
        messages = Message.query.filter_by(chat_room_id=chat_room.id).order_by(Message.timestamp.desc()).all()
        print(f"Found {len(messages)} existing messages for chat room {chat_room.id}")
        
        messages_data = [{
            '_id': msg.id,  # Use _id for consistency with GiftedChat
            'text': msg.content,
            'user': {
                '_id': msg.sender.id,
                'name': msg.sender.username,
            },
            'createdAt': msg.timestamp.isoformat() + 'Z'  # Add 'Z' to indicate UTC
        } for msg in messages]
        
        print(f"Emitting chat_room_created with {len(messages_data)} messages")
        emit('chat_room_created', {
            'room_id': chat_room.id,
            'messages': messages_data
        })

    @socketio.on('send_message')
    def handle_send_message(data):
        room_id = data.get('room_id')
        sender_id = data.get('sender_id')
        message_text = data.get('message')

        # Save message to the database
        message = Message(chat_room_id=room_id,
                          sender_id=sender_id,
                          content=message_text,
                          timestamp=datetime.now(timezone.utc)
                          )
        db.session.add(message)
        db.session.commit()

        # Get chat room and post info
        chat_room = db.session.get(ChatRoom, room_id)
        post = db.session.get(Post, chat_room.post_id)
        
        # Determine recipient (the other user in the chat)
        recipient_id = chat_room.user1_id if sender_id == chat_room.user2_id else chat_room.user2_id
        
        print(f"Creating notification: sender_id={sender_id}, recipient_id={recipient_id}")
        print(f"Chat room: user1_id={chat_room.user1_id}, user2_id={chat_room.user2_id}")
        
        # Create notification for the recipient
        notification = Notification(
            recipient_id=recipient_id,
            sender_id=sender_id,
            chat_room_id=room_id,
            message_preview=message_text[:100] + "..." if len(message_text) > 100 else message_text,
            post_title=post.title
        )
        db.session.add(notification)
        db.session.commit()
        
        # Get senders info
        sender = db.session.get(User, sender_id)
        
        print(f"Created notification: recipient_id={recipient_id}, sender_id={sender_id}")
        print(f"Sender username: {sender.username}")
        print(f"Recipient should be different from sender: {recipient_id != sender_id}")

        # Emit message to the chat room
        emit('new_message', {
            '_id': message.id,  # Use _id for consistency with GiftedChat
            'text': message.content,
            'user': {
                '_id': sender.id,
                'name': sender.username,
            },
            'createdAt': message.timestamp.isoformat() + 'Z'  # Add 'Z' to indicate UTC
        }, to=f'chat_{room_id}')

    @socketio.on('join_chat_room')
    def handle_join_chat_room(data):
        room_id = data.get('room_id')
        join_room(f'chat_{room_id}')

    @socketio.on('typing')
    def handle_typing(data):
        room_id = data.get('room_id')
        user_id = data.get('user_id')
        username = data.get('username')
        
        # Emit typing indicator to the chat room (excluding the sender)
        emit('user_typing', {
            'user_id': user_id,
            'username': username,
            'room_id': room_id
        }, to=f'chat_{room_id}', include_self=False)

    @socketio.on('stop_typing')
    def handle_stop_typing(data):
        room_id = data.get('room_id')
        user_id = data.get('user_id')
        username = data.get('username')
        
        # Emit stop typing indicator to the chat room (excluding the sender)
        emit('user_stopped_typing', {
            'user_id': user_id,
            'username': username,
            'room_id': room_id
        }, to=f'chat_{room_id}', include_self=False)


    @app.route('/')
    def home():
        return "Welcome to the Flask App!"
    
    # Route to serve uploaded images
    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory('uploads', filename)
    
    return app, socketio

app, socketio = create_app()

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', allow_unsafe_werkzeug=True, port=5000)