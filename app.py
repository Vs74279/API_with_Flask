from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os

# Flask app and configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)

# Create database
with app.app_context():
    db.create_all()

# JWT Token Helper Functions
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            token = token.split(" ")[1]  # Bearer <token>
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(email=data['sub']).first()
        except Exception as e:
            return jsonify({'message': f'Token is invalid! Error: {str(e)}'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def create_access_token(email, expires_in=30):
    expiration = datetime.utcnow() + timedelta(minutes=expires_in)
    token = jwt.encode({'sub': email, 'exp': expiration}, app.config['SECRET_KEY'], algorithm="HS256")
    return token

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Check if user already exists
    if User.query.filter((User.name == name) | (User.email == email)).first():
        return jsonify({'message': 'User already exists!'}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')

    # Fetch user from the database
    user = User.query.filter_by(name=name).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Generate JWT token
    token = create_access_token(user.email)
    return jsonify({'access_token': token, 'token_type': 'Bearer'}), 200

@app.route('/protected-data', methods=['GET'])
@token_required
def protected_data(current_user):
    return jsonify({
        'name': current_user.name,
        'email': current_user.email
    }), 200

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
