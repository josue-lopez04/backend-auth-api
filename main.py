from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os

app = Flask(__name__)
CORS(app)

# Configuración
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb+srv://admin:Movies2024Secure!@movies-cluster.xxxxx.mongodb.net/authdb?retryWrites=true&w=majority')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')

# Conexión a MongoDB
client = MongoClient(MONGO_URI)
db = client.authdb
users_collection = db.users

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Auth API',
        'timestamp': datetime.datetime.now().isoformat()
    }), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Registrar nuevo usuario"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        # Verificar si el usuario existe
        if users_collection.find_one({'email': data['email']}):
            return jsonify({'error': 'User already exists'}), 409
        
        # Crear usuario
        hashed_password = generate_password_hash(data['password'])
        user = {
            'email': data['email'],
            'password': hashed_password,
            'name': data.get('name', ''),
            'created_at': datetime.datetime.utcnow()
        }
        
        users_collection.insert_one(user)
        
        return jsonify({
            'message': 'User created successfully',
            'email': data['email']
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login de usuario"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        # Buscar usuario
        user = users_collection.find_one({'email': data['email']})
        
        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generar token JWT
        token = jwt.encode({
            'user_id': str(user['_id']),
            'email': user['email'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            'token': token,
            'email': user['email'],
            'name': user.get('name', '')
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/verify', methods=['GET'])
def verify_token():
    """Verificar token JWT"""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        
        return jsonify({
            'valid': True,
            'email': decoded['email']
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/auth/seed', methods=['POST'])
def seed_users():
    """Crear usuarios de prueba"""
    try:
        # Limpiar colección
        users_collection.delete_many({})
        
        # Usuarios de prueba
        test_users = [
            {'email': 'admin@test.com', 'password': 'admin123', 'name': 'Admin User'},
            {'email': 'user@test.com', 'password': 'user123', 'name': 'Test User'},
            {'email': 'demo@test.com', 'password': 'demo123', 'name': 'Demo User'}
        ]
        
        for user_data in test_users:
            user_data['password'] = generate_password_hash(user_data['password'])
            user_data['created_at'] = datetime.datetime.utcnow()
            users_collection.insert_one(user_data)
        
        return jsonify({
            'message': 'Test users created',
            'users': ['admin@test.com', 'user@test.com', 'demo@test.com']
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)