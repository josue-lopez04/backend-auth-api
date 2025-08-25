# main.py - Auth Service Corregido
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración
MONGO_URI = os.environ.get('MONGO_URI', '')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
PORT = int(os.environ.get('PORT', 8080))

# Conexión a MongoDB con manejo de errores
client = None
db = None
users_collection = None

def connect_to_mongodb():
    """Intentar conectar a MongoDB con reintentos"""
    global client, db, users_collection
    
    if not MONGO_URI:
        logger.warning("MONGO_URI not configured - running in demo mode")
        return False
    
    try:
        logger.info("Attempting to connect to MongoDB...")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        # Verificar conexión
        client.server_info()
        db = client.authdb
        users_collection = db.users
        logger.info("Successfully connected to MongoDB")
        return True
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error connecting to MongoDB: {str(e)}")
        return False

# Intentar conectar al inicio
mongodb_connected = connect_to_mongodb()

@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        'service': 'Auth API',
        'status': 'running',
        'mongodb': 'connected' if mongodb_connected else 'disconnected',
        'endpoints': ['/health', '/api/auth/login', '/api/auth/register']
    }), 200

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Auth API',
        'timestamp': datetime.datetime.now().isoformat(),
        'mongodb': 'connected' if mongodb_connected else 'disconnected',
        'port': PORT
    }), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Registrar nuevo usuario"""
    if not mongodb_connected:
        return jsonify({
            'error': 'Database connection unavailable',
            'demo_user': {'email': 'demo@test.com', 'password': 'demo123'}
        }), 503
    
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
        logger.error(f"Error in register: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login de usuario"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        # Modo demo si MongoDB no está conectado
        if not mongodb_connected:
            if data['email'] == 'demo@test.com' and data['password'] == 'demo123':
                token = jwt.encode({
                    'user_id': 'demo_user',
                    'email': 'demo@test.com',
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                }, JWT_SECRET, algorithm='HS256')
                
                return jsonify({
                    'token': token,
                    'email': 'demo@test.com',
                    'name': 'Demo User',
                    'mode': 'demo'
                }), 200
            else:
                return jsonify({
                    'error': 'Invalid credentials',
                    'hint': 'Try demo@test.com / demo123'
                }), 401
        
        # Buscar usuario en MongoDB
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
        logger.error(f"Error in login: {str(e)}")
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
    if not mongodb_connected:
        return jsonify({
            'error': 'Database connection unavailable',
            'message': 'Use demo@test.com / demo123 for testing'
        }), 503
    
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
        logger.error(f"Error in seed: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info(f"Starting Auth Service on port {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)