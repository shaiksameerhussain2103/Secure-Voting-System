#!/usr/bin/env python3
"""
Secure Online Voting System Using RSA Algorithm
A Flask-based voting application with RSA encryption for vote confidentiality
"""

import os
import json
import base64
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secure-voting-system-2024-rsa-encryption')

# Configuration
RSA_KEY_SIZE = 2048
USERS_FILE = 'data/users.json'
VOTES_FILE = 'data/votes.json'
CANDIDATES_FILE = 'data/candidates.json'
PRIVATE_KEY_FILE = 'rsa_keys/private.pem'
PUBLIC_KEY_FILE = 'rsa_keys/public.pem'

def generate_rsa_keys():
    """Generate RSA key pair and save to files"""
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Save keys to files
        with open(PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_pem)
        
        with open(PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_pem)
        
        print("[INFO] RSA key pair generated successfully")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to generate RSA keys: {e}")
        return False

def load_public_key():
    """Load public key from file"""
    try:
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        print(f"[ERROR] Failed to load public key: {e}")
        return None

def load_private_key():
    """Load private key from file"""
    try:
        with open(PRIVATE_KEY_FILE, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        print(f"[ERROR] Failed to load private key: {e}")
        return None

def decrypt_vote(encrypted_vote_b64):
    """Decrypt a vote using the private key"""
    try:
        private_key = load_private_key()
        if not private_key:
            return None
        
        # Decode from base64
        encrypted_vote = base64.b64decode(encrypted_vote_b64)
        
        # Decrypt
        decrypted_vote = private_key.decrypt(
            encrypted_vote,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted_vote.decode('utf-8')
    except Exception as e:
        print(f"[ERROR] Failed to decrypt vote: {e}")
        return None

def load_users():
    """Load users from JSON file"""
    if not os.path.exists(USERS_FILE):
        # Create default users including admin
        default_users = {
            "admin": {
                "password": "admin123",
                "role": "admin",
                "name": "Administrator"
            }
        }
        save_users(default_users)
        return default_users
    
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load users: {e}")
        return {}

def save_users(users):
    """Save users to JSON file"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save users: {e}")
        return False

def load_votes():
    """Load votes from JSON file"""
    if not os.path.exists(VOTES_FILE):
        return []
    
    try:
        with open(VOTES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load votes: {e}")
        return []

def save_votes(votes):
    """Save votes to JSON file"""
    try:
        with open(VOTES_FILE, 'w') as f:
            json.dump(votes, f, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save votes: {e}")
        return False

def has_user_voted(username):
    """Check if user has already voted"""
    votes = load_votes()
    for vote in votes:
        if vote.get('username') == username:
            return True
    return False

def load_candidates():
    """Load candidates from JSON file"""
    if not os.path.exists(CANDIDATES_FILE):
        # Create default candidates
        default_candidates = [
            {"id": 1, "name": "Candidate A", "description": "Experience in public service and community development"},
            {"id": 2, "name": "Candidate B", "description": "Background in economics and environmental policy"},
            {"id": 3, "name": "Candidate C", "description": "Focus on education reform and technology innovation"}
        ]
        save_candidates(default_candidates)
        return default_candidates
    
    try:
        with open(CANDIDATES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load candidates: {e}")
        return []

def save_candidates(candidates):
    """Save candidates to JSON file"""
    try:
        with open(CANDIDATES_FILE, 'w') as f:
            json.dump(candidates, f, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save candidates: {e}")
        return False

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed_password):
    """Verify password against hash"""
    return hash_password(password) == hashed_password

@app.route('/')
def index():
    """Home page / Login page"""
    if 'username' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('vote'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()
        
        if not username or not password or not full_name:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        users = load_users()
        
        if username in users:
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        # Add new user
        users[username] = {
            'password': hash_password(password),
            'role': 'voter',
            'name': full_name,
            'registered_at': datetime.now().isoformat(),
            'has_voted': False
        }
        
        if save_users(users):
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    """User login"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        flash('Username and password are required', 'error')
        return redirect(url_for('index'))
    
    users = load_users()
    
    if username in users and verify_password(password, users[username]['password']):
        session['username'] = username
        session['role'] = users[username]['role']
        session['name'] = users[username]['name']
        
        if users[username]['role'] == 'admin':
            flash(f'Welcome back, {users[username]["name"]}!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash(f'Welcome, {users[username]["name"]}!', 'success')
            return redirect(url_for('vote'))
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/vote')
def vote():
    """Voting page"""
    if 'username' not in session or session.get('role') != 'voter':
        flash('Please login as a voter to access this page', 'error')
        return redirect(url_for('index'))
    
    # Check if user has already voted
    candidates = load_candidates()
    if has_user_voted(session['username']):
        flash('You have already cast your vote!', 'info')
        return render_template('vote.html', candidates=candidates, already_voted=True)
    
    return render_template('vote.html', candidates=candidates, already_voted=False)

@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    """Handle encrypted vote submission"""
    if 'username' not in session or session.get('role') != 'voter':
        return jsonify({'success': False, 'message': 'Unauthorized access'})
    
    # Check if user has already voted
    if has_user_voted(session['username']):
        return jsonify({'success': False, 'message': 'You have already voted'})
    
    encrypted_vote = request.json.get('encrypted_vote')
    
    if not encrypted_vote:
        return jsonify({'success': False, 'message': 'No vote data received'})
    
    # Save encrypted vote
    votes = load_votes()
    vote_record = {
        'username': session['username'],
        'encrypted_vote': encrypted_vote,
        'timestamp': datetime.now().isoformat(),
        'voter_name': session['name']
    }
    
    votes.append(vote_record)
    
    if save_votes(votes):
        return jsonify({'success': True, 'message': 'Vote cast successfully!'})
    else:
        return jsonify({'success': False, 'message': 'Failed to save vote'})

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page and authentication"""
    if 'username' in session and session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        admin_username = os.getenv('ADMIN_USERNAME', 'admin_user')
        admin_password = os.getenv('ADMIN_PASSWORD', 'admin_secure_password')
        
        if username == admin_username and password == admin_password:
            session['username'] = username
            session['role'] = 'admin'
            session['name'] = 'Administrator'
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    """Admin dashboard with decrypted results"""
    if 'username' not in session or session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('admin_login'))
    
    votes = load_votes()
    
    # Decrypt votes and count results
    results = {}
    valid_votes = 0
    invalid_votes = 0
    
    candidates = load_candidates()
    for vote_record in votes:
        decrypted_vote = decrypt_vote(vote_record['encrypted_vote'])
        if decrypted_vote:
            try:
                candidate_id = int(decrypted_vote)
                candidate = next((c for c in candidates if c['id'] == candidate_id), None)
                if candidate:
                    candidate_name = candidate['name']
                    results[candidate_name] = results.get(candidate_name, 0) + 1
                    valid_votes += 1
                else:
                    invalid_votes += 1
            except ValueError:
                invalid_votes += 1
        else:
            invalid_votes += 1
    
    total_votes = valid_votes + invalid_votes
    
    return render_template('admin_dashboard.html', 
                         results=results, 
                         candidates=candidates,
                         total_votes=total_votes,
                         valid_votes=valid_votes,
                         invalid_votes=invalid_votes)

@app.route('/get_public_key')
def get_public_key():
    """API endpoint to get public key for frontend encryption"""
    try:
        with open(PUBLIC_KEY_FILE, 'r') as f:
            public_key_pem = f.read()
        return jsonify({'public_key': public_key_pem})
    except Exception as e:
        return jsonify({'error': 'Failed to load public key'}), 500

@app.route('/rsa_demo')
def rsa_demo():
    """RSA Demonstration and Visualization Page"""
    return render_template('rsa_demo.html')

@app.route('/rsa_encrypt_demo', methods=['POST'])
def rsa_encrypt_demo():
    """Demo endpoint to encrypt text using RSA public key"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Load public key
        public_key = load_public_key()
        if not public_key:
            return jsonify({'error': 'Failed to load public key'}), 500
        
        # Encrypt the message
        message_bytes = message.encode('utf-8')
        encrypted_data = public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Convert to base64 for frontend display
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        
        return jsonify({
            'success': True,
            'encrypted_message': encrypted_b64,
            'original_message': message,
            'encryption_method': 'RSA-OAEP with SHA-256',
            'key_size': RSA_KEY_SIZE
        })
        
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/rsa_decrypt_demo', methods=['POST'])
def rsa_decrypt_demo():
    """Demo endpoint to decrypt RSA encrypted text using private key"""
    try:
        data = request.get_json()
        encrypted_message_b64 = data.get('encrypted_message', '')
        
        if not encrypted_message_b64:
            return jsonify({'error': 'No encrypted message provided'}), 400
        
        # Load private key
        private_key = load_private_key()
        if not private_key:
            return jsonify({'error': 'Failed to load private key'}), 500
        
        # Decode from base64 and decrypt
        encrypted_data = base64.b64decode(encrypted_message_b64)
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_message = decrypted_data.decode('utf-8')
        
        return jsonify({
            'success': True,
            'decrypted_message': decrypted_message,
            'decryption_method': 'RSA-OAEP with SHA-256',
            'key_size': RSA_KEY_SIZE
        })
        
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

def initialize_app():
    """Initialize the application"""
    print("[INFO] Initializing Secure Voting System...")
    
    # Create data directories if they don't exist
    os.makedirs('data', exist_ok=True)
    os.makedirs('rsa_keys', exist_ok=True)
    
    # Generate RSA keys if they don't exist
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        print("[INFO] Generating RSA key pair...")
        if not generate_rsa_keys():
            print("[ERROR] Failed to generate RSA keys. Exiting.")
            return False
    else:
        print("[INFO] RSA keys found")
    
    # Initialize users file
    load_users()
    
    print("[INFO] Application initialized successfully")
    return True

if __name__ == '__main__':
    if initialize_app():
        print("[INFO] Flask server starting on http://127.0.0.1:5000")
        print("[INFO] RSA keys loaded successfully")
        print("[INFO] Default admin credentials: admin / admin123")
        app.run(debug=True, host='127.0.0.1', port=5000)
    else:
        print("[ERROR] Failed to initialize application")