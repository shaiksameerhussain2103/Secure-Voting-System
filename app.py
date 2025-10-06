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
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from werkzeug.utils import secure_filename
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
REGIONS_FILE = 'data/regions.json'
ELECTION_STATUS_FILE = 'data/election_status.json'
RESULTS_FILE = 'data/results.json'
PRIVATE_KEY_FILE = 'rsa_keys/private.pem'
PUBLIC_KEY_FILE = 'rsa_keys/public.pem'
UPLOAD_FOLDER = 'static/uploads/candidate_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Configure Flask upload settings
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

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

def load_regions():
    """Load regions from JSON file"""
    if not os.path.exists(REGIONS_FILE):
        # Create default regions
        default_regions = [
            {"id": 1, "name": "North Region", "description": "Northern constituency covering upper districts"},
            {"id": 2, "name": "South Region", "description": "Southern constituency covering lower districts"},
            {"id": 3, "name": "East Region", "description": "Eastern constituency covering coastal areas"},
            {"id": 4, "name": "West Region", "description": "Western constituency covering industrial areas"}
        ]
        save_regions(default_regions)
        return default_regions
    
    try:
        with open(REGIONS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load regions: {e}")
        return []

def save_regions(regions):
    """Save regions to JSON file"""
    try:
        with open(REGIONS_FILE, 'w') as f:
            json.dump(regions, f, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save regions: {e}")
        return False

def load_election_status():
    """Load election status from JSON file"""
    if not os.path.exists(ELECTION_STATUS_FILE):
        # Create default election status
        default_status = {
            "election_active": True,
            "election_completed": False,
            "winner_declared": False,
            "election_start_date": datetime.now().isoformat(),
            "election_end_date": None,
            "total_registered_voters": 0,
            "total_votes_cast": 0
        }
        save_election_status(default_status)
        return default_status
    
    try:
        with open(ELECTION_STATUS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load election status: {e}")
        return {}

def save_election_status(status):
    """Save election status to JSON file"""
    try:
        with open(ELECTION_STATUS_FILE, 'w') as f:
            json.dump(status, f, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save election status: {e}")
        return False

def load_results():
    """Load results from JSON file"""
    if not os.path.exists(RESULTS_FILE):
        # Create default results structure
        default_results = {
            "overall_winner": None,
            "regional_results": [],
            "vote_summary": {
                "total_votes": 0,
                "valid_votes": 0,
                "invalid_votes": 0
            },
            "candidate_results": [],
            "declared_at": None,
            "declared_by": None
        }
        save_results(default_results)
        return default_results
    
    try:
        with open(RESULTS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load results: {e}")
        return {}

def save_results(results):
    """Save results to JSON file"""
    try:
        with open(RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save results: {e}")
        return False

def allowed_file(filename):
    """Check if uploaded file has allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    """Decorator to require admin authentication"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

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
    regions = load_regions()
    if has_user_voted(session['username']):
        flash('You have already cast your vote!', 'info')
        return render_template('vote.html', candidates=candidates, regions=regions, already_voted=True)
    
    return render_template('vote.html', candidates=candidates, regions=regions, already_voted=False)

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

# ============ ADMIN ROUTES ============

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard showing overview of election"""
    candidates = load_candidates()
    users = load_users()
    votes = load_votes()
    regions = load_regions()
    election_status = load_election_status()
    
    # Calculate statistics
    stats = {
        'total_candidates': len(candidates),
        'total_registered_voters': len(users),
        'total_votes_cast': len(votes),
        'total_regions': len(regions),
        'election_active': election_status.get('election_active', False),
        'winner_declared': election_status.get('winner_declared', False)
    }
    
    return render_template('admin/dashboard.html', stats=stats, election_status=election_status)

@app.route('/admin/manage_candidates', methods=['GET', 'POST'])
@admin_required
def manage_candidates():
    """Manage candidates page"""
    # If POST request, redirect to GET (handles any accidental POST requests)
    if request.method == 'POST':
        return redirect(url_for('manage_candidates'))
    
    candidates = load_candidates()
    regions = load_regions()
    return render_template('admin/manage_candidates.html', candidates=candidates, regions=regions)

@app.route('/admin/add_candidate', methods=['POST'])
@admin_required
def add_candidate():
    """Add new candidate"""
    name = request.form.get('name')
    party = request.form.get('party')
    region_id = request.form.get('region_id')
    bio = request.form.get('bio', '')
    
    if not name or not party or not region_id:
        flash('All required fields must be filled', 'error')
        return redirect(url_for('manage_candidates'))
    
    candidates = load_candidates()
    
    # Generate new candidate ID
    new_id = max([c['id'] for c in candidates], default=0) + 1
    
    # Handle file upload
    image_filename = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Create upload directory if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            try:
                file.save(file_path)
                image_filename = filename
            except Exception as e:
                flash(f'Failed to upload image: {str(e)}', 'error')
                return redirect(url_for('manage_candidates'))
    
    # Create new candidate
    new_candidate = {
        'id': new_id,
        'name': name,
        'party': party,
        'region_id': int(region_id),
        'bio': bio,
        'image': image_filename
    }
    
    candidates.append(new_candidate)
    
    if save_candidates(candidates):
        flash(f'Candidate {name} added successfully', 'success')
    else:
        flash('Failed to add candidate', 'error')
    
    return redirect(url_for('manage_candidates'))

@app.route('/admin/edit_candidate/<int:candidate_id>', methods=['POST'])
@admin_required
def edit_candidate(candidate_id):
    """Edit existing candidate"""
    candidates = load_candidates()
    candidate = next((c for c in candidates if c['id'] == candidate_id), None)
    
    if not candidate:
        flash('Candidate not found', 'error')
        return redirect(url_for('manage_candidates'))
    
    # Update candidate fields
    candidate['name'] = request.form.get('name', candidate['name'])
    candidate['party'] = request.form.get('party', candidate['party'])
    candidate['region_id'] = int(request.form.get('region_id', candidate['region_id']))
    candidate['bio'] = request.form.get('bio', candidate.get('bio', ''))
    
    # Handle image upload
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            # Delete old image if exists
            if candidate.get('image'):
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate['image'])
                if os.path.exists(old_image_path):
                    try:
                        os.remove(old_image_path)
                    except Exception as e:
                        print(f"[WARNING] Could not delete old image: {e}")
            
            # Save new image
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(file_path)
                candidate['image'] = filename
            except Exception as e:
                flash(f'Failed to upload new image: {str(e)}', 'error')
                return redirect(url_for('manage_candidates'))
    
    if save_candidates(candidates):
        flash(f'Candidate {candidate["name"]} updated successfully', 'success')
    else:
        flash('Failed to update candidate', 'error')
    
    return redirect(url_for('manage_candidates'))

@app.route('/admin/delete_candidate/<int:candidate_id>')
@admin_required
def delete_candidate(candidate_id):
    """Delete candidate"""
    candidates = load_candidates()
    candidate = next((c for c in candidates if c['id'] == candidate_id), None)
    
    if not candidate:
        flash('Candidate not found', 'error')
        return redirect(url_for('manage_candidates'))
    
    # Delete candidate image if exists
    if candidate.get('image'):
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate['image'])
        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except Exception as e:
                print(f"[WARNING] Could not delete image: {e}")
    
    # Remove candidate from list
    candidates = [c for c in candidates if c['id'] != candidate_id]
    
    if save_candidates(candidates):
        flash(f'Candidate {candidate["name"]} deleted successfully', 'success')
    else:
        flash('Failed to delete candidate', 'error')
    
    return redirect(url_for('manage_candidates'))

@app.route('/admin/manage_voters')
@admin_required
def manage_voters():
    """Manage voters page"""
    users = load_users()
    votes = load_votes()
    
    # Get list of usernames who have voted
    voted_usernames = {vote['username'] for vote in votes}
    
    # Convert users dict to list and add voting status
    users_list = []
    for username, user_data in users.items():
        if user_data.get('role') == 'voter':  # Only include voters, not admin
            user_info = {
                'id': len(users_list) + 1,  # Generate sequential ID for display
                'username': username,
                'full_name': user_data.get('name', ''),
                'registration_date': user_data.get('registered_at', ''),
                'has_voted': username in voted_usernames
            }
            users_list.append(user_info)
    
    return render_template('admin/manage_voters.html', users=users_list)

@app.route('/admin/manage_regions')
@admin_required
def manage_regions():
    """Manage regions page"""
    regions = load_regions()
    candidates = load_candidates()
    
    # Add candidate count to regions
    for region in regions:
        # Count candidates that belong to this region by name
        region['candidate_count'] = len([c for c in candidates if c.get('region') == region['name']])
    
    return render_template('admin/manage_regions.html', regions=regions)

@app.route('/admin/add_region', methods=['POST'])
@admin_required
def add_region():
    """Add new region"""
    name = request.form.get('name')
    description = request.form.get('description', '')
    
    if not name:
        flash('Region name is required', 'error')
        return redirect(url_for('manage_regions'))
    
    regions = load_regions()
    
    # Generate new region ID
    new_id = max([r['id'] for r in regions], default=0) + 1
    
    new_region = {
        'id': new_id,
        'name': name,
        'description': description
    }
    
    regions.append(new_region)
    
    if save_regions(regions):
        flash(f'Region {name} added successfully', 'success')
    else:
        flash('Failed to add region', 'error')
    
    return redirect(url_for('manage_regions'))

@app.route('/admin/edit_region/<int:region_id>', methods=['POST'])
@admin_required
def edit_region(region_id):
    """Edit existing region"""
    regions = load_regions()
    region = next((r for r in regions if r['id'] == region_id), None)
    
    if not region:
        flash('Region not found', 'error')
        return redirect(url_for('manage_regions'))
    
    region['name'] = request.form.get('name', region['name'])
    region['description'] = request.form.get('description', region.get('description', ''))
    
    if save_regions(regions):
        flash(f'Region {region["name"]} updated successfully', 'success')
    else:
        flash('Failed to update region', 'error')
    
    return redirect(url_for('manage_regions'))

@app.route('/admin/delete_region/<int:region_id>')
@admin_required
def delete_region(region_id):
    """Delete region"""
    regions = load_regions()
    region = next((r for r in regions if r['id'] == region_id), None)
    
    if not region:
        flash('Region not found', 'error')
        return redirect(url_for('manage_regions'))
    
    # Check if region has candidates
    candidates = load_candidates()
    region_candidates = [c for c in candidates if c['region_id'] == region_id]
    
    if region_candidates:
        flash(f'Cannot delete region {region["name"]} - it has {len(region_candidates)} candidate(s)', 'error')
        return redirect(url_for('manage_regions'))
    
    # Remove region from list
    regions = [r for r in regions if r['id'] != region_id]
    
    if save_regions(regions):
        flash(f'Region {region["name"]} deleted successfully', 'success')
    else:
        flash('Failed to delete region', 'error')
    
    return redirect(url_for('manage_regions'))

@app.route('/admin/view_results')
@admin_required
def view_results():
    """View election results"""
    votes = load_votes()
    candidates = load_candidates()
    regions = load_regions()
    election_status = load_election_status()
    
    # Calculate vote counts per candidate by decrypting votes
    candidate_votes = {}
    valid_votes = 0
    for vote in votes:
        try:
            # Decrypt the vote to get candidate ID
            decrypted_vote = decrypt_vote(vote['encrypted_vote'])
            if decrypted_vote:
                candidate_id = int(decrypted_vote)
                candidate_votes[candidate_id] = candidate_votes.get(candidate_id, 0) + 1
                valid_votes += 1
        except (ValueError, KeyError) as e:
            # Skip invalid votes
            print(f"[WARNING] Invalid vote skipped: {e}")
            continue
    
    # Prepare results data
    results_data = []
    for candidate in candidates:
        vote_count = candidate_votes.get(candidate['id'], 0)
        # Find region by name from candidate's region field
        region = next((r for r in regions if r['name'] == candidate.get('region')), {'name': candidate.get('region', 'Unknown')})
        
        results_data.append({
            'candidate': candidate,
            'vote_count': vote_count,
            'percentage': (vote_count / valid_votes * 100) if valid_votes > 0 else 0,
            'region': region
        })
    
    # Sort by vote count
    results_data.sort(key=lambda x: x['vote_count'], reverse=True)
    
    # Calculate regional results
    regional_results = {}
    for region in regions:
        region_candidates = [c for c in candidates if c.get('region') == region['name']]
        region_votes = {}
        total_region_votes = 0
        
        for candidate in region_candidates:
            votes_count = candidate_votes.get(candidate['id'], 0)
            region_votes[candidate['id']] = votes_count
            total_region_votes += votes_count
        
        regional_results[region['id']] = {
            'region': region,
            'total_votes': total_region_votes,
            'candidate_votes': region_votes
        }
    
    return render_template('admin/view_results.html', 
                         results_data=results_data,
                         regional_results=regional_results,
                         total_votes=valid_votes,
                         election_status=election_status)

@app.route('/admin/declare_winner')
@admin_required
def declare_winner():
    """Declare election winner"""
    votes = load_votes()
    candidates = load_candidates()
    election_status = load_election_status()
    
    if election_status.get('winner_declared', False):
        flash('Winner has already been declared', 'warning')
        return redirect(url_for('view_results'))
    
    if not votes:
        flash('Cannot declare winner - no votes have been cast', 'error')
        return redirect(url_for('view_results'))
    
    # Calculate vote counts by decrypting votes
    candidate_votes = {}
    valid_votes = 0
    for vote in votes:
        try:
            # Decrypt the vote to get candidate ID
            decrypted_vote = decrypt_vote(vote['encrypted_vote'])
            if decrypted_vote:
                candidate_id = int(decrypted_vote)
                candidate_votes[candidate_id] = candidate_votes.get(candidate_id, 0) + 1
                valid_votes += 1
        except (ValueError, KeyError) as e:
            # Skip invalid votes
            print(f"[WARNING] Invalid vote skipped in winner declaration: {e}")
            continue
    
    if not candidate_votes:
        flash('Cannot declare winner - no valid votes found', 'error')
        return redirect(url_for('view_results'))
    
    # Find winner
    winner_id = max(candidate_votes, key=candidate_votes.get)
    winner = next((c for c in candidates if c['id'] == winner_id), None)
    
    if not winner:
        flash('Error finding winner', 'error')
        return redirect(url_for('view_results'))
    
    # Update election status
    election_status.update({
        'election_completed': True,
        'winner_declared': True,
        'election_end_date': datetime.now().isoformat(),
        'total_votes_cast': valid_votes
    })
    
    # Create results record
    results = {
        'overall_winner': {
            'candidate_id': winner_id,
            'candidate_name': winner['name'],
            'party': winner['party'],
            'vote_count': candidate_votes[winner_id],
            'percentage': (candidate_votes[winner_id] / valid_votes * 100)
        },
        'vote_summary': {
            'total_votes': len(votes),
            'valid_votes': valid_votes,
            'invalid_votes': len(votes) - valid_votes
        },
        'candidate_results': [
            {
                'candidate_id': c['id'],
                'candidate_name': c['name'],
                'party': c['party'],
                'vote_count': candidate_votes.get(c['id'], 0),
                'percentage': (candidate_votes.get(c['id'], 0) / valid_votes * 100) if valid_votes > 0 else 0
            }
            for c in candidates
        ],
        'declared_at': datetime.now().isoformat(),
        'declared_by': session.get('username', 'admin')
    }
    
    # Save results and election status
    if save_election_status(election_status) and save_results(results):
        flash(f'Winner declared: {winner["name"]} from {winner["party"]} with {candidate_votes[winner_id]} votes!', 'success')
    else:
        flash('Failed to declare winner', 'error')
    
    return redirect(url_for('view_results'))

@app.route('/admin/restart_election', methods=['POST'])
@admin_required
def restart_election():
    """Restart election by clearing votes and resetting status"""
    try:
        # Reset votes
        votes = []
        if not save_votes(votes):
            flash('Failed to clear votes', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Reset election status
        election_status = {
            'status': 'active',
            'winner_declared': False,
            'total_voters': len(load_users()),
            'votes_cast': 0,
            'started_at': datetime.now().isoformat(),
            'restarted_at': datetime.now().isoformat(),
            'restarted_by': session.get('username', 'admin')
        }
        if not save_election_status(election_status):
            flash('Failed to reset election status', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Clear results
        results = {}
        if not save_results(results):
            flash('Failed to clear results', 'error')
            return redirect(url_for('admin_dashboard'))
        
        flash('Election restarted successfully! All votes have been cleared.', 'success')
        
    except Exception as e:
        flash(f'Failed to restart election: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ============ INITIALIZATION ============

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