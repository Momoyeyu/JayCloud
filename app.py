from flask import Flask, render_template, request, session, jsonify, redirect, url_for, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf.csrf import CSRFProtect
import os
import hashlib
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your actual secret key

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jaycloud.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp',
    'c', 'cpp', 'py', 'rb', 'go', 'kt', 'java', 'js', 'html', 'css',
    'php', 'cs', 'swift', 'rs', 'ts', 'sh', 'bat'
}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_hash(file_stream):
    """Calculate SHA-256 hash of the file content."""
    hasher = hashlib.sha256()
    for chunk in iter(lambda: file_stream.read(4096), b""):
        hasher.update(chunk)
    file_stream.seek(0)  # Reset file stream position
    return hasher.hexdigest()

def generate_challenge():
    """Generate a new challenge for Proof of Work."""
    challenge = secrets.token_hex(16)
    session['challenge'] = challenge
    return challenge

def verify_pow(challenge, nonce, difficulty=4):
    """Verify the Proof of Work submitted by the client."""
    combined = (challenge + nonce).encode('utf-8')
    hash_result = hashlib.sha256(combined).hexdigest()
    return hash_result.startswith('0' * difficulty)

def convergent_encrypt(file_stream):
    """Encrypt the file using convergent encryption."""
    data = file_stream.read()
    key = SHA256.new(data).digest()  # Key derived from file content
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_data = iv + cipher.encrypt(data)
    file_stream.seek(0)  # Reset file stream position
    return encrypted_data

# Database models
class User(UserMixin, db.Model):
    """Database model for users."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    """Database model for uploaded files."""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))
    file_hash = db.Column(db.String(64), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<File {self.filename}>'

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Authenticate user
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """User logout."""
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@csrf.exempt
@app.route('/api/get_challenge', methods=['GET'])
@login_required
def get_challenge():
    """
    API Endpoint: Get a new challenge for Proof of Work.
    Returns a JSON object containing the challenge.
    """
    challenge = generate_challenge()
    return jsonify({'challenge': challenge})

@csrf.exempt
@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """
    API Endpoint: Handle file uploads.
    Expects 'file' in form-data and 'nonce' in form-data.
    Performs Proof of Work verification and encrypted deduplication.
    """
    nonce = request.form.get('nonce')
    challenge = session.get('challenge')
    if not challenge or not nonce or not verify_pow(challenge, nonce):
        return jsonify({'status': 'error', 'message': 'PoW verification failed'}), 400
    # Clear the used challenge
    session.pop('challenge', None)
    uploaded_file = request.files.get('file')
    if uploaded_file and allowed_file(uploaded_file.filename):
        encrypted_data = convergent_encrypt(uploaded_file.stream)
        file_hash = hashlib.sha256(encrypted_data).hexdigest()
        file_path = os.path.join(UPLOAD_FOLDER, file_hash)
        if os.path.exists(file_path):
            # File already exists; check if user has uploaded it before
            existing_file = File.query.filter_by(file_hash=file_hash, user_id=current_user.id).first()
            if existing_file:
                return jsonify({'status': 'success', 'message': 'File already exists in your account. Fast upload successful!'})
            else:
                # Associate existing file with user
                new_file = File(filename=uploaded_file.filename, file_hash=file_hash, user_id=current_user.id)
                db.session.add(new_file)
                db.session.commit()
                return jsonify({'status': 'success', 'message': 'File uploaded and associated with your account!'})
        else:
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            # Add file metadata to the database
            new_file = File(filename=uploaded_file.filename, file_hash=file_hash, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'File uploaded and encrypted successfully!'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid file or file type'}), 400

@app.route('/files', methods=['GET'])
@login_required
def list_files():
    """
    API Endpoint: List all uploaded files for the current user.
    Returns a JSON object containing file metadata.
    """
    files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_time.desc()).all()
    files_data = [{
        'id': file.id,
        'filename': file.filename,
        'file_hash': file.file_hash,
        'upload_time': file.upload_time.strftime('%Y-%m-%d %H:%M:%S')
    } for file in files]
    return jsonify({'status': 'success', 'files': files_data})

@app.route('/download/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    """Allow users to download their files."""
    file = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    if file:
        file_path = os.path.join(UPLOAD_FOLDER, file.file_hash)
        if os.path.exists(file_path):
            # Decryption logic can be added here if necessary
            return send_file(file_path, as_attachment=True, download_name=file.filename)
        else:
            abort(404)
    else:
        abort(403)  # Forbidden

@csrf.exempt
@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Allow users to delete their files."""
    file = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    if file:
        file_path = os.path.join(UPLOAD_FOLDER, file.file_hash)
        # Remove the file record from the database
        db.session.delete(file)
        db.session.commit()
        # Check if other users are using the same file
        other_users_with_file = File.query.filter_by(file_hash=file.file_hash).count()
        if other_users_with_file == 0:
            # No other users have this file, so we can delete it from storage
            if os.path.exists(file_path):
                os.remove(file_path)
        return jsonify({'status': 'success', 'message': 'File deleted successfully!'})
    else:
        return jsonify({'status': 'error', 'message': 'File not found or access denied.'}), 403

@app.route('/', methods=['GET'])
def index():
    """Render the home page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Render the main dashboard page."""
    return render_template('index.html')

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
