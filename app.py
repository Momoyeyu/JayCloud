from flask import Flask, render_template, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import hashlib
import secrets
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your actual secret key

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jaycloud.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

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
class File(db.Model):
    """Database model for uploaded files."""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))
    file_hash = db.Column(db.String(64), unique=True, nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<File {self.filename}>'

@app.route('/api/get_challenge', methods=['GET'])
def get_challenge():
    """
    API Endpoint: Get a new challenge for Proof of Work.
    Returns a JSON object containing the challenge.
    """
    challenge = generate_challenge()
    return jsonify({'challenge': challenge})

@app.route('/api/upload', methods=['POST'])
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
            # File already exists; update database if necessary
            existing_file = File.query.filter_by(file_hash=file_hash).first()
            if not existing_file:
                new_file = File(filename=uploaded_file.filename, file_hash=file_hash)
                db.session.add(new_file)
                db.session.commit()
            return jsonify({'status': 'success', 'message': 'File already exists. Fast upload successful!'})
        else:
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            # Add file metadata to the database
            new_file = File(filename=uploaded_file.filename, file_hash=file_hash)
            db.session.add(new_file)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'File uploaded and encrypted successfully!'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid file or file type'}), 400

@app.route('/files', methods=['GET'])
def list_files():
    """
    API Endpoint: List all uploaded files.
    Returns a JSON object containing file metadata.
    """
    files = File.query.order_by(File.upload_time.desc()).all()
    files_data = [{
        'filename': file.filename,
        'file_hash': file.file_hash,
        'upload_time': file.upload_time.strftime('%Y-%m-%d %H:%M:%S')
    } for file in files]
    return jsonify({'status': 'success', 'files': files_data})

@app.route('/', methods=['GET'])
def index():
    """Render the main page."""
    return render_template('index.html')

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
