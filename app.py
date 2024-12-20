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
import io

app = Flask(__name__)
app.secret_key = 'momoyeyu'  # Replace with your actual secret key

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

def convergent_encrypt(data, file_hash):
    """Encrypt the file using convergent encryption."""
    key = SHA256.new(file_hash.encode('utf-8')).digest()  # Key derived from file hash
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_data = iv + cipher.encrypt(data)
    return encrypted_data

def convergent_decrypt(encrypted_data, file_hash):
    """Decrypt the file using convergent encryption."""
    key = hashlib.sha256(file_hash.encode('utf-8')).digest()  # Key derived from file hash
    iv = encrypted_data[:AES.block_size]  # Extract IV
    encrypted_content = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(encrypted_content)
    return decrypted_data

# Database models
class User(UserMixin, db.Model):
    """Database model for users."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)  # 用户名
    password = db.Column(db.String(150), nullable=False)  # 密码
    files = db.relationship('File', backref='owner', lazy=True)  # 关联文件

class File(db.Model):
    """Database model for uploaded files."""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))  # 文件名
    file_hash = db.Column(db.String(64), nullable=False)  # 文件哈希
    merkle_root = db.Column(db.String(64), nullable=False)  # Merkle树根哈希
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)  # 上传时间
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 所属用户

    def __repr__(self):
        return f'<File {self.filename}>'

def compute_merkle_root(data, chunk_size=1024):
    """
    Compute the Merkle Root of the file data.
    Splits the data into chunks of `chunk_size` bytes, hashes each chunk, and builds the Merkle Tree.
    Returns the Merkle Root as a hex string.
    """
    def hash_chunk(chunk):
        return hashlib.sha256(chunk).hexdigest()

    def build_merkle_tree(hashes):
        if len(hashes) == 1:
            return hashes
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])  # 复制最后一个哈希以保证数量为偶数
        new_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            new_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
            new_level.append(new_hash)
        return build_merkle_tree(new_level)

    # 将数据分割为多个块
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    # 对每个块进行哈希
    chunk_hashes = [hash_chunk(chunk) for chunk in chunks]
    # 构建Merkle Tree并获取根哈希
    merkle_root = build_merkle_tree(chunk_hashes)[0] if chunk_hashes else None
    return merkle_root

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        username = request.form['username']  # 获取用户名
        password = request.form['password']  # 获取密码
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()  # 检查用户是否存在
        if existing_user:
            flash('Username already exists. Please choose a different one.')  # 提示用户名已存在
            return redirect(url_for('register'))
        # Create new user
        hashed_password = generate_password_hash(password)  # 哈希密码
        new_user = User(username=username, password=hashed_password)  # 创建新用户
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')  # 提示注册成功
        return redirect(url_for('login'))
    return render_template('register.html')  # 渲染注册页面

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        username = request.form['username']  # 获取用户名
        password = request.form['password']  # 获取密码
        # Authenticate user
        user = User.query.filter_by(username=username).first()  # 查询用户
        if user and check_password_hash(user.password, password):  # 验证密码
            login_user(user)  # 登录用户
            flash('Login successful!')  # 提示登录成功
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')  # 提示登录失败
            return redirect(url_for('login'))
    return render_template('login.html')  # 渲染登录页面

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """User logout."""
    logout_user()  # 注销用户
    flash('You have been logged out.')  # 提示注销成功
    return redirect(url_for('index'))

@app.route('/api/get_challenge', methods=['GET'])
@login_required
def get_challenge_endpoint():
    """API Endpoint: Get a new challenge for Proof of Work."""
    challenge = generate_challenge()
    return jsonify({'challenge': challenge})

@app.route('/api/check_file', methods=['POST'])
@login_required
def check_file():
    """API Endpoint: Check if a file with the given hash exists."""
    data = request.get_json()
    file_hash = data.get('file_hash')
    filename = data.get('filename')
    if not file_hash or not filename:
        return jsonify({'status': 'error', 'message': 'Missing file hash or filename.'}), 400
    # Check if the file exists on the server
    file_path = os.path.join(UPLOAD_FOLDER, file_hash)
    if os.path.exists(file_path):
        # Check if the user already has this file
        existing_file = File.query.filter_by(file_hash=file_hash, user_id=current_user.id).first()
        if existing_file:
            return jsonify({'status': 'exists', 'message': 'File already exists in your account.'})
        else:
            # Associate the file with the user
            new_file = File(filename=filename, file_hash=file_hash, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            return jsonify({'status': 'associated', 'message': 'File associated with your account.'})
    else:
        return jsonify({'status': 'not_exists', 'message': 'File does not exist on the server.'})

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file uploads with Proof of Ownership via Merkle Tree."""
    # nonce = request.form.get('nonce')
    # challenge = session.get('challenge')
    # if not challenge or not nonce or not verify_pow(challenge, nonce):
    #     return jsonify({'status': 'error', 'message': 'PoW verification failed'}), 400
    # session.pop('challenge', None)
    uploaded_file = request.files.get('file')
    file_hash = request.form.get('file_hash')
    if not file_hash or not uploaded_file:
        return jsonify({'status': 'error', 'message': 'Missing file hash or file.'}), 400
    if uploaded_file and allowed_file(uploaded_file.filename):
        # Read raw file data
        file_data = uploaded_file.read()
        server_file_hash = hashlib.sha256(file_data).hexdigest()
        if server_file_hash != file_hash:
            return jsonify({'status': 'error', 'message': 'File hash mismatch.'}), 400
        # 计算Merkle Root
        merkle_root = compute_merkle_root(file_data)
        if not merkle_root:
            return jsonify({'status': 'error', 'message': 'Failed to compute Merkle Root.'}), 400
        # Encrypt the file data using the file hash as the key
        encrypted_data = convergent_encrypt(file_data, file_hash)
        file_path = os.path.join(UPLOAD_FOLDER, file_hash)
        if not os.path.exists(file_path):
            # Save the encrypted file
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
        # Add file metadata to the database
        new_file = File(filename=uploaded_file.filename, file_hash=file_hash, merkle_root=merkle_root, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'File uploaded and encrypted successfully!', 'merkle_root': merkle_root}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid file or file type'}), 400

@app.route('/files', methods=['GET'])
@login_required
def list_files():
    """API Endpoint: List all uploaded files for the current user."""
    files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_time.desc()).all()
    files_data = [{
        'id': file.id,
        'filename': file.filename,
        'file_hash': file.file_hash,
        'merkle_root': file.merkle_root,
        'upload_time': file.upload_time.isoformat() + 'Z'  # ISO format with 'Z' to indicate UTC
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
            # Read encrypted data
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            # Decrypt the data using the file hash
            decrypted_data = convergent_decrypt(encrypted_data, file.file_hash)
            # Send the decrypted file to the client
            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=file.filename
            )
        else:
            abort(404)
    else:
        abort(403)  # Forbidden


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
