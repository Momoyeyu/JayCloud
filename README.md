# JayCloud

JayCloud is a secure and efficient cloud storage prototype system that provides users with features such as instant file transmission, enhanced Proof of Work (PoW) mechanisms to prevent system abuse, and encrypted file deduplication for optimized storage utilization.

![logo](static/images/logo.webp)

## Features

1. **User Authentication Module**: 
   - Secure user registration, login, and logout.
   - Passwords are hashed before storage for enhanced security.
   - Implements CSRF protection to prevent cross-site request forgery attacks.

2. **Instant Transmission Module**:
   - Supports efficient file uploading using SHA-256 hashes for deduplication.
   - Avoids duplicate storage of identical files, saving server space.

3. **Enhanced PoW Mechanism**:
   - Prevents interface abuse by requiring computational work before file uploads.
   - Dynamically adjusts difficulty to balance security and usability.

4. **Encrypted File Deduplication**:
   - Uses convergent encryption for file security and deduplication.
   - Ensures privacy while optimizing storage by recognizing identical encrypted files.

## Technology Stack

- **Programming Language**: Python 3.8
- **Web Framework**: Flask
- **Database**: SQLite
- **Front-End**: HTML, CSS, JavaScript
- **Libraries Used**:
  - `Flask-Login`: User authentication management
  - `Flask-WTF`: CSRF protection
  - `Flask-Migrate`: Database migration
  - `PyCryptodome`: Encryption functionalities
  - `Werkzeug`: Password hashing and validation

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/jaycloud.git
   cd jaycloud
   ```

2. Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # For Linux/MacOS
   venv\Scripts\activate     # For Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up the database:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

5. Run the application:
   ```bash
   flask run
   ```

## How It Works

1. **User Registration and Login**:
   - Users create accounts and log in securely with hashed passwords.
   - CSRF tokens ensure that form submissions are safe.

2. **File Upload and Instant Transmission**:
   - Uploaded files are hashed using SHA-256.
   - If the file already exists, the server links it to the user without re-uploading the content.

3. **Enhanced PoW Mechanism**:
   - Before uploading, users perform Proof of Work (PoW) computations to validate upload requests.

4. **Encrypted File Deduplication**:
   - Files are encrypted using a hash of their content as the key (convergent encryption).
   - Identical files result in the same encrypted output, enabling deduplication.

## Future Improvements

- Implement a more sophisticated key management system for file decryption.
- Enhance the front-end user interface for better usability.
- Expand storage support to distributed systems.

## Contribution

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

Developed by **Momoyeyu** as part of the "Big Data Security" research experiment at Beijing University of Posts and Telecommunications.

