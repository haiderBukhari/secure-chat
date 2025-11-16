import mysql.connector
import hashlib
import os
import argparse

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'scuser'),
    'password': os.getenv('DB_PASSWORD', 'scpass'),
    'database': os.getenv('DB_NAME', 'securechat')
}

def get_connection():
    """Get MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)

def init_db():
    """Initialize database tables."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(255) NOT NULL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        salt BINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    cursor.close()
    conn.close()
    print("DB Initialized: users table created")

def hash_password(password: str, salt: bytes) -> str:
    """Hash password with salt using SHA-256."""
    return hashlib.sha256((salt + password.encode())).hexdigest()

def create_user(email: str, username: str, pwd_hash: str, salt: bytes = None) -> bool:
    """Create new user with salted password hash."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Generate random 16-byte salt if not provided
    if salt is None:
        salt = os.urandom(16)
    
    try:
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except mysql.connector.IntegrityError:
        cursor.close()
        conn.close()
        return False

def get_user(username: str):
    """Retrieve user by username."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def get_user_by_email(email: str):
    """Retrieve user by email."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def verify_user(username: str, password: str) -> bool:
    """Verify user credentials."""
    user = get_user(username)
    if not user:
        return False
    
    # Recompute hash with stored salt
    computed_hash = hash_password(password, bytes(user['salt']))
    
    # Constant-time comparison
    return computed_hash == user['pwd_hash']

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--init', action='store_true', help='Initialize DB tables')
    args = parser.parse_args()

    if args.init:
        init_db()
    else:
        print("Usage: python -m app.storage.db --init")
