"""Verification script to check SecureChat setup."""
import os
import sys

def check_file(path, description):
    """Check if file exists."""
    if os.path.exists(path):
        print(f"[OK] {description}: {path}")
        return True
    else:
        print(f"[FAIL] {description} missing: {path}")
        return False

def check_module(module_name):
    """Check if Python module is installed."""
    try:
        __import__(module_name)
        print(f"[OK] Module installed: {module_name}")
        return True
    except ImportError:
        print(f"[FAIL] Module missing: {module_name}")
        return False

def main():
    print("=" * 60)
    print("SecureChat Setup Verification")
    print("=" * 60)
    
    all_good = True
    
    # Check Python version
    print("\n[*] Checking Python version...")
    if sys.version_info >= (3, 8):
        print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    else:
        print(f"[FAIL] Python 3.8+ required (found {sys.version_info.major}.{sys.version_info.minor})")
        all_good = False
    
    # Check required modules
    print("\n[*] Checking Python modules...")
    modules = ['cryptography', 'mysql.connector', 'pydantic', 'dotenv']
    for module in modules:
        if not check_module(module):
            all_good = False
    
    # Check directories
    print("\n[*] Checking directories...")
    dirs = ['app', 'scripts', 'certs', 'transcripts']
    for d in dirs:
        if not check_file(d, f"Directory"):
            all_good = False
    
    # Check core files
    print("\n[*] Checking core files...")
    files = [
        ('app/server.py', 'Server'),
        ('app/client.py', 'Client'),
        ('app/storage/db.py', 'Database layer'),
        ('app/crypto/aes.py', 'AES module'),
        ('app/crypto/dh.py', 'DH module'),
        ('app/crypto/pki.py', 'PKI module'),
        ('app/crypto/sign.py', 'Signature module'),
        ('scripts/gen_ca.py', 'CA generation script'),
        ('scripts/gen_cert.py', 'Certificate generation script'),
        ('requirements.txt', 'Requirements file'),
        ('.gitignore', 'Gitignore file'),
    ]
    for path, desc in files:
        if not check_file(path, desc):
            all_good = False
    
    # Check certificates
    print("\n[*] Checking certificates...")
    cert_files = [
        ('certs/ca.crt', 'Root CA certificate'),
        ('certs/ca.key', 'Root CA private key'),
        ('certs/server.crt', 'Server certificate'),
        ('certs/server.key', 'Server private key'),
        ('certs/client.crt', 'Client certificate'),
        ('certs/client.key', 'Client private key'),
    ]
    certs_exist = True
    for path, desc in cert_files:
        if not check_file(path, desc):
            certs_exist = False
    
    if not certs_exist:
        print("\n[!] Certificates not found. Run:")
        print("    python scripts/gen_ca.py --name 'FAST-NU Root CA'")
        print("    python scripts/gen_cert.py --cn server.local --out certs/server")
        print("    python scripts/gen_cert.py --cn client.local --out certs/client")
    
    # Check .env file
    print("\n[*] Checking configuration...")
    if os.path.exists('.env'):
        print("[OK] .env file exists")
    else:
        print("[!] .env file not found. Copy from .env.example:")
        print("    copy .env.example .env")
    
    # Check MySQL connection
    print("\n[*] Checking MySQL connection...")
    try:
        import mysql.connector
        from dotenv import load_dotenv
        load_dotenv()
        
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'scuser'),
            password=os.getenv('DB_PASSWORD', 'scpass'),
            database=os.getenv('DB_NAME', 'securechat')
        )
        conn.close()
        print("[OK] MySQL connection successful")
    except Exception as e:
        print(f"[FAIL] MySQL connection failed: {e}")
        print("\n[!] Start MySQL with:")
        print("    docker run -d --name securechat-db \\")
        print("      -e MYSQL_ROOT_PASSWORD=rootpass \\")
        print("      -e MYSQL_DATABASE=securechat \\")
        print("      -e MYSQL_USER=scuser \\")
        print("      -e MYSQL_PASSWORD=scpass \\")
        print("      -p 3306:3306 mysql:8")
        print("\n    Then initialize database:")
        print("    python -m app.storage.db --init")
        all_good = False
    
    # Summary
    print("\n" + "=" * 60)
    if all_good and certs_exist:
        print("[SUCCESS] Setup verification PASSED")
        print("\nYou can now run:")
        print("  Terminal 1: python -m app.server")
        print("  Terminal 2: python -m app.client")
    else:
        print("[WARNING] Setup verification INCOMPLETE")
        print("\nPlease address the issues above.")
    print("=" * 60)

if __name__ == "__main__":
    main()
