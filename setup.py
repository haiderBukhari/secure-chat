"""Setup script for SecureChat system."""
import os
import sys
import subprocess

def run_command(cmd, description):
    """Run a command and print status."""
    print(f"\n[*] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"[OK] {description} - Success")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] {description} - Failed")
        if e.stderr:
            print(e.stderr)
        return False

def main():
    print("=" * 60)
    print("SecureChat System Setup")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("[!] Python 3.8+ required")
        return
    
    print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}")
    
    # Create directories
    print("\n[*] Creating directories...")
    os.makedirs("certs", exist_ok=True)
    os.makedirs("transcripts", exist_ok=True)
    print("[OK] Directories created")
    
    # Install dependencies
    if not run_command("pip install -r requirements.txt", "Installing dependencies"):
        return
    
    # Copy .env if needed
    if not os.path.exists(".env"):
        if os.path.exists(".env.example"):
            print("\n[*] Creating .env file...")
            with open(".env.example", "r") as src:
                with open(".env", "w") as dst:
                    dst.write(src.read())
            print("[OK] .env file created")
    
    # Generate CA
    if not os.path.exists("certs/ca.crt"):
        if not run_command('python scripts/gen_ca.py --name "FAST-NU Root CA"', "Generating Root CA"):
            return
    else:
        print("\n[OK] Root CA already exists")
    
    # Generate server certificate
    if not os.path.exists("certs/server.crt"):
        if not run_command('python scripts/gen_cert.py --cn server.local --out certs/server', "Generating server certificate"):
            return
    else:
        print("\n[OK] Server certificate already exists")
    
    # Generate client certificate
    if not os.path.exists("certs/client.crt"):
        if not run_command('python scripts/gen_cert.py --cn client.local --out certs/client', "Generating client certificate"):
            return
    else:
        print("\n[OK] Client certificate already exists")
    
    # Initialize database
    print("\n[*] Database initialization...")
    print("    Make sure MySQL is running with the following configuration:")
    print("    - Host: localhost")
    print("    - User: scuser")
    print("    - Password: scpass")
    print("    - Database: securechat")
    print("\n    Run: python -m app.storage.db --init")
    
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Ensure MySQL is running")
    print("2. Initialize database: python -m app.storage.db --init")
    print("3. Start server: python -m app.server")
    print("4. Start client: python -m app.client")
    print("\nFor Docker MySQL:")
    print('docker run -d --name securechat-db \\')
    print('  -e MYSQL_ROOT_PASSWORD=rootpass \\')
    print('  -e MYSQL_DATABASE=securechat \\')
    print('  -e MYSQL_USER=scuser \\')
    print('  -e MYSQL_PASSWORD=scpass \\')
    print('  -p 3306:3306 mysql:8')

if __name__ == "__main__":
    main()
