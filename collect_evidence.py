"""Evidence collection helper script for SecureChat assignment."""
import os
import shutil
import subprocess
from datetime import datetime

def create_evidence_structure():
    """Create evidence directory structure."""
    dirs = [
        'evidence',
        'evidence/wireshark',
        'evidence/screenshots',
        'evidence/transcripts',
        'evidence/database',
        'evidence/certificates'
    ]
    
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"[OK] Created: {d}")

def collect_database_evidence():
    """Collect database schema and sample records."""
    print("\n[*] Collecting database evidence...")
    
    try:
        # Export schema
        print("    Exporting schema...")
        subprocess.run(
            'mysqldump -u scuser -pscpass securechat > evidence/database/schema.sql',
            shell=True, check=True
        )
        print("    [OK] Schema exported")
        
        # Export user records
        print("    Exporting user records...")
        subprocess.run(
            'mysql -u scuser -pscpass securechat -e "SELECT email, username, HEX(salt), pwd_hash, created_at FROM users;" > evidence/database/users.txt',
            shell=True, check=True
        )
        print("    [OK] User records exported")
        
    except Exception as e:
        print(f"    [!] Database export failed: {e}")
        print("    Make sure MySQL is running and credentials are correct")

def collect_transcripts():
    """Copy transcript files to evidence folder."""
    print("\n[*] Collecting transcripts...")
    
    if not os.path.exists('transcripts'):
        print("    [!] No transcripts directory found")
        return
    
    files = os.listdir('transcripts')
    if not files:
        print("    [!] No transcript files found")
        print("    Run a chat session first to generate transcripts")
        return
    
    for f in files:
        src = os.path.join('transcripts', f)
        dst = os.path.join('evidence/transcripts', f)
        shutil.copy2(src, dst)
        print(f"    [OK] Copied: {f}")

def collect_certificates():
    """Copy certificate information to evidence folder."""
    print("\n[*] Collecting certificate information...")
    
    certs = ['ca.crt', 'server.crt', 'client.crt']
    
    for cert in certs:
        cert_path = os.path.join('certs', cert)
        if os.path.exists(cert_path):
            # Copy certificate
            dst = os.path.join('evidence/certificates', cert)
            shutil.copy2(cert_path, dst)
            
            # Generate text info
            info_file = os.path.join('evidence/certificates', f'{cert}.txt')
            try:
                result = subprocess.run(
                    f'openssl x509 -in {cert_path} -text -noout',
                    shell=True, capture_output=True, text=True
                )
                with open(info_file, 'w') as f:
                    f.write(result.stdout)
                print(f"    [OK] Collected: {cert}")
            except:
                print(f"    [!] Could not extract info from {cert} (openssl not found)")
        else:
            print(f"    [!] Certificate not found: {cert}")

def create_readme():
    """Create README for evidence folder."""
    print("\n[*] Creating evidence README...")
    
    readme_content = f"""# SecureChat Evidence Collection

**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Directory Structure

- `wireshark/` - Network capture files (.pcapng)
- `screenshots/` - Test evidence screenshots
- `transcripts/` - Session transcript files
- `database/` - Database schema and records
- `certificates/` - Certificate information

## Wireshark Captures

Place your Wireshark capture files here:
- `registration.pcapng` - User registration capture
- `login.pcapng` - User login capture
- `chat.pcapng` - Chat session capture

**Display Filters Used**:
```
tcp.port == 9999
tcp.port == 9999 && tcp.len > 0
```

## Screenshots

Recommended screenshots:
1. `01_valid_cert.png` - Valid certificate acceptance
2. `02_invalid_cert.png` - Invalid certificate rejection (BAD_CERT)
3. `03_registration.png` - User registration
4. `04_database_record.png` - Database user record
5. `05_login_success.png` - Successful login
6. `06_login_failure.png` - Failed login
7. `07_chat_session.png` - Chat session
8. `08_tamper_detection.png` - Tamper detection (SIG_FAIL)
9. `09_replay_protection.png` - Replay protection (REPLAY)
10. `10_transcript.png` - Transcript file
11. `11_receipt.png` - Session receipt
12. `12_verification.png` - Offline verification

## Database Evidence

- `schema.sql` - Complete database schema
- `users.txt` - Sample user records

## Transcripts

- Session transcript files (`.txt`)
- Session receipt files (`_receipt.json`)

## Certificates

- Certificate files (`.crt`)
- Certificate details (`.txt`)

## Notes

- All evidence collected automatically where possible
- Manual steps required for Wireshark captures and screenshots
- Refer to TESTING.md for detailed test procedures
"""
    
    with open('evidence/README.md', 'w') as f:
        f.write(readme_content)
    
    print("    [OK] README created")

def main():
    print("=" * 60)
    print("SecureChat Evidence Collection")
    print("=" * 60)
    
    # Create structure
    create_evidence_structure()
    
    # Collect evidence
    collect_database_evidence()
    collect_transcripts()
    collect_certificates()
    create_readme()
    
    print("\n" + "=" * 60)
    print("Evidence Collection Complete")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run Wireshark captures and save to evidence/wireshark/")
    print("2. Take screenshots and save to evidence/screenshots/")
    print("3. Review evidence/README.md for complete checklist")
    print("4. Refer to TESTING.md for test procedures")
    print("\nEvidence folder: ./evidence/")

if __name__ == "__main__":
    main()
