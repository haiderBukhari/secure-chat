# SecureChat - Secure Chat System

**Course**: CS-3002 Information Security, Fall 2025  
**Assignment**: #2  
**Institution**: FAST-NUCES

## 📖 Complete Documentation

**See [SETUP.md](SETUP.md) for complete setup, implementation details, and testing guide.**

## ⚡ Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start MySQL
docker run -d --name securechat-db -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_DATABASE=securechat -e MYSQL_USER=scuser -e MYSQL_PASSWORD=scpass -p 3306:3306 mysql:8

# 3. Generate certificates
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client

# 4. Initialize database
python -m app.storage.db --init

# 5. Verify setup
python verify_setup.py

# 6. Run application
# Terminal 1:
python -m app.server

# Terminal 2:
python -m app.client
```

## 📁 Project Structure

```
securechat-skeleton/
├── app/                    # Application code
│   ├── server.py          # Server implementation
│   ├── client.py          # Client implementation
│   ├── crypto/            # Cryptographic modules
│   ├── common/            # Protocol & utilities
│   └── storage/           # Database & transcripts
├── scripts/               # Certificate generation
├── certs/                 # Certificates (gitignored)
├── transcripts/           # Session logs (gitignored)
├── SETUP.md              # Complete documentation
├── setup.py              # Automated setup
├── verify_setup.py       # Setup verification
└── collect_evidence.py   # Evidence collection
```

## ✅ Implementation Status

- ✅ PKI Infrastructure (CA, certificates, validation)
- ✅ Secure Registration & Login (salted SHA-256, MySQL)
- ✅ Encrypted Communication (DH + AES-128)
- ✅ Message Integrity (RSA signatures)
- ✅ Replay Protection (sequence numbers)
- ✅ Non-Repudiation (transcripts + receipts)

## 🔒 Security Properties

- **Confidentiality**: AES-128 encryption
- **Integrity**: SHA-256 + RSA signatures
- **Authenticity**: Mutual certificate validation
- **Non-Repudiation**: Signed session transcripts

## 📚 Full Documentation

For complete details including:
- Assignment requirements
- Implementation details
- Testing procedures
- Troubleshooting guide
- Submission checklist

**Read [SETUP.md](SETUP.md)**

---

**GitHub Repository**: [Add your fork URL here]
