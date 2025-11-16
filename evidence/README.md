# SecureChat Evidence Collection

**Date**: 2025-11-16 19:51:40

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
