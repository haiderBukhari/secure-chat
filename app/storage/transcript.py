"""Append-only transcript + TranscriptHash helpers."""
import hashlib
import os
from datetime import datetime

class Transcript:
    """Append-only transcript for non-repudiation."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.lines = []
        
        # Create directory if needed
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Create file if it doesn't exist
        if not os.path.exists(filepath):
            open(filepath, 'w').close()
    
    def append(self, seqno: int, timestamp: int, ciphertext: str, signature: str, peer_cert_fingerprint: str):
        """Append a message record to transcript."""
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}\n"
        self.lines.append(line)
        
        # Write to file immediately
        with open(self.filepath, 'a') as f:
            f.write(line)
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of entire transcript."""
        content = ''.join(self.lines)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get_sequence_range(self) -> tuple[int, int]:
        """Get first and last sequence numbers."""
        if not self.lines:
            return 0, 0
        
        first_seq = int(self.lines[0].split('|')[0])
        last_seq = int(self.lines[-1].split('|')[0])
        return first_seq, last_seq
    
    def load_from_file(self):
        """Load existing transcript from file."""
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                self.lines = f.readlines()

def verify_transcript(transcript_path: str, expected_hash: str) -> bool:
    """Verify transcript integrity by comparing hash."""
    t = Transcript(transcript_path)
    t.load_from_file()
    computed_hash = t.compute_hash()
    return computed_hash == expected_hash

def get_cert_fingerprint(cert_pem: str) -> str:
    """Compute SHA-256 fingerprint of certificate."""
    return hashlib.sha256(cert_pem.encode()).hexdigest()[:16]
