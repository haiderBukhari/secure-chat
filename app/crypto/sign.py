"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

def sign_data(private_key, data: bytes) -> bytes:
    """Sign data using RSA private key with SHA-256."""
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(cert_pem: str, data: bytes, signature: bytes) -> bool:
    """Verify RSA signature using certificate's public key."""
    try:
        cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
        public_key = cert.public_key()
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def load_private_key(key_path: str, password: bytes = None):
    """Load RSA private key from PEM file."""
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=password,
            backend=default_backend()
        )
