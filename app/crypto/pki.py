"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timezone
import os

def load_cert(cert_pem: str):
    """Load X.509 certificate from PEM string."""
    return x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

def load_ca_cert(ca_path: str = "certs/ca.crt"):
    """Load CA certificate from file."""
    with open(ca_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def verify_cert_signature(cert, ca_cert) -> bool:
    """Verify that cert is signed by CA."""
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
            cert.signature_hash_algorithm
        )
        return True
    except Exception:
        return False

def check_validity(cert) -> bool:
    """Check if certificate is within validity period."""
    now = datetime.now(timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

def get_common_name(cert) -> str:
    """Extract Common Name from certificate."""
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except:
        return ""

def validate_certificate(cert_pem: str, expected_cn: str = None, ca_path: str = "certs/ca.crt") -> tuple[bool, str]:
    """
    Validate certificate:
    - Signed by trusted CA
    - Within validity period
    - CN matches expected (if provided)
    
    Returns: (is_valid, error_message)
    """
    try:
        cert = load_cert(cert_pem)
        
        # Check if CA cert exists
        if not os.path.exists(ca_path):
            return False, "CA certificate not found"
        
        ca_cert = load_ca_cert(ca_path)
        
        # Verify signature
        if not verify_cert_signature(cert, ca_cert):
            return False, "BAD_CERT: Invalid signature"
        
        # Check validity period
        if not check_validity(cert):
            return False, "BAD_CERT: Certificate expired or not yet valid"
        
        # Check CN if expected
        if expected_cn:
            cn = get_common_name(cert)
            if cn != expected_cn:
                return False, f"BAD_CERT: CN mismatch (expected {expected_cn}, got {cn})"
        
        return True, "OK"
    
    except Exception as e:
        return False, f"BAD_CERT: {str(e)}"
