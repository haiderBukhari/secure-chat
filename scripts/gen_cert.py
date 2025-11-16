"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import argparse
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def load_ca(ca_dir: str = "certs"):
    """Load CA certificate and private key."""
    ca_cert_path = os.path.join(ca_dir, "ca.crt")
    ca_key_path = os.path.join(ca_dir, "ca.key")
    
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key

def generate_cert(cn: str, output_prefix: str, ca_dir: str = "certs"):
    """Generate certificate signed by CA."""
    
    # Load CA
    ca_cert, ca_key = load_ca(ca_dir)
    
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)  # 1 year
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(cn)]),
        critical=False,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Write private key
    key_path = f"{output_prefix}.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate
    cert_path = f"{output_prefix}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"[OK] Certificate generated:")
    print(f"  Private Key: {key_path}")
    print(f"  Certificate: {cert_path}")
    print(f"  Common Name: {cn}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate certificate signed by CA")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., server.local)")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    parser.add_argument("--ca-dir", default="certs", help="CA directory")
    args = parser.parse_args()
    
    generate_cert(args.cn, args.out, args.ca_dir)
