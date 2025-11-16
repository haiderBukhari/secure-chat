"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import hashlib
import secrets

# Safe prime and generator (1536-bit MODP group from RFC 3526)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16
)
DH_G = 2

def generate_dh_keypair():
    """Generate DH private key and public value."""
    private = secrets.randbelow(DH_P - 2) + 1
    public = pow(DH_G, private, DH_P)
    return private, public

def compute_dh_shared(private: int, peer_public: int) -> int:
    """Compute shared secret from private key and peer's public value."""
    return pow(peer_public, private, DH_P)

def derive_aes_key(shared_secret: int) -> bytes:
    """Derive AES-128 key from DH shared secret: K = Trunc16(SHA256(big-endian(Ks)))."""
    # Convert shared secret to big-endian bytes
    byte_length = (shared_secret.bit_length() + 7) // 8
    ks_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash and truncate to 16 bytes
    hash_digest = hashlib.sha256(ks_bytes).digest()
    return hash_digest[:16]
