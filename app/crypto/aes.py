"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    padding_len = data[-1]
    return data[:-padding_len]

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-128 ECB mode with PKCS#7 padding."""
    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 ECB mode and remove PKCS#7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)
