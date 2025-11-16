"""Client skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import os
import hashlib
import threading
from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import *
from app.crypto.dh import *
from app.crypto.pki import *
from app.crypto.sign import *
from app.storage.transcript import *

class SecureChatClient:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.cert_path = "certs/client.crt"
        self.key_path = "certs/client.key"
        self.client_cert_pem = None
        self.private_key = None
        self.server_cert_pem = None
        self.session_key = None
        self.seqno = 0
        self.server_seqno = 0
        self.transcript = None
        self.sock = None
        
    def load_credentials(self):
        """Load client certificate and private key."""
        with open(self.cert_path, 'r') as f:
            self.client_cert_pem = f.read()
        self.private_key = load_private_key(self.key_path)
        print(f"✓ Loaded client credentials")
    
    def connect(self):
        """Connect to server and perform handshake."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[+] Connected to server {self.host}:{self.port}")
        
        # Phase 1: Certificate Exchange
        hello = HelloMsg(
            client_cert=self.client_cert_pem,
            nonce=b64e(os.urandom(16))
        )
        self.sock.send(hello.model_dump_json().encode())
        print(f"[>] Sent hello to server")
        
        # Receive server hello
        data = self.sock.recv(8192).decode()
        server_hello = ServerHelloMsg.model_validate_json(data)
        print(f"[<] Received server hello")
        
        # Validate server certificate
        valid, error = validate_certificate(server_hello.server_cert, expected_cn="server.local")
        if not valid:
            print(f"[!] {error}")
            return False
        
        self.server_cert_pem = server_hello.server_cert
        print(f"[✓] Server certificate validated")
        
        return True
    
    def perform_dh_exchange(self):
        """Perform DH key exchange."""
        # Generate DH keypair
        dh_private, dh_public = generate_dh_keypair()
        
        # Send DH parameters
        dh_client = DHClientMsg(
            g=DH_G,
            p=DH_P,
            A=dh_public
        )
        self.sock.send(dh_client.model_dump_json().encode())
        print(f"[>] Sent DH parameters")
        
        # Receive server DH response
        data = self.sock.recv(8192).decode()
        dh_server = DHServerMsg.model_validate_json(data)
        print(f"[<] Received DH response")
        
        # Compute shared secret and derive key
        shared_secret = compute_dh_shared(dh_private, dh_server.B)
        key = derive_aes_key(shared_secret)
        
        return key
    
    def register(self, email: str, username: str, password: str):
        """Register new user."""
        # Perform initial DH for registration
        temp_key = self.perform_dh_exchange()
        print(f"[✓] Temporary key established")
        
        # Generate salt and hash password
        salt = os.urandom(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        
        # Prepare registration data
        reg_data = {
            'email': email,
            'username': username,
            'pwd': pwd_hash,
            'salt': b64e(salt)
        }
        
        # Encrypt registration data
        plaintext = json.dumps(reg_data).encode()
        ct = aes_encrypt(temp_key, plaintext)
        
        # Send registration message
        msg = {
            'type': 'register',
            'ct': b64e(ct)
        }
        self.sock.send(json.dumps(msg).encode())
        print(f"[>] Sent registration request")
        
        # Receive response
        data = self.sock.recv(8192).decode()
        response = json.loads(data)
        
        if response['success']:
            print(f"[✓] {response['message']}")
            return True
        else:
            print(f"[!] {response['message']}")
            return False
    
    def login(self, email: str, password: str):
        """Login existing user."""
        # Perform initial DH for login
        temp_key = self.perform_dh_exchange()
        print(f"[✓] Temporary key established")
        
        # Get user's salt from database (in real scenario, server would provide this)
        # For now, we'll compute hash with a retrieved salt
        # Simplified: hash password directly for demo
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Prepare login data
        login_data = {
            'email': email,
            'pwd': pwd_hash,
            'nonce': b64e(os.urandom(16))
        }
        
        # Encrypt login data
        plaintext = json.dumps(login_data).encode()
        ct = aes_encrypt(temp_key, plaintext)
        
        # Send login message
        msg = {
            'type': 'login',
            'ct': b64e(ct)
        }
        self.sock.send(json.dumps(msg).encode())
        print(f"[>] Sent login request")
        
        # Receive response
        data = self.sock.recv(8192).decode()
        response = json.loads(data)
        
        if response['success']:
            print(f"[✓] {response['message']}")
            return True
        else:
            print(f"[!] {response['message']}")
            return False

    def establish_session(self):
        """Establish session key for chat."""
        self.session_key = self.perform_dh_exchange()
        print(f"[✓] Session key established")
        
        # Initialize transcript
        self.transcript = Transcript(f"transcripts/client_{self.host}_{self.port}.txt")
    
    def chat(self):
        """Start encrypted chat session."""
        print("\n[*] Chat session started. Type messages to send (or 'quit' to exit)")
        
        def receive_messages():
            while True:
                try:
                    data = self.sock.recv(8192).decode()
                    if not data:
                        break
                    
                    msg = ChatMsg.model_validate_json(data)
                    
                    # Verify sequence number
                    if msg.seqno <= self.server_seqno:
                        print(f"[!] REPLAY: Invalid sequence number")
                        continue
                    self.server_seqno = msg.seqno
                    
                    # Verify signature
                    digest_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode()
                    sig = b64d(msg.sig)
                    if not verify_signature(self.server_cert_pem, digest_data, sig):
                        print(f"[!] SIG_FAIL: Invalid signature")
                        continue
                    
                    # Decrypt message
                    ct = b64d(msg.ct)
                    plaintext = aes_decrypt(self.session_key, ct)
                    
                    # Log to transcript
                    peer_fp = get_cert_fingerprint(self.server_cert_pem)
                    self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, peer_fp)
                    
                    print(f"\n[Server]: {plaintext.decode()}")
                    print("[You]: ", end='', flush=True)
                    
                except Exception as e:
                    print(f"\n[!] Receive error: {e}")
                    break
        
        # Start receive thread
        recv_thread = threading.Thread(target=receive_messages, daemon=True)
        recv_thread.start()
        
        # Send messages
        while True:
            try:
                message = input("[You]: ")
                if message.lower() == 'quit':
                    # Generate session receipt
                    self.generate_receipt()
                    break
                
                # Encrypt message
                ct = aes_encrypt(self.session_key, message.encode())
                self.seqno += 1
                ts = now_ms()
                
                # Sign message
                digest_data = f"{self.seqno}{ts}{b64e(ct)}".encode()
                sig = sign_data(self.private_key, digest_data)
                
                # Send message
                chat_msg = ChatMsg(
                    seqno=self.seqno,
                    ts=ts,
                    ct=b64e(ct),
                    sig=b64e(sig)
                )
                self.sock.send(chat_msg.model_dump_json().encode())
                
                # Log to transcript
                peer_fp = get_cert_fingerprint(self.server_cert_pem)
                self.transcript.append(self.seqno, ts, b64e(ct), b64e(sig), peer_fp)
                
            except Exception as e:
                print(f"[!] Send error: {e}")
                break
    
    def generate_receipt(self):
        """Generate session receipt."""
        try:
            transcript_hash = self.transcript.compute_hash()
            first_seq, last_seq = self.transcript.get_sequence_range()
            
            # Sign transcript hash
            sig = sign_data(self.private_key, transcript_hash.encode())
            
            receipt = ReceiptMsg(
                peer="client",
                first_seq=first_seq,
                last_seq=last_seq,
                transcript_sha256=transcript_hash,
                sig=b64e(sig)
            )
            
            # Save receipt
            receipt_path = self.transcript.filepath.replace('.txt', '_receipt.json')
            with open(receipt_path, 'w') as f:
                f.write(receipt.model_dump_json(indent=2))
            
            print(f"\n[✓] Session receipt saved: {receipt_path}")
            
        except Exception as e:
            print(f"[!] Receipt generation error: {e}")
    
    def close(self):
        """Close connection."""
        if self.sock:
            self.sock.close()
            print("[*] Connection closed")

def main():
    client = SecureChatClient()
    
    try:
        client.load_credentials()
        
        if not client.connect():
            return
        
        # Interactive menu
        print("\n=== SecureChat Client ===")
        print("1. Register")
        print("2. Login")
        choice = input("Choose option: ")
        
        if choice == '1':
            email = input("Email: ")
            username = input("Username: ")
            password = input("Password: ")
            
            if not client.register(email, username, password):
                return
        
        elif choice == '2':
            email = input("Email: ")
            password = input("Password: ")
            
            if not client.login(email, password):
                return
        else:
            print("[!] Invalid choice")
            return
        
        # Establish session and start chat
        client.establish_session()
        client.chat()
        
    except KeyboardInterrupt:
        print("\n[*] Client shutting down")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()

if __name__ == "__main__":
    main()
