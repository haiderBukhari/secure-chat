"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import os
import sys
from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import *
from app.crypto.dh import *
from app.crypto.pki import *
from app.crypto.sign import *
from app.storage.db import *
from app.storage.transcript import *

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.cert_path = "certs/server.crt"
        self.key_path = "certs/server.key"
        self.server_cert_pem = None
        self.private_key = None
        self.session_key = None
        self.client_cert_pem = None
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = None
        
    def load_credentials(self):
        """Load server certificate and private key."""
        with open(self.cert_path, 'r') as f:
            self.server_cert_pem = f.read()
        self.private_key = load_private_key(self.key_path)
        print(f"✓ Loaded server credentials")
    
    def handle_client(self, conn, addr):
        """Handle client connection."""
        print(f"\n[+] Client connected: {addr}")
        
        try:
            # Phase 1: Certificate Exchange
            data = conn.recv(8192).decode()
            hello_msg = HelloMsg.model_validate_json(data)
            print(f"[<] Received hello from client")
            
            # Validate client certificate
            valid, error = validate_certificate(hello_msg.client_cert)
            if not valid:
                print(f"[!] {error}")
                conn.send(json.dumps({"type": "status", "success": False, "message": error}).encode())
                return
            
            self.client_cert_pem = hello_msg.client_cert
            print(f"[✓] Client certificate validated")
            
            # Send server hello
            server_hello = ServerHelloMsg(
                server_cert=self.server_cert_pem,
                nonce=b64e(os.urandom(16))
            )
            conn.send(server_hello.model_dump_json().encode())
            print(f"[>] Sent server hello")
            
            # Phase 2: Initial DH for registration/login
            data = conn.recv(8192).decode()
            dh_client = DHClientMsg.model_validate_json(data)
            print(f"[<] Received DH parameters from client")
            
            # Generate server DH keypair
            dh_private, dh_public = generate_dh_keypair()
            shared_secret = compute_dh_shared(dh_private, dh_client.A)
            temp_key = derive_aes_key(shared_secret)
            
            # Send DH response
            dh_server = DHServerMsg(B=dh_public)
            conn.send(dh_server.model_dump_json().encode())
            print(f"[>] Sent DH response, temp key established")
            
            # Phase 3: Registration or Login
            data = conn.recv(8192).decode()
            msg = json.loads(data)
            
            if msg['type'] == 'register':
                self.handle_registration(conn, msg, temp_key)
            elif msg['type'] == 'login':
                authenticated = self.handle_login(conn, msg, temp_key)
                if not authenticated:
                    return
            else:
                conn.send(json.dumps({"type": "status", "success": False, "message": "Unknown message type"}).encode())
                return
            
            # Phase 4: Session DH for chat
            data = conn.recv(8192).decode()
            dh_client = DHClientMsg.model_validate_json(data)
            print(f"[<] Received session DH from client")
            
            dh_private, dh_public = generate_dh_keypair()
            shared_secret = compute_dh_shared(dh_private, dh_client.A)
            self.session_key = derive_aes_key(shared_secret)
            
            dh_server = DHServerMsg(B=dh_public)
            conn.send(dh_server.model_dump_json().encode())
            print(f"[>] Session key established")
            
            # Initialize transcript
            self.transcript = Transcript(f"transcripts/server_{addr[0]}_{addr[1]}.txt")
            
            # Phase 5: Encrypted chat
            self.chat_loop(conn)
            
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            print(f"[-] Client disconnected: {addr}")

    def handle_registration(self, conn, msg, temp_key):
        """Handle user registration."""
        try:
            # Decrypt registration data
            ct = b64d(msg['ct'])
            plaintext = aes_decrypt(temp_key, ct)
            reg_data = json.loads(plaintext.decode())
            
            email = reg_data['email']
            username = reg_data['username']
            pwd_hash = reg_data['pwd']
            salt = b64d(reg_data['salt'])
            
            # Create user in database
            success = create_user(email, username, pwd_hash, salt)
            
            if success:
                print(f"[✓] User registered: {username}")
                response = {"type": "status", "success": True, "message": "Registration successful"}
            else:
                print(f"[!] Registration failed: user exists")
                response = {"type": "status", "success": False, "message": "User already exists"}
            
            conn.send(json.dumps(response).encode())
            
        except Exception as e:
            print(f"[!] Registration error: {e}")
            conn.send(json.dumps({"type": "status", "success": False, "message": str(e)}).encode())
    
    def handle_login(self, conn, msg, temp_key):
        """Handle user login."""
        try:
            # Decrypt login data
            ct = b64d(msg['ct'])
            plaintext = aes_decrypt(temp_key, ct)
            login_data = json.loads(plaintext.decode())
            
            email = login_data['email']
            pwd_hash = login_data['pwd']
            
            # Verify credentials
            user = get_user_by_email(email)
            if user and user['pwd_hash'] == pwd_hash:
                print(f"[✓] User authenticated: {user['username']}")
                response = {"type": "status", "success": True, "message": "Login successful"}
                conn.send(json.dumps(response).encode())
                return True
            else:
                print(f"[!] Authentication failed")
                response = {"type": "status", "success": False, "message": "Invalid credentials"}
                conn.send(json.dumps(response).encode())
                return False
                
        except Exception as e:
            print(f"[!] Login error: {e}")
            conn.send(json.dumps({"type": "status", "success": False, "message": str(e)}).encode())
            return False
    
    def chat_loop(self, conn):
        """Handle encrypted chat messages."""
        print("\n[*] Chat session started. Type messages to send (or 'quit' to exit)")
        
        import threading
        
        def receive_messages():
            while True:
                try:
                    data = conn.recv(8192).decode()
                    if not data:
                        break
                    
                    msg = ChatMsg.model_validate_json(data)
                    
                    # Verify sequence number
                    if msg.seqno <= self.client_seqno:
                        print(f"[!] REPLAY: Invalid sequence number")
                        continue
                    self.client_seqno = msg.seqno
                    
                    # Verify signature
                    digest_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode()
                    sig = b64d(msg.sig)
                    if not verify_signature(self.client_cert_pem, digest_data, sig):
                        print(f"[!] SIG_FAIL: Invalid signature")
                        continue
                    
                    # Decrypt message
                    ct = b64d(msg.ct)
                    plaintext = aes_decrypt(self.session_key, ct)
                    
                    # Log to transcript
                    peer_fp = get_cert_fingerprint(self.client_cert_pem)
                    self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, peer_fp)
                    
                    print(f"\n[Client]: {plaintext.decode()}")
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
                    self.generate_receipt(conn)
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
                conn.send(chat_msg.model_dump_json().encode())
                
                # Log to transcript
                peer_fp = get_cert_fingerprint(self.client_cert_pem)
                self.transcript.append(self.seqno, ts, b64e(ct), b64e(sig), peer_fp)
                
            except Exception as e:
                print(f"[!] Send error: {e}")
                break
    
    def generate_receipt(self, conn):
        """Generate and exchange session receipt."""
        try:
            transcript_hash = self.transcript.compute_hash()
            first_seq, last_seq = self.transcript.get_sequence_range()
            
            # Sign transcript hash
            sig = sign_data(self.private_key, transcript_hash.encode())
            
            receipt = ReceiptMsg(
                peer="server",
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
    
    def start(self):
        """Start server."""
        self.load_credentials()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                conn, addr = sock.accept()
                self.handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\n[*] Server shutting down")
        finally:
            sock.close()

def main():
    server = SecureChatServer()
    server.start()

if __name__ == "__main__":
    main()
