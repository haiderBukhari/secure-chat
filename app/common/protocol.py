"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from pydantic import BaseModel
from typing import Optional

class HelloMsg(BaseModel):
    type: str = "hello"
    client_cert: str
    nonce: str

class ServerHelloMsg(BaseModel):
    type: str = "server_hello"
    server_cert: str
    nonce: str

class RegisterMsg(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str  # base64

class LoginMsg(BaseModel):
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||pwd))
    nonce: str

class DHClientMsg(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int

class DHServerMsg(BaseModel):
    type: str = "dh_server"
    B: int

class ChatMsg(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int
    ct: str  # base64 ciphertext
    sig: str  # base64 RSA signature

class ReceiptMsg(BaseModel):
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str  # base64 RSA signature

class StatusMsg(BaseModel):
    type: str = "status"
    success: bool
    message: str
