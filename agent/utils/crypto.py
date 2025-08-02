#!/usr/bin/env python3
"""
Production cryptographic utilities for Mythic Mobile Agent
"""
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

ALG_AES = "AES-256-GCM"
ALG_CHACHA = "ChaCha20-Poly1305"

def key_from_campaign_device(campaign: str, device: str, alg: str = ALG_AES) -> bytes:
    """Derive encryption key from campaign ID and device UUID"""
    seed = f"{campaign}:{device}".encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"mythic-mobile-salt",
        info=b"agent-encryption-key",
        backend=default_backend(),
    ).derive(seed)

def encrypt(data: bytes, key: bytes, alg: str = ALG_AES) -> bytes:
    """Encrypt data with authenticated encryption"""
    nonce = secrets.token_bytes(12)
    if alg == ALG_AES:
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)
    return nonce + cipher.encrypt(nonce, data, None)

def decrypt(blob: bytes, key: bytes, alg: str = ALG_AES) -> bytes:
    """Decrypt data encrypted with encrypt()"""
    nonce, ct = blob[:12], blob[12:]
    if alg == ALG_AES:
        cipher = AESGCM(key) 
    else:
        cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ct, None)
