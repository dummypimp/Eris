
"""
Enhanced encryptor.py - Advanced cryptographic utilities for Mythic Mobile Agent
Supports multiple encryption algorithms with enhanced key derivation and security
"""

import os
import secrets
import hashlib
import struct
from typing import Tuple, Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


ALG_AES = "AES-256-GCM"
ALG_CHACHA = "ChaCha20-Poly1305"
ALG_XOR = "XOR-STREAM"


KDF_HKDF = "HKDF-SHA256"
KDF_PBKDF2 = "PBKDF2-SHA256"
KDF_SCRYPT = "SCRYPT"

class EnhancedEncryptor:
    def __init__(self, kdf_method: str = KDF_HKDF):
        self.kdf_method = kdf_method
        self.context_salt = b"mythic-mobile-agent-v2"
        
    def _derive_key(self, master: bytes, salt: bytes, length: int = 32,
                   iterations: int = 100000) -> bytes:
        """Enhanced key derivation with multiple KDF options"""
        if self.kdf_method == KDF_HKDF:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                info=self.context_salt,
                backend=default_backend(),
            ).derive(master)
        
        elif self.kdf_method == KDF_PBKDF2:
            return PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                iterations=iterations,
                backend=default_backend(),
            ).derive(master)
        
        elif self.kdf_method == KDF_SCRYPT:
            return Scrypt(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend(),
            ).derive(master)
        
        else:
            raise ValueError(f"Unsupported KDF method: {self.kdf_method}")

    def key_from_campaign_device(self, campaign: str, device: str,
                                android_version: int = 34,
                                alg: str = ALG_AES) -> bytes:
        """Enhanced key derivation with Android version awareness"""

        seed_components = [
            campaign.encode(),
            device.encode(),
            str(android_version).encode(),
            os.urandom(16) if not hasattr(self, '_static_entropy') else self._static_entropy
        ]
        

        self._static_entropy = hashlib.sha256(f"{campaign}:{device}".encode()).digest()[:16]
        
        seed = b"".join([
            campaign.encode(),
            device.encode(),
            str(android_version).encode(),
            self._static_entropy
        ])
        
        salt = hashlib.sha256(seed).digest()[:16]
        return self._derive_key(seed, salt, 32)

    def encrypt(self, data: bytes, key: bytes, alg: str = ALG_AES,
               additional_data: Optional[bytes] = None) -> bytes:
        """Enhanced encryption with additional authenticated data support"""
        if alg == ALG_XOR:
            return self._xor_encrypt(data, key)
        

        nonce = secrets.token_bytes(12)
        
        if alg == ALG_AES:
            cipher = AESGCM(key)
        elif alg == ALG_CHACHA:
            cipher = ChaCha20Poly1305(key)
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")
        

        ciphertext = cipher.encrypt(nonce, data, additional_data)
        

        return nonce + ciphertext

    def decrypt(self, blob: bytes, key: bytes, alg: str = ALG_AES,
               additional_data: Optional[bytes] = None) -> bytes:
        """Enhanced decryption with additional authenticated data support"""
        if alg == ALG_XOR:
            return self._xor_decrypt(blob, key)
        

        nonce, ciphertext = blob[:12], blob[12:]
        
        if alg == ALG_AES:
            cipher = AESGCM(key)
        elif alg == ALG_CHACHA:
            cipher = ChaCha20Poly1305(key)
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")
        

        return cipher.decrypt(nonce, ciphertext, additional_data)

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Lightweight XOR encryption for basic obfuscation"""
        key_stream = self._generate_key_stream(len(data), key)
        return bytes(d ^ k for d, k in zip(data, key_stream))
    
    def _xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR decryption (same as encryption)"""
        return self._xor_encrypt(data, key)
    
    def _generate_key_stream(self, length: int, key: bytes) -> bytes:
        """Generate key stream from key for XOR operations"""
        key_stream = b""
        key_index = 0
        
        for i in range(length):
            if key_index >= len(key):
                key_index = 0
            key_stream += bytes([key[key_index] ^ (i & 0xFF)])
            key_index += 1
            
        return key_stream

    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """Generate RSA keypair for hybrid encryption scenarios"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem

    def secure_delete_key(self, key: Union[bytes, bytearray]) -> None:
        """Securely delete key from memory"""
        if isinstance(key, bytes):

            key = bytearray(key)
        

        for i in range(len(key)):
            key[i] = secrets.randbits(8)
        

        for i in range(len(key)):
            key[i] = 0


encryptor = EnhancedEncryptor()

def key_from_campaign_device(campaign: str, device: str, alg: str = ALG_AES) -> bytes:
    return encryptor.key_from_campaign_device(campaign, device, alg=alg)

def encrypt(data: bytes, key: bytes, alg: str = ALG_AES) -> bytes:
    return encryptor.encrypt(data, key, alg)

def decrypt(blob: bytes, key: bytes, alg: str = ALG_AES) -> bytes:
    return encryptor.decrypt(blob, key, alg)
