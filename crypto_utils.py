#!/usr/bin/env python3
"""
Cryptographic utilities for Secure File Manager
Handles encryption, decryption, key derivation, and cryptographic operations
"""

import os
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from dataclasses import dataclass

# Cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("Warning: cryptography library not available. Install with: pip install cryptography")

@dataclass
class CryptoConfig:
    """Configuration settings for cryptographic operations."""
    CHUNK_SIZE: int = 64 * 1024  # 64KB chunks for memory efficiency
    SALT_SIZE: int = 32
    IV_SIZE: int = 16
    KEY_SIZE: int = 32
    TAG_SIZE: int = 16
    ITERATIONS: int = 100000  # PBKDF2 iterations

class CryptoManager:
    """Handles all cryptographic operations for file encryption/decryption."""
    
    def __init__(self, config: CryptoConfig = None):
        self.config = config or CryptoConfig()
        
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required. Install with: pip install cryptography")
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.KEY_SIZE,
            salt=salt,
            iterations=self.config.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def generate_salt(self) -> bytes:
        """Generate random salt for key derivation."""
        return os.urandom(self.config.SALT_SIZE)
    
    def generate_iv(self) -> bytes:
        """Generate random initialization vector."""
        return os.urandom(self.config.IV_SIZE)
    
    def encrypt_file(self, file_path: Path, password: str, output_dir: Path) -> Dict[str, Any]:
        """Encrypt a single file with progress tracking and integrity verification."""
        try:
            # Generate cryptographic materials
            salt = self.generate_salt()
            iv = self.generate_iv()
            key = self.derive_key(password, salt)
            
            # Setup encryption
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Prepare output file path
            relative_path = file_path.relative_to(file_path.parts[0])
            encrypted_file = output_dir / f"{relative_path}.enc"
            encrypted_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Read and encrypt file in chunks
            file_size = file_path.stat().st_size
            encrypted_size = 0
            
            with open(file_path, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
                # Write metadata header
                header = {
                    'salt': salt.hex(),
                    'iv': iv.hex(),
                    'original_name': file_path.name,
                    'original_size': file_size,
                    'timestamp': datetime.now().isoformat()
                }
                header_bytes = json.dumps(header).encode('utf-8')
                header_length = len(header_bytes).to_bytes(4, 'big')
                outfile.write(header_length)
                outfile.write(header_bytes)
                
                # Encrypt file content
                while True:
                    chunk = infile.read(self.config.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                    encrypted_size += len(encrypted_chunk)
                
                # Finalize encryption and get tag
                encryptor.finalize()
                tag = encryptor.tag
                outfile.write(tag)
            
            return {
                'status': 'success',
                'original_file': str(file_path),
                'encrypted_file': str(encrypted_file),
                'original_size': file_size,
                'encrypted_size': encrypted_file.stat().st_size,
                'compression_ratio': (file_size / encrypted_file.stat().st_size) if encrypted_file.stat().st_size > 0 else 0
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'original_file': str(file_path),
                'error': str(e)
            }
    
    def decrypt_file(self, encrypted_file: Path, password: str, output_dir: Path) -> Dict[str, Any]:
        """Decrypt a single encrypted file."""
        try:
            with open(encrypted_file, 'rb') as infile:
                # Read header
                header_length = int.from_bytes(infile.read(4), 'big')
                header_bytes = infile.read(header_length)
                header = json.loads(header_bytes.decode('utf-8'))
                
                # Extract cryptographic materials
                salt = bytes.fromhex(header['salt'])
                iv = bytes.fromhex(header['iv'])
                original_name = header['original_name']
                original_size = header['original_size']
                
                # Derive key
                key = self.derive_key(password, salt)
                
                # Setup decryption
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag=None), backend=default_backend())
                decryptor = cipher.decryptor()
                
                # Prepare output file path
                decrypted_file = output_dir / original_name
                decrypted_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Read and decrypt file content
                encrypted_data = infile.read()
                tag = encrypted_data[-self.config.TAG_SIZE:]
                encrypted_content = encrypted_data[:-self.config.TAG_SIZE]
                
                # Decrypt
                decrypted_content = decryptor.update(encrypted_content)
                decryptor.finalize_with_tag(tag)
                
                # Write decrypted file
                with open(decrypted_file, 'wb') as outfile:
                    outfile.write(decrypted_content)
                
                # Verify size
                if decrypted_file.stat().st_size != original_size:
                    raise ValueError(f"Size mismatch: expected {original_size}, got {decrypted_file.stat().st_size}")
                
                return {
                    'status': 'success',
                    'encrypted_file': str(encrypted_file),
                    'decrypted_file': str(decrypted_file),
                    'original_size': original_size,
                    'decrypted_size': decrypted_file.stat().st_size
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'encrypted_file': str(encrypted_file),
                'error': str(e)
            } 