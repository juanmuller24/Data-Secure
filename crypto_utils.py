#!/usr/bin/env python3
"""
Cryptographic utilities for Secure File Manager
Handles encryption, decryption, key derivation, and cryptographic operations
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import hashlib

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
    
    def encrypt_file(self, file_path: Path, password: str, output_dir: Path,
                     base_dir: Optional[Path] = None,
                     verify_integrity: bool = True) -> Dict[str, Any]:
        """Encrypt a single file with streaming and optional integrity metadata.
        
        Args:
            file_path: Path to the plaintext file
            password: Password for key derivation
            output_dir: Base directory where encrypted file will be written
            base_dir: If provided, encrypted file path will mirror structure relative to this dir
            verify_integrity: If True, store SHA-256 of plaintext in header for verification
        """
        try:
            if not password:
                raise ValueError("Password must not be empty")
            if not file_path.exists() or not file_path.is_file():
                raise FileNotFoundError(f"Source file does not exist: {file_path}")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate cryptographic materials
            salt = self.generate_salt()
            iv = self.generate_iv()
            key = self.derive_key(password, salt)
            
            # Setup encryption
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Determine output file path, preserving directory structure when base_dir provided
            if base_dir:
                relative_path = Path(file_path).resolve().relative_to(Path(base_dir).resolve())
                encrypted_file = output_dir / (str(relative_path) + ".enc")
            else:
                relative_path = Path(file_path.name)
                encrypted_file = output_dir / f"{file_path.name}.enc"
            encrypted_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Compute optional integrity hash while reading
            sha256 = hashlib.sha256() if verify_integrity else None
            file_size = file_path.stat().st_size
            
            with open(file_path, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
                # Write metadata header
                header = {
                    'salt': salt.hex(),
                    'iv': iv.hex(),
                    'original_name': file_path.name,
                    'relative_path': str(relative_path).replace('\\\\', '/'),
                    'original_size': file_size,
                    'timestamp': datetime.now().isoformat(),
                    'algo': 'AES-256-GCM',
                    'kdf': 'PBKDF2-HMAC-SHA256',
                    'iterations': self.config.ITERATIONS,
                }
                # Write header (length-prefixed JSON)
                header_bytes = json.dumps(header).encode('utf-8')
                outfile.write(len(header_bytes).to_bytes(4, 'big'))
                outfile.write(header_bytes)
                
                # Encrypt file content in chunks
                while True:
                    chunk = infile.read(self.config.CHUNK_SIZE)
                    if not chunk:
                        break
                    if sha256:
                        sha256.update(chunk)
                    encrypted_chunk = encryptor.update(chunk)
                    if encrypted_chunk:
                        outfile.write(encrypted_chunk)
                
                # Finalize encryption and write tag
                encryptor.finalize()
                tag = encryptor.tag
                outfile.write(tag)
            
            result: Dict[str, Any] = {
                'status': 'success',
                'original_file': str(file_path),
                'encrypted_file': str(encrypted_file),
                'original_size': file_size,
                'encrypted_size': encrypted_file.stat().st_size,
            }
            if sha256:
                result['sha256'] = sha256.hexdigest()
            return result
            
        except Exception as e:
            return {
                'status': 'error',
                'original_file': str(file_path),
                'error': str(e)
            }
    
    def decrypt_file(self, encrypted_file: Path, password: str, output_dir: Path,
                     verify_integrity: bool = True) -> Dict[str, Any]:
        """Decrypt a single encrypted file using streaming.
        
        Args:
            encrypted_file: Path to .enc file
            password: Password used for key derivation
            output_dir: Directory where plaintext will be written
            verify_integrity: If True and header/metadata available, verify SHA-256 of plaintext
        """
        try:
            if not password:
                raise ValueError("Password must not be empty")
            if not encrypted_file.exists() or not encrypted_file.is_file():
                raise FileNotFoundError(f"Encrypted file does not exist: {encrypted_file}")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            file_size = encrypted_file.stat().st_size
            
            with open(encrypted_file, 'rb') as infile:
                # Read header
                header_length = int.from_bytes(infile.read(4), 'big')
                if header_length <= 0 or header_length > 10 * 1024 * 1024:
                    raise ValueError("Invalid header length")
                header_bytes = infile.read(header_length)
                header = json.loads(header_bytes.decode('utf-8'))
                
                # Extract cryptographic materials
                salt = bytes.fromhex(header['salt'])
                iv = bytes.fromhex(header['iv'])
                original_name = header.get('original_name')
                relative_path = header.get('relative_path') or original_name
                original_size = header.get('original_size')
                
                # Derive key
                key = self.derive_key(password, salt)
                
                # Setup decryption
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag=None), backend=default_backend())
                decryptor = cipher.decryptor()
                
                # Prepare output file path (preserve structure if available)
                decrypted_file = output_dir / relative_path
                decrypted_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Determine lengths
                remaining = file_size - 4 - header_length
                if remaining < self.config.TAG_SIZE:
                    raise ValueError("Encrypted file is too short or corrupted")
                data_len = remaining - self.config.TAG_SIZE
                
                # Stream decrypt and optional integrity verify
                sha256 = hashlib.sha256() if verify_integrity else None
                bytes_read = 0
                with open(decrypted_file, 'wb') as outfile:
                    while bytes_read < data_len:
                        to_read = min(self.config.CHUNK_SIZE, data_len - bytes_read)
                        chunk = infile.read(to_read)
                        if not chunk:
                            break
                        plaintext = decryptor.update(chunk)
                        if plaintext:
                            outfile.write(plaintext)
                            if sha256:
                                sha256.update(plaintext)
                        bytes_read += len(chunk)
                    # Read tag and finalize
                    tag = infile.read(self.config.TAG_SIZE)
                    decryptor.finalize_with_tag(tag)
                
                # Verify size
                if original_size is not None and decrypted_file.stat().st_size != original_size:
                    raise ValueError(f"Size mismatch: expected {original_size}, got {decrypted_file.stat().st_size}")
                
                # Optional integrity validation against header hash if present
                header_sha256 = header.get('sha256')
                if verify_integrity and header_sha256:
                    if sha256 and sha256.hexdigest() != header_sha256:
                        raise ValueError("Integrity check failed (SHA-256 mismatch)")
                
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