#!/usr/bin/env python3
"""
Secure File Manager - Production Level File Encryption/Decryption Tool
Handles folders, subfolders, and individual files with robust security features.
"""

import os
import sys
import json
import hashlib
import argparse
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
import shutil
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("Warning: cryptography library not available. Install with: pip install cryptography")

# Progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("Warning: tqdm library not available. Install with: pip install tqdm")

# Configuration
@dataclass
class Config:
    """Configuration settings for the encryption/decryption process."""
    CHUNK_SIZE: int = 64 * 1024  # 64KB chunks for memory efficiency
    SALT_SIZE: int = 32
    IV_SIZE: int = 16
    KEY_SIZE: int = 32
    TAG_SIZE: int = 16
    ITERATIONS: int = 100000  # PBKDF2 iterations
    MAX_WORKERS: int = 4  # Thread pool workers
    COMPRESSION_LEVEL: int = 6  # ZIP compression level
    BACKUP_ORIGINAL: bool = True  # Keep original files as backup
    VERIFY_INTEGRITY: bool = True  # Verify file integrity after operations

class SecureFileManager:
    """Production-level file encryption and decryption manager."""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.logger = self._setup_logging()
        self._lock = threading.Lock()
        
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required. Install with: pip install cryptography")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('SecureFileManager')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
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
            
            # Verify integrity
            if self.config.VERIFY_INTEGRITY:
                self._verify_encrypted_file(encrypted_file, password)
            
            return {
                'status': 'success',
                'original_file': str(file_path),
                'encrypted_file': str(encrypted_file),
                'original_size': file_size,
                'encrypted_size': encrypted_file.stat().st_size,
                'compression_ratio': (file_size / encrypted_file.stat().st_size) if encrypted_file.stat().st_size > 0 else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error encrypting {file_path}: {str(e)}")
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
            self.logger.error(f"Error decrypting {encrypted_file}: {str(e)}")
            return {
                'status': 'error',
                'encrypted_file': str(encrypted_file),
                'error': str(e)
            }
    
    def _verify_encrypted_file(self, encrypted_file: Path, password: str) -> bool:
        """Verify that an encrypted file can be decrypted."""
        try:
            # Create temporary directory for verification
            temp_dir = Path(f"/tmp/secure_file_manager_verify_{os.getpid()}")
            temp_dir.mkdir(exist_ok=True)
            
            # Attempt to decrypt
            result = self.decrypt_file(encrypted_file, password, temp_dir)
            
            # Cleanup
            shutil.rmtree(temp_dir)
            
            return result['status'] == 'success'
        except Exception:
            return False
    
    def encrypt_directory(self, source_dir: Path, password: str, output_dir: Path = None) -> Dict[str, Any]:
        """Encrypt an entire directory structure.
        
        Note: This method encrypts ALL files including hidden files (starting with '.')
        and files inside hidden directories. Use with caution if you want to exclude
        system files or configuration files.
        """
        if not source_dir.exists() or not source_dir.is_dir():
            raise ValueError(f"Source directory does not exist or is not a directory: {source_dir}")
        
        if output_dir is None:
            output_dir = source_dir.parent / f"{source_dir.name}_encrypted"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get all files to encrypt
        files_to_encrypt = []
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                # No filtering - encrypt everything including hidden files
                file_path = Path(root) / file
                files_to_encrypt.append(file_path)
        
        if not files_to_encrypt:
            return {'status': 'warning', 'message': 'No files found to encrypt'}
        
        self.logger.info(f"Found {len(files_to_encrypt)} files to encrypt")
        
        # Encrypt files with progress tracking
        results = []
        successful = 0
        failed = 0
        
        if TQDM_AVAILABLE:
            pbar = tqdm(files_to_encrypt, desc="Encrypting files")
        else:
            pbar = files_to_encrypt
        
        for file_path in pbar:
            result = self.encrypt_file(file_path, password, output_dir)
            results.append(result)
            
            if result['status'] == 'success':
                successful += 1
            else:
                failed += 1
            
            if TQDM_AVAILABLE:
                pbar.set_postfix({'Success': successful, 'Failed': failed})
        
        # Create directory structure manifest
        manifest = {
            'source_directory': str(source_dir),
            'encryption_date': datetime.now().isoformat(),
            'total_files': len(files_to_encrypt),
            'successful_encryptions': successful,
            'failed_encryptions': failed,
            'results': results
        }
        
        manifest_file = output_dir / 'encryption_manifest.json'
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Backup original if configured
        if self.config.BACKUP_ORIGINAL:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')  # Include microseconds for uniqueness
            backup_dir = source_dir.parent / f"{source_dir.name}_backup_{timestamp}"
            shutil.copytree(source_dir, backup_dir)
            self.logger.info(f"Original directory backed up to: {backup_dir}")
        
        return manifest
    
    def decrypt_directory(self, encrypted_dir: Path, password: str, output_dir: Path = None) -> Dict[str, Any]:
        """Decrypt an entire encrypted directory structure."""
        if not encrypted_dir.exists() or not encrypted_dir.is_dir():
            raise ValueError(f"Encrypted directory does not exist or is not a directory: {encrypted_dir}")
        
        if output_dir is None:
            output_dir = encrypted_dir.parent / f"{encrypted_dir.name}_decrypted"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Find all encrypted files
        encrypted_files = []
        for root, dirs, files in os.walk(encrypted_dir):
            for file in files:
                if file.endswith('.enc'):
                    file_path = Path(root) / file
                    encrypted_files.append(file_path)
        
        if not encrypted_files:
            return {'status': 'warning', 'message': 'No encrypted files found'}
        
        self.logger.info(f"Found {len(encrypted_files)} encrypted files to decrypt")
        
        # Decrypt files with progress tracking
        results = []
        successful = 0
        failed = 0
        
        if TQDM_AVAILABLE:
            pbar = tqdm(encrypted_files, desc="Decrypting files")
        else:
            pbar = encrypted_files
        
        for encrypted_file in pbar:
            result = self.decrypt_file(encrypted_file, password, output_dir)
            results.append(result)
            
            if result['status'] == 'success':
                successful += 1
            else:
                failed += 1
            
            if TQDM_AVAILABLE:
                pbar.set_postfix({'Success': successful, 'Failed': failed})
        
        # Create decryption manifest
        manifest = {
            'encrypted_directory': str(encrypted_dir),
            'decryption_date': datetime.now().isoformat(),
            'total_files': len(encrypted_files),
            'successful_decryptions': successful,
            'failed_decryptions': failed,
            'results': results
        }
        
        manifest_file = output_dir / 'decryption_manifest.json'
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return manifest
    
    def create_archive(self, source_dir: Path, password: str, output_file: Path = None) -> Dict[str, Any]:
        """Create an encrypted archive of a directory."""
        if output_file is None:
            output_file = source_dir.parent / f"{source_dir.name}_secure.zip"
        
        # Create temporary directory for encrypted files
        temp_dir = Path(f"/tmp/secure_file_manager_archive_{os.getpid()}")
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Encrypt the directory
            encrypt_result = self.encrypt_directory(source_dir, password, temp_dir)
            
            if encrypt_result.get('status') == 'warning':
                return encrypt_result
            
            # Create ZIP archive
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED, compresslevel=self.config.COMPRESSION_LEVEL) as zipf:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(temp_dir)
                        zipf.write(file_path, arcname)
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir)
            
            return {
                'status': 'success',
                'archive_file': str(output_file),
                'archive_size': output_file.stat().st_size,
                'encryption_results': encrypt_result
            }
            
        except Exception as e:
            # Cleanup on error
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            raise e
    
    def extract_archive(self, archive_file: Path, password: str, output_dir: Path = None) -> Dict[str, Any]:
        """Extract and decrypt an encrypted archive."""
        if not archive_file.exists():
            raise ValueError(f"Archive file does not exist: {archive_file}")
        
        if output_dir is None:
            output_dir = archive_file.parent / f"{archive_file.stem}_extracted"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create temporary directory for extraction
        temp_dir = Path(f"/tmp/secure_file_manager_extract_{os.getpid()}")
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Extract archive
            with zipfile.ZipFile(archive_file, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Decrypt the extracted directory
            decrypt_result = self.decrypt_directory(temp_dir, password, output_dir)
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir)
            
            return decrypt_result
            
        except Exception as e:
            # Cleanup on error
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            raise e

def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="Secure File Manager - Production Level File Encryption/Decryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a directory
  python secure_file_manager.py encrypt /path/to/directory --password mypassword
  
  # Decrypt an encrypted directory
  python secure_file_manager.py decrypt /path/to/encrypted_directory --password mypassword
  
  # Create encrypted archive
  python secure_file_manager.py archive /path/to/directory --password mypassword
  
  # Extract encrypted archive
  python secure_file_manager.py extract archive.zip --password mypassword
  
  # Encrypt with custom output directory
  python secure_file_manager.py encrypt /path/to/directory --password mypassword --output /path/to/output
  
  # Use key file instead of password
  python secure_file_manager.py encrypt /path/to/directory --key-file /path/to/keyfile
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a directory or file')
    encrypt_parser.add_argument('source', type=Path, help='Source directory or file to encrypt')
    encrypt_parser.add_argument('--password', type=str, help='Encryption password')
    encrypt_parser.add_argument('--key-file', type=Path, help='File containing encryption key')
    encrypt_parser.add_argument('--output', type=Path, help='Output directory for encrypted files')
    encrypt_parser.add_argument('--no-backup', action='store_true', help='Skip backing up original files')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt an encrypted directory or file')
    decrypt_parser.add_argument('source', type=Path, help='Encrypted directory or file to decrypt')
    decrypt_parser.add_argument('--password', type=str, help='Decryption password')
    decrypt_parser.add_argument('--key-file', type=Path, help='File containing decryption key')
    decrypt_parser.add_argument('--output', type=Path, help='Output directory for decrypted files')
    
    # Archive command
    archive_parser = subparsers.add_parser('archive', help='Create encrypted archive')
    archive_parser.add_argument('source', type=Path, help='Source directory to archive')
    archive_parser.add_argument('--password', type=str, help='Encryption password')
    archive_parser.add_argument('--key-file', type=Path, help='File containing encryption key')
    archive_parser.add_argument('--output', type=Path, help='Output archive file')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract encrypted archive')
    extract_parser.add_argument('source', type=Path, help='Archive file to extract')
    extract_parser.add_argument('--password', type=str, help='Decryption password')
    extract_parser.add_argument('--key-file', type=Path, help='File containing decryption key')
    extract_parser.add_argument('--output', type=Path, help='Output directory for extracted files')
    
    # Global options
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--config', type=Path, help='Configuration file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    if args.verbose:
        logging.getLogger('SecureFileManager').setLevel(logging.DEBUG)
    
    # Load configuration
    config = Config()
    if args.config and args.config.exists():
        # Load custom config if provided
        pass  # Implementation for custom config loading
    
    # Get password/key
    password = None
    if args.password:
        password = args.password
    elif args.key_file and args.key_file.exists():
        with open(args.key_file, 'r') as f:
            password = f.read().strip()
    else:
        import getpass
        password = getpass.getpass("Enter password: ")
    
    if not password:
        print("Error: No password or key file provided")
        return
    
    # Initialize manager
    try:
        manager = SecureFileManager(config)
    except ImportError as e:
        print(f"Error: {e}")
        print("Install required dependencies with: pip install cryptography tqdm")
        return
    
    # Execute command
    try:
        if args.command == 'encrypt':
            if args.no_backup:
                config.BACKUP_ORIGINAL = False
            
            if args.source.is_file():
                result = manager.encrypt_file(args.source, password, args.output or args.source.parent)
            else:
                result = manager.encrypt_directory(args.source, password, args.output)
            
            print(f"Encryption completed: {result}")
            
        elif args.command == 'decrypt':
            if args.source.is_file():
                result = manager.decrypt_file(args.source, password, args.output or args.source.parent)
            else:
                result = manager.decrypt_directory(args.source, password, args.output)
            
            print(f"Decryption completed: {result}")
            
        elif args.command == 'archive':
            result = manager.create_archive(args.source, password, args.output)
            print(f"Archive creation completed: {result}")
            
        elif args.command == 'extract':
            result = manager.extract_archive(args.source, password, args.output)
            print(f"Archive extraction completed: {result}")
    
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main()) 