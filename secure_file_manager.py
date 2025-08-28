#!/usr/bin/env python3
"""
Secure File Manager - Production Level File Encryption/Decryption Tool
Handles folders, subfolders, and individual files with robust security features.
"""

import os
import sys
import logging
import tempfile
from pathlib import Path
from typing import Dict, Any
from dataclasses import dataclass

# Import our modular components
from crypto_utils import CryptoManager, CryptoConfig
from file_operations import FileOperations, FileOpsConfig
from cli_interface import parse_arguments, get_password_from_args

# Configuration
@dataclass
class Config:
    """Configuration settings for the encryption/decryption process."""
    # Crypto settings
    CHUNK_SIZE: int = 64 * 1024  # 64KB chunks for memory efficiency
    SALT_SIZE: int = 32
    IV_SIZE: int = 16
    KEY_SIZE: int = 32
    TAG_SIZE: int = 16
    ITERATIONS: int = 100000  # PBKDF2 iterations
    
    # File operations settings
    MAX_WORKERS: int = 4  # Thread pool workers
    COMPRESSION_LEVEL: int = 6  # ZIP compression level
    BACKUP_ORIGINAL: bool = True  # Keep original files as backup
    VERIFY_INTEGRITY: bool = True  # Verify file integrity after operations

class SecureFileManager:
    """Production-level file encryption and decryption manager."""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.logger = self._setup_logging()
        
        # Initialize components
        crypto_config = CryptoConfig(
            CHUNK_SIZE=self.config.CHUNK_SIZE,
            SALT_SIZE=self.config.SALT_SIZE,
            IV_SIZE=self.config.IV_SIZE,
            KEY_SIZE=self.config.KEY_SIZE,
            TAG_SIZE=self.config.TAG_SIZE,
            ITERATIONS=self.config.ITERATIONS
        )
        
        file_ops_config = FileOpsConfig(
            MAX_WORKERS=self.config.MAX_WORKERS,
            COMPRESSION_LEVEL=self.config.COMPRESSION_LEVEL,
            BACKUP_ORIGINAL=self.config.BACKUP_ORIGINAL,
            VERIFY_INTEGRITY=self.config.VERIFY_INTEGRITY
        )
        
        self.crypto_manager = CryptoManager(crypto_config)
        self.file_ops = FileOperations(file_ops_config)
    
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
    
    def encrypt_directory(self, source_dir: Path, password: str, output_dir: Path = None) -> Dict[str, Any]:
        """Encrypt an entire directory structure using parallel processing.
        
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
        files_to_encrypt = self.file_ops.get_files_to_process(source_dir)
        
        if not files_to_encrypt:
            return {'status': 'warning', 'message': 'No files found to encrypt'}
        
        self.logger.info(f"Found {len(files_to_encrypt)} files to encrypt")
        
        # Process files with parallel progress tracking
        def encrypt_single_file(file_path: Path) -> Dict[str, Any]:
            try:
                import threading
                thread_id = threading.current_thread().name
                self.logger.info(f"Starting encryption of {file_path.name} on thread {thread_id}")
                result = self.crypto_manager.encrypt_file(
                    file_path,
                    password,
                    output_dir,
                    base_dir=source_dir,
                    verify_integrity=self.config.VERIFY_INTEGRITY,
                )
                self.logger.info(f"Completed encryption of {file_path.name} on thread {thread_id}")
                return {
                    'status': 'success',
                    'file': str(file_path),
                    'thread': thread_id,
                    'result': result
                }
            except Exception as e:
                self.logger.error(f"Error encrypting {file_path.name}: {str(e)}")
                return {
                    'status': 'error',
                    'file': str(file_path),
                    'thread': threading.current_thread().name,
                    'error': str(e)
                }
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from tqdm import tqdm
        
        results = []
        with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(encrypt_single_file, file_path): file_path 
                for file_path in files_to_encrypt
            }
            
            with tqdm(total=len(files_to_encrypt), desc="Encrypting files") as pbar:
                for future in as_completed(future_to_file):
                    res = future.result()
                    results.append(res)
                    pbar.update(1)
        
        # Aggregate results
        total_files = len(results)
        successful = sum(1 for r in results if r.get('result', {}).get('status') == 'success')
        failed = total_files - successful
        
        manifest = {
            'source_directory': str(source_dir),
            'encryption_date': self._get_timestamp(),
            'total_files': total_files,
            'successful_encryptions': successful,
            'failed_encryptions': failed,
            'results': results
        }
        
        self.file_ops.create_manifest(manifest, output_dir, 'encryption_manifest.json')
        
        # Backup original if configured
        if self.config.BACKUP_ORIGINAL:
            backup_dir = self.file_ops.create_backup(source_dir)
            if backup_dir:
                self.logger.info(f"Original directory backed up to: {backup_dir}")
        
        return manifest
    
    def decrypt_directory(self, encrypted_dir: Path, password: str, output_dir: Path | None = None) -> Dict[str, Any]:
        """Decrypt an entire encrypted directory structure using parallel processing."""
        if not encrypted_dir.exists() or not encrypted_dir.is_dir():
            raise ValueError(f"Encrypted directory does not exist or is not a directory: {encrypted_dir}")
        
        if output_dir is None:
            output_dir = encrypted_dir.parent / f"{encrypted_dir.name}_decrypted"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Find all encrypted files
        encrypted_files = self.file_ops.get_encrypted_files(encrypted_dir)
        
        if not encrypted_files:
            return {'status': 'warning', 'message': 'No encrypted files found'}
        
        self.logger.info(f"Found {len(encrypted_files)} encrypted files to decrypt")
        
        # Process files with parallel tracking
        def decrypt_single_file(encrypted_file: Path) -> Dict[str, Any]:
            try:
                import threading
                thread_id = threading.current_thread().name
                self.logger.info(f"Starting decryption of {encrypted_file.name} on thread {thread_id}")
                result = self.crypto_manager.decrypt_file(
                    encrypted_file,
                    password,
                    output_dir,
                    verify_integrity=self.config.VERIFY_INTEGRITY,
                )
                self.logger.info(f"Completed decryption of {encrypted_file.name} on thread {thread_id}")
                return {
                    'status': 'success',
                    'file': str(encrypted_file),
                    'thread': thread_id,
                    'result': result
                }
            except Exception as e:
                self.logger.error(f"Error decrypting {encrypted_file.name}: {str(e)}")
                return {
                    'status': 'error',
                    'file': str(encrypted_file),
                    'thread': threading.current_thread().name,
                    'error': str(e)
                }
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from tqdm import tqdm
        
        results = []
        with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(decrypt_single_file, encrypted_file): encrypted_file 
                for encrypted_file in encrypted_files
            }
            
            with tqdm(total=len(encrypted_files), desc="Decrypting files") as pbar:
                for future in as_completed(future_to_file):
                    res = future.result()
                    results.append(res)
                    pbar.update(1)
        
        # Aggregate results
        total_files = len(results)
        successful = sum(1 for r in results if r.get('result', {}).get('status') == 'success')
        failed = total_files - successful
        
        manifest = {
            'encrypted_directory': str(encrypted_dir),
            'decryption_date': self._get_timestamp(),
            'total_files': total_files,
            'successful_decryptions': successful,
            'failed_decryptions': failed,
            'results': results
        }
        
        self.file_ops.create_manifest(manifest, output_dir, 'decryption_manifest.json')
        
        return manifest
    
    def create_archive(self, source_dir: Path, password: str, output_file: Path | None = None) -> Dict[str, Any]:
        """Create an encrypted archive of a directory."""
        if output_file is None:
            output_file = source_dir.parent / f"{source_dir.name}_secure.zip"
        
        # Create temporary directory for encrypted files
        temp_dir = Path(tempfile.mkdtemp(prefix="secure_file_manager_archive_"))
        
        try:
            # Encrypt the directory
            encrypt_result = self.encrypt_directory(source_dir, password, temp_dir)
            
            if encrypt_result.get('status') == 'warning':
                return encrypt_result
            
            # Create ZIP archive
            archive_result = self.file_ops.create_archive(temp_dir, output_file)
            
            if archive_result['status'] == 'success':
                return {
                    'status': 'success',
                    'archive_file': archive_result['archive_file'],
                    'archive_size': archive_result['archive_size'],
                    'encryption_results': encrypt_result
                }
            else:
                return archive_result
            
        except Exception as e:
            raise e
        finally:
            # Cleanup temp directory
            self.file_ops.cleanup_temp_directory(temp_dir)
    
    def extract_archive(self, archive_file: Path, password: str, output_dir: Path | None = None) -> Dict[str, Any]:
        """Extract and decrypt an encrypted archive."""
        if not archive_file.exists():
            raise ValueError(f"Archive file does not exist: {archive_file}")
        
        if output_dir is None:
            output_dir = archive_file.parent / f"{archive_file.stem}_extracted"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create temporary directory for extraction
        temp_dir = Path(tempfile.mkdtemp(prefix="secure_file_manager_extract_"))
        
        try:
            # Extract archive
            extract_result = self.file_ops.extract_archive(archive_file, temp_dir)
            
            if extract_result['status'] != 'success':
                return extract_result
            
            # Decrypt the extracted directory
            decrypt_result = self.decrypt_directory(temp_dir, password, output_dir)
            
            return decrypt_result
            
        except Exception as e:
            raise e
        finally:
            # Cleanup temp directory
            self.file_ops.cleanup_temp_directory(temp_dir)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()

def main():
    """Main CLI interface."""
    # Parse arguments
    args = parse_arguments()
    if args is None:
        return 1
    
    # Setup logging
    if args.verbose:
        logging.getLogger('SecureFileManager').setLevel(logging.DEBUG)
    
    # Load configuration
    config = Config()
    if args.config and args.config.exists():
        # Load custom config if provided
        pass  # Implementation for custom config loading
    
    # Get password
    password = get_password_from_args(args)
    if not password:
        return 1
    
    # Initialize manager
    try:
        manager = SecureFileManager(config)
    except ImportError as e:
        print(f"Error: {e}")
        print("Install required dependencies with: pip install cryptography tqdm")
        return 1
    
    # Execute command
    try:
        if args.command == 'encrypt':
            if args.no_backup:
                config.BACKUP_ORIGINAL = False
            
            if args.source.is_file():
                result = manager.crypto_manager.encrypt_file(
                    args.source, password, args.output or args.source.parent,
                    base_dir=args.source.parent,
                    verify_integrity=config.VERIFY_INTEGRITY,
                )
            else:
                result = manager.encrypt_directory(args.source, password, args.output)
            
            print(f"Encryption completed: {result}")
            
        elif args.command == 'decrypt':
            if args.source.is_file():
                result = manager.crypto_manager.decrypt_file(
                    args.source, password, args.output or args.source.parent,
                    verify_integrity=config.VERIFY_INTEGRITY,
                )
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