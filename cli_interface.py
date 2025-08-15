#!/usr/bin/env python3
"""
Command-line interface for Secure File Manager
Handles argument parsing and CLI operations
"""

import argparse
import getpass
from pathlib import Path
from typing import Optional

def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
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
    
    return parser

def get_password_from_args(args) -> Optional[str]:
    """Get password from command line arguments or prompt user."""
    password = None
    
    if args.password:
        password = args.password
    elif args.key_file and args.key_file.exists():
        with open(args.key_file, 'r') as f:
            password = f.read().strip()
    else:
        password = getpass.getpass("Enter password: ")
    
    if not password:
        print("Error: No password or key file provided")
        return None
    
    return password

def validate_args(args) -> bool:
    """Validate command line arguments."""
    if not args.command:
        return False
    
    # Validate source path exists
    if not args.source.exists():
        print(f"Error: Source path does not exist: {args.source}")
        return False
    
    # Validate key file if provided
    if hasattr(args, 'key_file') and args.key_file and not args.key_file.exists():
        print(f"Error: Key file does not exist: {args.key_file}")
        return False
    
    return True

def parse_arguments():
    """Parse and validate command line arguments."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not validate_args(args):
        parser.print_help()
        return None
    
    return args 