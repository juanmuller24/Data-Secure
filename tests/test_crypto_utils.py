#!/usr/bin/env python3
"""
Unit tests for crypto_utils module
"""

import pytest
from pathlib import Path
from crypto_utils import CryptoManager, CryptoConfig
from exceptions import CryptoError
from test_utils import temp_dir, test_password, mock_crypto_config

def test_crypto_manager_initialization(mock_crypto_config):
    """Test CryptoManager initialization."""
    manager = CryptoManager(mock_crypto_config)
    assert manager.config == mock_crypto_config

def test_key_derivation(mock_crypto_config):
    """Test key derivation produces consistent results."""
    manager = CryptoManager(mock_crypto_config)
    password = "test_password"
    salt = b'0' * mock_crypto_config.SALT_SIZE
    
    key1 = manager.derive_key(password, salt)
    key2 = manager.derive_key(password, salt)
    
    assert key1 == key2
    assert len(key1) == mock_crypto_config.KEY_SIZE

def test_encrypt_decrypt_file(temp_dir, test_password, mock_crypto_config):
    """Test file encryption and decryption."""
    manager = CryptoManager(mock_crypto_config)
    
    # Create test file
    source_file = temp_dir / "test.txt"
    content = b"Test content for encryption"
    source_file.write_bytes(content)
    
    # Encrypt
    encrypted_dir = temp_dir / "encrypted"
    encrypted_dir.mkdir()
    encrypt_result = manager.encrypt_file(source_file, test_password, encrypted_dir)
    
    assert encrypt_result['status'] == 'success'
    assert Path(encrypt_result['encrypted_file']).exists()
    
    # Decrypt
    decrypted_dir = temp_dir / "decrypted"
    decrypted_dir.mkdir()
    decrypt_result = manager.decrypt_file(
        Path(encrypt_result['encrypted_file']), 
        test_password, 
        decrypted_dir
    )
    
    assert decrypt_result['status'] == 'success'
    decrypted_file = Path(decrypt_result['decrypted_file'])
    assert decrypted_file.exists()
    assert decrypted_file.read_bytes() == content

def test_encryption_with_wrong_password(temp_dir, test_password, mock_crypto_config):
    """Test decryption fails with wrong password."""
    manager = CryptoManager(mock_crypto_config)
    
    # Create and encrypt test file
    source_file = temp_dir / "test.txt"
    source_file.write_text("Test content")
    
    encrypted_dir = temp_dir / "encrypted"
    encrypted_dir.mkdir()
    encrypt_result = manager.encrypt_file(source_file, test_password, encrypted_dir)
    
    # Try to decrypt with wrong password
    decrypted_dir = temp_dir / "decrypted"
    decrypted_dir.mkdir()
    
    decrypt_result = manager.decrypt_file(
        Path(encrypt_result['encrypted_file']), 
        "wrong_password", 
        decrypted_dir
    )
    
    assert decrypt_result['status'] == 'error'
    assert 'error' in decrypt_result

def test_large_file_encryption(temp_dir, test_password, mock_crypto_config):
    """Test encryption/decryption of large files."""
    manager = CryptoManager(mock_crypto_config)
    
    # Create large test file (10MB)
    source_file = temp_dir / "large_file.bin"
    with open(source_file, 'wb') as f:
        f.write(os.urandom(10 * 1024 * 1024))
    
    # Encrypt
    encrypted_dir = temp_dir / "encrypted"
    encrypted_dir.mkdir()
    encrypt_result = manager.encrypt_file(source_file, test_password, encrypted_dir)
    
    assert encrypt_result['status'] == 'success'
    
    # Decrypt
    decrypted_dir = temp_dir / "decrypted"
    decrypted_dir.mkdir()
    decrypt_result = manager.decrypt_file(
        Path(encrypt_result['encrypted_file']), 
        test_password, 
        decrypted_dir
    )
    
    assert decrypt_result['status'] == 'success'
    assert source_file.read_bytes() == Path(decrypt_result['decrypted_file']).read_bytes()

def test_invalid_input_handling(temp_dir, test_password, mock_crypto_config):
    """Test handling of invalid inputs."""
    manager = CryptoManager(mock_crypto_config)
    
    # Test non-existent file
    with pytest.raises(FileNotFoundError):
        manager.encrypt_file(temp_dir / "nonexistent.txt", test_password, temp_dir)
    
    # Test invalid output directory
    source_file = temp_dir / "test.txt"
    source_file.write_text("test")
    with pytest.raises(Exception):
        manager.encrypt_file(source_file, test_password, temp_dir / "nonexistent")
    
    # Test empty password
    with pytest.raises(ValueError):
        manager.encrypt_file(source_file, "", temp_dir)
