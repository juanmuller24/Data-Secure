#!/usr/bin/env python3
"""
Test utilities and fixtures for Secure File Manager
"""

import os
import pytest
import shutil
import tempfile
from pathlib import Path
from typing import Generator

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for testing."""
    temp_path = Path(tempfile.mkdtemp(prefix="secure_file_manager_test_"))
    yield temp_path
    shutil.rmtree(temp_path)

@pytest.fixture
def sample_files(temp_dir: Path) -> Generator[Path, None, None]:
    """Create sample files for testing."""
    # Create test files with various sizes and content
    files = {
        'small.txt': b'Hello, World!',
        'medium.txt': b'A' * 1024,  # 1KB
        'large.txt': b'B' * (1024 * 1024),  # 1MB
        'binary.bin': bytes(range(256))
    }
    
    for name, content in files.items():
        file_path = temp_dir / name
        file_path.write_bytes(content)
    
    # Create nested directory structure
    nested_dir = temp_dir / "nested" / "subdirectory"
    nested_dir.mkdir(parents=True)
    (nested_dir / "nested_file.txt").write_text("Nested content")
    
    yield temp_dir

@pytest.fixture
def test_password() -> str:
    """Return a test password."""
    return "TestPassword123!@#"

@pytest.fixture
def mock_crypto_config():
    """Return test crypto configuration with reduced iterations."""
    from crypto_utils import CryptoConfig
    return CryptoConfig(
        CHUNK_SIZE=1024,  # 1KB chunks for faster tests
        SALT_SIZE=32,
        IV_SIZE=16,
        KEY_SIZE=32,
        TAG_SIZE=16,
        ITERATIONS=1000  # Reduced iterations for faster tests
    )

@pytest.fixture
def mock_file_ops_config():
    """Return test file operations configuration."""
    from file_operations import FileOpsConfig
    return FileOpsConfig(
        MAX_WORKERS=2,  # Reduced workers for testing
        COMPRESSION_LEVEL=1,  # Fast compression for testing
        BACKUP_ORIGINAL=True,
        VERIFY_INTEGRITY=True
    )

def create_test_file_structure(base_dir: Path, num_files: int = 5, 
                             size_range: tuple = (1024, 1024*10)) -> dict:
    """Create a test file structure with specified number of files."""
    import random
    
    files_info = {}
    for i in range(num_files):
        # Create random content
        size = random.randint(size_range[0], size_range[1])
        content = os.urandom(size)
        
        # Create file path
        depth = random.randint(0, 2)
        path_parts = ['dir_{}'.format(random.randint(0, 2)) for _ in range(depth)]
        file_name = 'file_{}.bin'.format(i)
        path_parts.append(file_name)
        
        file_path = base_dir.joinpath(*path_parts)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write content
        file_path.write_bytes(content)
        
        # Store file info
        files_info[file_path] = {
            'size': size,
            'content': content,
            'sha256': compute_file_hash(file_path)
        }
    
    return files_info

def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_directory_structure(dir1: Path, dir2: Path) -> bool:
    """Verify that two directories have identical structure and file contents."""
    files1 = sorted(p for p in dir1.rglob('*') if p.is_file())
    files2 = sorted(p for p in dir2.rglob('*') if p.is_file())
    
    if len(files1) != len(files2):
        return False
    
    for f1, f2 in zip(files1, files2):
        # Check relative paths match
        if f1.relative_to(dir1) != f2.relative_to(dir2):
            return False
        
        # Check file contents match
        if compute_file_hash(f1) != compute_file_hash(f2):
            return False
    
    return True
