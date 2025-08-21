#!/usr/bin/env python3
"""
Unit tests for file_operations module
"""

import os
import pytest
from pathlib import Path
from file_operations import FileOperations, FileOpsConfig
from exceptions import FileOperationError
from test_utils import (
    temp_dir, 
    mock_file_ops_config, 
    create_test_file_structure,
    verify_directory_structure
)

def test_file_operations_initialization(mock_file_ops_config):
    """Test FileOperations initialization."""
    ops = FileOperations(mock_file_ops_config)
    assert ops.config == mock_file_ops_config

def test_get_files_to_process(temp_dir):
    """Test getting files from directory."""
    # Create test file structure
    files_info = create_test_file_structure(temp_dir)
    
    ops = FileOperations()
    files = ops.get_files_to_process(temp_dir)
    
    # Verify all files are found
    assert len(files) == len(files_info)
    assert all(f.exists() for f in files)

def test_backup_creation(temp_dir):
    """Test backup directory creation."""
    # Create test structure
    create_test_file_structure(temp_dir)
    
    ops = FileOperations()
    backup_dir = ops.create_backup(temp_dir)
    
    assert backup_dir.exists()
    assert verify_directory_structure(temp_dir, backup_dir)

def test_backup_disabled(temp_dir):
    """Test backup creation when disabled."""
    config = FileOpsConfig(BACKUP_ORIGINAL=False)
    ops = FileOperations(config)
    
    backup_dir = ops.create_backup(temp_dir)
    assert backup_dir is None

def test_manifest_creation(temp_dir):
    """Test operation manifest creation."""
    ops = FileOperations()
    manifest_data = {
        'operation': 'test',
        'status': 'success',
        'files': ['file1.txt', 'file2.txt']
    }
    
    manifest_file = ops.create_manifest(manifest_data, temp_dir, 'test_manifest.json')
    
    assert manifest_file.exists()
    import json
    with open(manifest_file) as f:
        loaded_data = json.load(f)
    assert loaded_data == manifest_data

def test_archive_operations(temp_dir):
    """Test archive creation and extraction."""
    # Create test files
    source_dir = temp_dir / "source"
    source_dir.mkdir()
    files_info = create_test_file_structure(source_dir)
    
    ops = FileOperations()
    
    # Create archive
    archive_file = temp_dir / "test_archive.zip"
    result = ops.create_archive(source_dir, archive_file)
    
    assert result['status'] == 'success'
    assert archive_file.exists()
    
    # Extract archive
    extract_dir = temp_dir / "extracted"
    extract_dir.mkdir()
    extract_result = ops.extract_archive(archive_file, extract_dir)
    
    assert extract_result['status'] == 'success'
    assert verify_directory_structure(source_dir, extract_dir)

def test_invalid_operations(temp_dir):
    """Test handling of invalid operations."""
    ops = FileOperations()
    
    # Test non-existent source directory
    with pytest.raises(Exception):
        ops.get_files_to_process(temp_dir / "nonexistent")
    
    # Test invalid archive file
    with pytest.raises(Exception):
        ops.extract_archive(temp_dir / "nonexistent.zip", temp_dir)
    
    # Test invalid manifest data
    with pytest.raises(Exception):
        ops.create_manifest(None, temp_dir, "invalid.json")

def test_parallel_processing(temp_dir):
    """Test parallel file processing."""
    # Create many test files
    files_info = create_test_file_structure(temp_dir, num_files=20)
    
    ops = FileOperations(FileOpsConfig(MAX_WORKERS=4))
    
    # Mock operation function
    def operation_func(file_path):
        return {'status': 'success', 'file': str(file_path)}
    
    result = ops.process_files_with_progress(
        list(files_info.keys()),
        operation_func,
        desc="Testing parallel processing"
    )
    
    assert result['total_files'] == len(files_info)
    assert result['successful'] == len(files_info)
    assert result['failed'] == 0
