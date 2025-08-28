#!/usr/bin/env python3
"""
File operations for Secure File Manager
Handles directory traversal, backup operations, and archive management
"""

import os
import json
import shutil
import zipfile
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from dataclasses import dataclass

# Progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("Warning: tqdm library not available. Install with: pip install tqdm")

@dataclass
class FileOpsConfig:
    """Configuration settings for file operations."""
    MAX_WORKERS: int = 4  # Thread pool workers
    COMPRESSION_LEVEL: int = 6  # ZIP compression level
    BACKUP_ORIGINAL: bool = True  # Keep original files as backup
    VERIFY_INTEGRITY: bool = True  # Verify file integrity after operations

class FileOperations:
    """Handles file operations like directory traversal, backup, and archive management."""
    
    def __init__(self, config: FileOpsConfig = None):
        self.config = config or FileOpsConfig()
    
    def get_files_to_process(self, source_dir: Path) -> List[Path]:
        """Get all files to process from a directory (including hidden files)."""
        if not source_dir.exists() or not source_dir.is_dir():
            raise ValueError(f"Source directory does not exist or is not a directory: {source_dir}")
        files_to_process: List[Path] = []
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                file_path = Path(root) / file
                files_to_process.append(file_path)
        return files_to_process
    
    def get_encrypted_files(self, encrypted_dir: Path) -> List[Path]:
        """Get all encrypted files from a directory."""
        if not encrypted_dir.exists() or not encrypted_dir.is_dir():
            raise ValueError(f"Encrypted directory does not exist or is not a directory: {encrypted_dir}")
        encrypted_files: List[Path] = []
        for root, dirs, files in os.walk(encrypted_dir):
            for file in files:
                if file.endswith('.enc'):
                    file_path = Path(root) / file
                    encrypted_files.append(file_path)
        return encrypted_files
    
    def create_backup(self, source_dir: Path) -> Path | None:
        """Create a backup of the original directory."""
        if not self.config.BACKUP_ORIGINAL:
            return None
        if not source_dir.exists() or not source_dir.is_dir():
            raise ValueError(f"Source directory does not exist or is not a directory: {source_dir}")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')  # Include microseconds for uniqueness
        backup_dir = source_dir.parent / f"{source_dir.name}_backup_{timestamp}"
        shutil.copytree(source_dir, backup_dir)
        return backup_dir
    
    def create_manifest(self, manifest_data: Dict[str, Any], output_dir: Path, filename: str) -> Path:
        """Create a manifest file with operation results."""
        if not isinstance(manifest_data, dict):
            raise ValueError("manifest_data must be a dictionary")
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_file = output_dir / filename
        with open(manifest_file, 'w') as f:
            json.dump(manifest_data, f, indent=2)
        return manifest_file
    
    def create_archive(self, source_dir: Path, output_file: Path) -> Dict[str, Any]:
        """Create a ZIP archive from a directory."""
        try:
            if not source_dir.exists() or not source_dir.is_dir():
                raise ValueError(f"Source directory does not exist or is not a directory: {source_dir}")
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED, 
                               compresslevel=self.config.COMPRESSION_LEVEL) as zipf:
                for root, dirs, files in os.walk(source_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(source_dir)
                        zipf.write(file_path, arcname)
            
            return {
                'status': 'success',
                'archive_file': str(output_file),
                'archive_size': output_file.stat().st_size
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def extract_archive(self, archive_file: Path, output_dir: Path) -> Dict[str, Any]:
        """Extract a ZIP archive to a directory."""
        try:
            if not archive_file.exists() or not archive_file.is_file():
                raise ValueError(f"Archive file does not exist: {archive_file}")
            output_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive_file, 'r') as zipf:
                zipf.extractall(output_dir)
            
            return {
                'status': 'success',
                'extracted_dir': str(output_dir)
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def process_files_with_progress(self, files: List[Path], operation_func, 
                                  desc: str = "Processing files", **kwargs) -> Dict[str, Any]:
        """Process files with progress tracking."""
        results = []
        successful = 0
        failed = 0
        
        iterator = tqdm(files, desc=desc) if TQDM_AVAILABLE else files
        for file_path in iterator:
            result = operation_func(file_path, **kwargs)
            results.append(result)
            
            if result.get('status') == 'success' or result.get('result', {}).get('status') == 'success':
                successful += 1
            else:
                failed += 1
            
            if TQDM_AVAILABLE:
                iterator.set_postfix({'Success': successful, 'Failed': failed})
        
        return {
            'total_files': len(files),
            'successful': successful,
            'failed': failed,
            'results': results
        }
    
    def cleanup_temp_directory(self, temp_dir: Path):
        """Clean up temporary directory."""
        if temp_dir.exists():
            shutil.rmtree(temp_dir)