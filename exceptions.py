#!/usr/bin/env python3
"""
Custom exceptions for Secure File Manager
"""

class SecureFileManagerError(Exception):
    """Base exception class for Secure File Manager."""
    pass

class CryptoError(SecureFileManagerError):
    """Raised when cryptographic operations fail."""
    pass

class FileOperationError(SecureFileManagerError):
    """Raised when file operations fail."""
    pass

class ConfigurationError(SecureFileManagerError):
    """Raised when configuration is invalid."""
    pass

class ValidationError(SecureFileManagerError):
    """Raised when input validation fails."""
    pass

class PasswordError(SecureFileManagerError):
    """Raised when password-related operations fail."""
    pass

class IntegrityError(SecureFileManagerError):
    """Raised when file integrity checks fail."""
    pass
