#!/usr/bin/env python3
"""
Configuration example for Secure File Manager
Shows how to customize various settings for different use cases
"""

from secure_file_manager import Config

# Basic configuration with default settings
basic_config = Config()

# High-security configuration (slower but more secure)
high_security_config = Config(
    CHUNK_SIZE=32 * 1024,        # 32KB chunks for better security
    SALT_SIZE=64,                 # 64-byte salt (doubled)
    IV_SIZE=16,                   # 16-byte IV
    KEY_SIZE=32,                  # 32-byte key (256-bit)
    TAG_SIZE=16,                  # 16-byte authentication tag
    ITERATIONS=500000,            # 500K PBKDF2 iterations (5x more)
    MAX_WORKERS=2,                # Fewer workers for security
    COMPRESSION_LEVEL=9,          # Maximum compression
    BACKUP_ORIGINAL=True,         # Always backup
    VERIFY_INTEGRITY=True         # Always verify
)

# Performance-focused configuration (faster but less secure)
performance_config = Config(
    CHUNK_SIZE=128 * 1024,       # 128KB chunks for speed
    SALT_SIZE=16,                 # 16-byte salt (minimum)
    IV_SIZE=16,                   # 16-byte IV
    KEY_SIZE=32,                  # 32-byte key (256-bit)
    TAG_SIZE=16,                  # 16-byte authentication tag
    ITERATIONS=50000,             # 50K PBKDF2 iterations (half)
    MAX_WORKERS=8,                # More workers for speed
    COMPRESSION_LEVEL=3,          # Lower compression for speed
    BACKUP_ORIGINAL=False,        # Skip backup for speed
    VERIFY_INTEGRITY=False        # Skip verification for speed
)

# Enterprise configuration (balanced security and performance)
enterprise_config = Config(
    CHUNK_SIZE=64 * 1024,        # 64KB chunks (balanced)
    SALT_SIZE=32,                 # 32-byte salt
    IV_SIZE=16,                   # 16-byte IV
    KEY_SIZE=32,                  # 32-byte key (256-bit)
    TAG_SIZE=16,                  # 16-byte authentication tag
    ITERATIONS=200000,            # 200K PBKDF2 iterations (2x more)
    MAX_WORKERS=4,                # Balanced worker count
    COMPRESSION_LEVEL=6,          # Balanced compression
    BACKUP_ORIGINAL=True,         # Always backup in enterprise
    VERIFY_INTEGRITY=True         # Always verify in enterprise
)

# Custom configuration for specific use case
custom_config = Config(
    CHUNK_SIZE=256 * 1024,       # 256KB chunks for very large files
    SALT_SIZE=48,                 # 48-byte salt
    IV_SIZE=16,                   # 16-byte IV
    KEY_SIZE=32,                  # 32-byte key (256-bit)
    TAG_SIZE=16,                  # 16-byte authentication tag
    ITERATIONS=150000,            # 150K PBKDF2 iterations
    MAX_WORKERS=6,                # 6 workers
    COMPRESSION_LEVEL=7,          # High compression
    BACKUP_ORIGINAL=True,         # Keep backups
    VERIFY_INTEGRITY=True         # Verify integrity
)

# Configuration for embedded systems (memory-constrained)
embedded_config = Config(
    CHUNK_SIZE=16 * 1024,        # 16KB chunks for low memory
    SALT_SIZE=16,                 # 16-byte salt (minimum)
    IV_SIZE=16,                   # 16-byte IV
    KEY_SIZE=32,                  # 32-byte key (256-bit)
    TAG_SIZE=16,                  # 16-byte authentication tag
    ITERATIONS=100000,            # Standard iterations
    MAX_WORKERS=1,                # Single worker for low memory
    COMPRESSION_LEVEL=1,          # Minimal compression
    BACKUP_ORIGINAL=False,        # Skip backup to save space
    VERIFY_INTEGRITY=True         # Keep verification for security
)

# Configuration for cloud storage (network-optimized)
cloud_config = Config(
    CHUNK_SIZE=512 * 1024,       # 512KB chunks for network efficiency
    SALT_SIZE=32,                 # 32-byte salt
    IV_SIZE=16,                   # 16-byte IV
    KEY_SIZE=32,                  # 32-byte key (256-bit)
    TAG_SIZE=16,                  # 16-byte authentication tag
    ITERATIONS=100000,            # Standard iterations
    MAX_WORKERS=4,                # Balanced workers
    COMPRESSION_LEVEL=8,          # High compression for network
    BACKUP_ORIGINAL=True,         # Keep backups
    VERIFY_INTEGRITY=True         # Verify integrity
)

def print_config_info(config: Config, name: str):
    """Print configuration information."""
    print(f"\n=== {name} ===")
    print(f"Chunk Size: {config.CHUNK_SIZE / 1024:.1f} KB")
    print(f"Salt Size: {config.SALT_SIZE} bytes")
    print(f"IV Size: {config.IV_SIZE} bytes")
    print(f"Key Size: {config.KEY_SIZE * 8} bits")
    print(f"PBKDF2 Iterations: {config.ITERATIONS:,}")
    print(f"Max Workers: {config.MAX_WORKERS}")
    print(f"Compression Level: {config.COMPRESSION_LEVEL}")
    print(f"Backup Original: {config.BACKUP_ORIGINAL}")
    print(f"Verify Integrity: {config.VERIFY_INTEGRITY}")

if __name__ == "__main__":
    print("Secure File Manager Configuration Examples")
    print("=" * 50)
    
    print_config_info(basic_config, "Basic Configuration (Default)")
    print_config_info(high_security_config, "High Security Configuration")
    print_config_info(performance_config, "Performance Configuration")
    print_config_info(enterprise_config, "Enterprise Configuration")
    print_config_info(custom_config, "Custom Configuration")
    print_config_info(embedded_config, "Embedded System Configuration")
    print_config_info(cloud_config, "Cloud Storage Configuration")
    
    print("\n" + "=" * 50)
    print("Usage:")
    print("from config_example import enterprise_config")
    print("manager = SecureFileManager(enterprise_config)") 