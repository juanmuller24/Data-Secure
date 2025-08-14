# Secure File Manager

A production-level file encryption and decryption tool that can handle folders, subfolders, and individual files with robust security features.

## Features

- **Advanced Encryption**: AES-256-GCM with PBKDF2 key derivation (100,000 iterations)
- **Folder Support**: Encrypts entire directory structures while preserving folder hierarchy
- **Progress Tracking**: Real-time progress bars with detailed status information
- **Integrity Verification**: Automatic verification of encrypted files
- **Backup Protection**: Automatic backup of original files before encryption
- **Archive Support**: Create encrypted ZIP archives for easy transport
- **Memory Efficient**: Processes files in chunks to handle large files
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Requirements

- Python 3.7+
- `cryptography` - For encryption/decryption operations
- `tqdm` - For progress bars

## Installation

1. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python secure_file_manager.py --help
   ```

## Quick Start

### Basic Usage

```bash
# Encrypt a directory
python secure_file_manager.py encrypt /path/to/your/folder --password "your_secure_password"

# Decrypt an encrypted directory
python secure_file_manager.py decrypt /path/to/encrypted_folder --password "your_secure_password"

# Create encrypted archive
python secure_file_manager.py archive /path/to/your/folder --password "your_password"

# Extract encrypted archive
python secure_file_manager.py extract my_secure_archive.zip --password "your_password"
```

### Interactive Mode

The script will prompt for password if not provided:

```bash
python secure_file_manager.py encrypt /path/to/folder
# Will prompt: Enter password:
```

## Usage Examples

### Encrypt with Custom Output
```bash
python secure_file_manager.py encrypt /path/to/folder --password "password" --output /path/to/output
```

### Use Key File Instead of Password
```bash
# Create a key file (store securely!)
echo "your_secure_password" > my_key.txt

# Use the key file
python secure_file_manager.py encrypt /path/to/folder --key-file my_key.txt
```

### Skip Backup (Not Recommended)
```bash
python secure_file_manager.py encrypt /path/to/folder --password "password" --no-backup
```

### Verbose Logging
```bash
python secure_file_manager.py encrypt /path/to/folder --password "password" --verbose
```

## Security Features

- **AES-256-GCM**: Military-grade encryption with authentication
- **PBKDF2**: 100,000 iterations prevent brute force attacks
- **Unique salts**: Each file gets a unique salt
- **Unique IVs**: Each file gets a unique initialization vector
- **Integrity verification**: Automatic verification of encrypted files

## Important Notes

### Security
- **Never share your password** - it's the only way to decrypt your files
- **Keep backups** - the tool creates automatic backups, but maintain additional backups
- **Store passwords securely** - consider using a password manager
- **Test decryption** - always verify you can decrypt before deleting originals

### File Handling
- **All files are encrypted** - including hidden files (starting with `.`)
- **Large files are supported** - processed in 64KB chunks for memory efficiency
- **Folder structure is preserved** - relative paths are maintained
- **Original files are backed up** - unless `--no-backup` is specified

## Troubleshooting

### Common Issues

1. **Import Error for cryptography**
   ```bash
   pip install cryptography
   ```

2. **Import Error for tqdm**
   ```bash
   pip install tqdm
   ```

3. **Permission Denied**
   - Ensure you have read/write permissions for source and destination directories
   - On Windows, run as Administrator if needed

4. **Decryption Fails**
   - Verify the password is correct
   - Check that the encrypted files are not corrupted
   - Ensure you're using the same version of the tool for encryption and decryption

## Project Structure

```
file_secure/
├── secure_file_manager.py      # Main production script
├── requirements.txt            # Dependencies
├── README.md                  # This file
├── config_example.py          # Configuration examples
└── .gitignore                 # Git ignore rules
```

## Configuration

The tool uses sensible defaults but can be customized. See `config_example.py` for various configuration options including:
- High security configuration
- Performance-focused configuration
- Enterprise configuration
- Embedded systems configuration
- Cloud storage configuration

## License

This tool is provided as-is for educational and production use. Ensure you comply with all applicable laws and regulations regarding encryption in your jurisdiction.

---

**⚠️ Security Disclaimer**: While this tool uses industry-standard encryption algorithms, the security of your encrypted data ultimately depends on the strength of your password and the security of your system. Use strong, unique passwords and keep your system secure. 