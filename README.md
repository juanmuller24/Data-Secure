### File Secure

Simple CLI to encrypt an entire directory into a single zip file and decrypt it back later using a password-derived key.

### Features
- **AES-CBC encryption**: Encrypts every file in a directory.
- **Zip packaging**: Produces a single `*_enc.zip` archive containing the encrypted files.
- **Progress bar**: Uses `tqdm` for progress feedback.

### Requirements
- **Python**: 3.8+
- **Packages**: `pycryptodome`, `tqdm`

Install dependencies:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install pycryptodome tqdm
```

### Usage
The CLI entrypoint is `file_secure.py`.

General syntax:

```bash
python3 file_secure.py <mode> <path> <password>
# modes: -e (encrypt), -d (decrypt)
```

- **Encrypt a directory**

```bash
python3 file_secure.py -e /path/to/my_folder myStrongPassword
```

Result:
- All files inside `/path/to/my_folder` are encrypted in place, then compressed into `/path/to/my_folder_enc.zip`.
- The original directory `/path/to/my_folder` is deleted after compression.

- **Decrypt an archive**

```bash
python3 file_secure.py -d /path/to/my_folder_enc.zip myStrongPassword
```

Result:
- The archive is extracted next to the zip, and each file is decrypted back to its original content.

### How it works (high level)
- The key is derived from your password by computing SHA-256, taking the first 16 hex characters, and using those bytes as a 16-byte AES key.
- During encryption, a single random 16-byte IV is generated per run and prepended to every encrypted file's bytes. Files are then zipped and the original directory is removed.
- During decryption, files are read from the extracted directory, their first 16 bytes are used as the IV, and the rest is decrypted.

### Important notes and limitations
- **Destructive behavior**: After encryption, the original directory is deleted. Work on a copy if you are experimenting.
- **Key derivation**: No salt or KDF iterations are used. The key is derived as ASCII bytes of the first 16 hex chars of SHA-256(password), which is a 128-bit key but not a standard KDF like PBKDF2/scrypt/Argon2.
- **IV reuse per run**: One IV is generated for the entire encryption run and prepended to each file. This is functional for decryption but not ideal cryptographically; unique IVs per file are recommended for stronger security.
- **No integrity/authentication**: AES-CBC without an authentication tag does not detect tampering. Consider an AEAD mode (e.g., AES-GCM) for integrity.
- **Supported inputs**: Encryption expects a directory path. Decryption expects a zip path that ends with `_enc.zip`.
- **Hidden/system files**: Files named `.DS_Store` are skipped; other files (including hidden ones) are processed.

### Troubleshooting
- "Select Proper Mode!": Use `-e` to encrypt a directory or `-d` to decrypt a `*_enc.zip` file.
- "Give proper Zip": Ensure the path you pass to `-d` ends with `_enc.zip` and exists.
- Wrong password: Decryption will fail and the partially extracted directory is removed to avoid leaving corrupted data.

### Project structure
- `file_secure.py`: CLI entrypoint (argument parsing, key creation, routing to encrypt/decrypt).
- `encrypt.py`: Encrypts files in the given directory, prepends IV, zips the result, deletes the original directory.
- `decrypt.py`: Decompresses the zip, reads IV from each file, and decrypts the contents.

### Roadmap (ideas)
- Switch to a standard KDF (PBKDF2/scrypt/Argon2) with salt and iterations.
- Use per-file random IVs and authenticated encryption (AES-GCM/ChaCha20-Poly1305).
- Add a non-destructive mode that keeps originals.
- Add `--help` and safer CLI UX with confirmations.
- Provide a `requirements.txt` and tests.

### Disclaimer
This tool is for educational and light personal use. It is not audited for production security. Use at your own risk and keep backups of your data.

