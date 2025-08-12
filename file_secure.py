#!/usr/bin/env python3
import os
import sys
import hashlib
import encrypt
import decrypt


def get_filenames(path):
    files_path = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file != ".DS_Store":
                file_path = os.path.join(root, file)
                files_path.append(file_path)
    return files_path


def create_key(password):
    # returns 256 bit hash string
    hash256 = hashlib.sha256(password.encode("UTF-8")).hexdigest()
    # returns first 16bits, since only 16 bits is needed for key generation
    hash16 = hash256[:16]
    # converts the string to bits for key
    key = hash16.encode()
    return key


if __name__ == '__main__':
    files_path = get_filenames(sys.argv[2])
    key = create_key(sys.argv[3])
    mode = sys.argv[1].lower()

    if mode == '-e':
        if os.path.exists(sys.argv[2]) and os.path.isdir(sys.argv[2]):
            e = encrypt.Encrypt(base_path=sys.argv[2], key=key, files_path=files_path)
            e.encrypt_file()
        else:
            print(f"No directory found/ Not a Directory: {sys.argv[2]}")
    elif mode == '-d':
        if sys.argv[2].endswith("_enc.zip") and os.path.exists(sys.argv[2]):
            d = decrypt.Decrypt(base_path=sys.argv[2], key=key)
            d.decrypt_file()
        else:
            print("Give proper Zip")
    else:
        print("Select Proper Mode!")
        print("example: python3 file_secure.py 'mode' 'path' 'password'")
        print("mode: -e: encrypt / -d: decrypt")

        print(sys.argv)
        sys.exit()
