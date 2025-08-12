import os
import shutil
import zipfile
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


class Encrypt:
    def __init__(self, base_path, key, files_path):
        self.base_path = base_path
        self.key = key
        self.iv = get_random_bytes(16)
        self.files_path = files_path

    def encrypt_file(self):
        try:
            for file_path in tqdm(self.files_path, desc="Loading....."):
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
                encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
                encrypted_data_with_iv = self.iv + encrypted_data

                with open(file_path, 'wb') as f:
                    f.write(encrypted_data_with_iv)
        except Exception as e:
            print(e)
        finally:
            self.compress()

    def compress(self):
        print("Starting to compress....")
        zip_path = f"{self.base_path}_enc.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self.files_path:
                arcname = os.path.relpath(file_path, os.path.dirname(self.base_path))
                zipf.write(file_path, arcname)
        print("Deleting original Directory....")
        shutil.rmtree(self.base_path)
        print("Directory Encrypted!!")
        print(f"Saved at: {self.base_path}_enc.zip")
