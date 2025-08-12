import os
import shutil
import zipfile
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes


def get_filenames(path):
    files_path = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file != ".DS_Store":
                file_path = os.path.join(root, file)
                files_path.append(file_path)
    return files_path


class Decrypt:

    def __init__(self, base_path, key):
        self.base_path = base_path
        self.key = key

    def decrypt_file(self):
        self.decompress()
        decompress_files = self.base_path.strip("_enc.zip")
        files_path = get_filenames(decompress_files)

        try:
            print("Decrypting....")
            for file_path in tqdm(files_path, desc="Loading...."):
                with open(file_path, 'rb') as file:
                    # first 16 bits is iv
                    iv = file.read(16)
                    encrypted_data = file.read()

                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                with open(file_path, 'wb') as file:
                    file.write(decrypted_data)
        except Exception as e:
            print(e)
            print("Deleting Improper Data....")
            shutil.rmtree(decompress_files)
        else:
            print("Directory Decrypted!!")

    def decompress(self):
        print("Starting to Decompress....")
        extract_to = os.path.dirname(self.base_path)
        with zipfile.ZipFile(f'{self.base_path}', 'r') as zip_ref:
            zip_ref.extractall(extract_to)
