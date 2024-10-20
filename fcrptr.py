import os
import argparse
import sys
import json
import random
import string
import base64
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crpt.sync_encryptor import SyncEncryptor
from crpt.rsa_encryptor import RSAEncryptor


def generate_salt(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def save_encrypted_data(file_path, content, public_key, passphrase):
    encryptor = SyncEncryptor(passphrase)
    encrypted_content, salt = encryptor.encrypt(content, is_bytes=True)

    rsa_encryptor = RSAEncryptor()
    encrypted_passphrase = rsa_encryptor.encrypt_with_public_key(public_key, passphrase)

    encrypted_content_base64 = base64.b64encode(encrypted_content).decode('utf-8')
    encrypted_passphrase_base64 = base64.b64encode(encrypted_passphrase).decode('utf-8')

    data = {
        "timestamp": int(time.time()),
        "public_key": public_key,
        "filename": os.path.basename(file_path),
        "path": os.path.dirname(file_path),
        "encrypted_content": encrypted_content_base64,
        "encrypted_passphrase": encrypted_passphrase_base64,
    }

    with open(file_path, 'w') as json_file:
        json.dump(data, json_file)

    output_path = f"{file_path}.fcrptrencrypted"
    os.rename(file_path, output_path)

    print(f"Data encrypted and saved to: {output_path}. Original file {file_path}.")


def read_encrypted_data(file_path, private_key):
    with open(file_path, 'r') as json_file:
        data = json.load(json_file)

    rsa_encryptor = RSAEncryptor()
    encrypted_passphrase = base64.b64decode(data["encrypted_passphrase"])
    passphrase = rsa_encryptor.decrypt_with_private_key(private_key, encrypted_passphrase)

    encrypted_content = base64.b64decode(data["encrypted_content"])
    encryptor = SyncEncryptor(passphrase)
    decrypted_content = encryptor.decrypt(encrypted_content, is_bytes=True)

    with open(file_path, 'wb') as file:
        file.write(decrypted_content)

    original_file_path = file_path[:-len('.fcrptrencrypted')]
    os.rename(file_path, original_file_path)

    print(f"Data decrypted and saved back to: {original_file_path}")

def load_file(file_path, mode='r'):
    with open(file_path, mode) as file:
        return file.read()


def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(description="Encrypt or decrypt files.")
    parser.add_argument('--encrypt-directory', type=str, required=False,
                        help="Path to the directory to encrypt files.")
    parser.add_argument('--encrypt-file', type=str, help="Path to the specific file to encrypt.")
    parser.add_argument('--decrypt-directory', type=str, required=False,
                        help="Path to the directory to decrypt files.")
    parser.add_argument('--decrypt-file', type=str, help="Path to the specific file to decrypt.")
    parser.add_argument('--public-key', type=str, required=False,
                        help="Path to the file containing the public key for encryption.")
    parser.add_argument('--private-key', type=str, required=False,
                        help="Path to the file containing the private key for decryption.")
    parser.add_argument('--passphrase', type=str, required=False, help="Passphrase for encryption.")
    parser.add_argument('--generate_keys', action='store_true',
                        help="Generate RSA keys. Optionally provide a passphrase.")

    args = parser.parse_args()

    if args.generate_keys:
        print(f"Generating RSA keys")
        rsa_encryptor = RSAEncryptor()
        private_key, public_key = rsa_encryptor.generate_keys()
        private_key_path = 'private_key.pem'
        public_key_path = 'public_key.pem'

        with open(private_key_path, 'w') as private_file:
            private_file.write(private_key)
        with open(public_key_path, 'w') as public_file:
            public_file.write(public_key)
        print("Successfully created the RSA key files.")

    if args.encrypt_file and args.public_key:
        public_key_data = load_file(args.public_key)
        content = load_file(args.encrypt_file, mode='rb')
        save_encrypted_data(args.encrypt_file, content, public_key_data, args.passphrase)

    if args.decrypt_file and args.private_key:
        private_key_data = load_file(args.private_key)
        read_encrypted_data(args.decrypt_file, private_key_data)

    if args.encrypt_directory and args.public_key and args.passphrase:
        public_key_data = load_file(args.public_key)
        encrypt_exception_report = list()
        for root, dirs, files in os.walk(args.encrypt_directory):
            for file in files:
                file_path = os.path.join(root, file)
                content = load_file(file_path, mode='rb')
                try:
                    save_encrypted_data(file_path, content, public_key_data, args.passphrase)
                except PermissionError:
                    msg = f"Permission denied for file: {file_path}. Skipping..."
                    encrypt_exception_report.append(msg)
                except Exception as e:
                    msg = f"An error occurred while processing {file_path}: {e}"
                    encrypt_exception_report.append(msg)
        if encrypt_exception_report:
            print("Errors occurred while processing:")
            for msg in encrypt_exception_report:
                print(f"  {msg}")

    if args.decrypt_directory and args.private_key:
        private_key_data = load_file(args.private_key)
        for root, dirs, files in os.walk(args.decrypt_directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith('.fcrptrencrypted'):
                    read_encrypted_data(file_path, private_key_data)

    end_time = time.time()
    duration = end_time - start_time
    print(f"Script execution time: {duration:.2f} seconds")


if __name__ == "__main__":
    main()
