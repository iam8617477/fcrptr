import os
import argparse
import sys
import random
import string
import base64
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crpt.sync_encryptor import SyncEncryptor
from crpt.rsa_encryptor import RSAEncryptor
from libs import FileReadWrite


class FileCrypter:
    file = FileReadWrite
    encrypt_exception_report = list()

    def __init__(self, public_key=None):
        self.sync_encryptor = SyncEncryptor()
        self.rsa_encryptor = RSAEncryptor()
        self.public_key = public_key

    @staticmethod
    def generate_salt(length=8):
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def encrypt_file(self, file_path, passphrase):
        content = self.file.read(file_path, mode='rb')
        encrypted_content, salt = self.sync_encryptor.encrypt(content, passphrase=passphrase, is_bytes=True)
        encrypted_passphrase = self.rsa_encryptor.encrypt_with_public_key(
            self.public_key, passphrase
        )
        encrypted_content_base64 = base64.b64encode(encrypted_content).decode('utf-8')
        encrypted_passphrase_base64 = base64.b64encode(encrypted_passphrase).decode('utf-8')
        data = {
            'timestamp': int(time.time()),
            'public_key': self.public_key,
            'filename': os.path.basename(file_path),
            'path': os.path.dirname(file_path),
            'encrypted_content': encrypted_content_base64,
            'encrypted_passphrase': encrypted_passphrase_base64,
        }
        self.file.write_json(file_path, data)
        output_path = f'{file_path}.fcrptrencrypted'
        os.rename(file_path, output_path)
        return f'Data encrypted and saved to: {output_path}. Original file {file_path}.'

    def decrypt_file(self, file_path, private_key):
        data = self.file.read_json(file_path)
        encrypted_passphrase = base64.b64decode(data['encrypted_passphrase'])
        passphrase = self.rsa_encryptor.decrypt_with_private_key(private_key, encrypted_passphrase)
        encrypted_content = base64.b64decode(data['encrypted_content'])
        decrypted_content = self.sync_encryptor.decrypt(encrypted_content, passphrase=passphrase, is_bytes=True)
        self.file.write(file_path, decrypted_content, mode='wb')
        original_file_path = file_path[:-len('.fcrptrencrypted')]
        os.rename(file_path, original_file_path)
        return f'Data decrypted and saved back to: {original_file_path}'

    @staticmethod
    def get_files(directory):
        return (
            os.path.join(root, file)
            for root, _, files in os.walk(directory)
            for file in files
        )

    @staticmethod
    def task_cryptor(func_cryptor, *args):
        return func_cryptor(*args)

    def task_cryptor_callback(self, future, file_path):
        try:
            msg = future.result()
            print(msg)
        except PermissionError:
            msg = f'Permission denied for file: {file_path}. Skipping...'
            self.encrypt_exception_report.append(msg)
        except Exception as e:
            msg = f'An error occurred while processing {file_path}: {e}'
            self.encrypt_exception_report.append(msg)

    def main_thread(self, task, func, *args):
        try:
            msg = task(func, *args)
            print(msg)
        except PermissionError:
            msg = f'Permission denied for file: {args[0]}. Skipping...'
            self.encrypt_exception_report.append(msg)
        except Exception as e:
            msg = f'An error occurred while processing {args[0]}: {e}'
            self.encrypt_exception_report.append(msg)

    def print_exception_report(self):
        if self.encrypt_exception_report:
            print('Errors occurred while processing:')
            for msg in self.encrypt_exception_report:
                print(f'  {msg}')


def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(description='Encrypt or decrypt files.')
    parser.add_argument('--use-threading', type=bool, required=False, help='Use threading')
    parser.add_argument('--encrypt-directory', type=str, required=False,
                        help='Path to the directory to encrypt files.')
    parser.add_argument('--encrypt-file', type=str, help='Path to the specific file to encrypt.')
    parser.add_argument('--decrypt-directory', type=str, required=False,
                        help='Path to the directory to decrypt files.')
    parser.add_argument('--decrypt-file', type=str, help='Path to the specific file to decrypt.')
    parser.add_argument('--public-key', type=str, required=False,
                        help='Path to the file containing the public key for encryption.')
    parser.add_argument('--private-key', type=str, required=False,
                        help='Path to the file containing the private key for decryption.')
    parser.add_argument('--passphrase', type=str, required=False, help='Passphrase for encryption.')
    parser.add_argument('--generate_keys', action='store_true',
                        help='Generate RSA keys. Optionally provide a passphrase.')

    args = parser.parse_args()

    if args.generate_keys:
        print(f'Generating RSA keys')
        rsa_encryptor = RSAEncryptor()
        private_key, public_key = rsa_encryptor.generate_keys()
        private_key_path = 'private_key.pem'
        public_key_path = 'public_key.pem'
        FileCrypter.file.write(private_key_path, private_key)
        FileCrypter.file.write(public_key_path, public_key)
        print('Successfully created the RSA key files.')

    if args.encrypt_file and args.public_key and args.passphrase:
        public_key_data = FileCrypter.file.read(args.public_key)
        fc = FileCrypter(public_key_data)
        encrypted_msg = fc.encrypt_file(args.encrypt_file, args.passphrase)
        print(encrypted_msg)

    if args.decrypt_file and args.private_key:
        private_key_data = FileCrypter.file.read(args.private_key)
        fc = FileCrypter()
        decrypted_msg = fc.decrypt_file(args.decrypt_file, private_key_data)
        print(decrypted_msg)

    if args.encrypt_directory and args.public_key and args.passphrase:
        public_key_data = FileCrypter.file.read(args.public_key)
        fc = FileCrypter(public_key_data)
        if args.use_threading:
            print('Using threading module')
            from concurrent.futures import ThreadPoolExecutor
            from functools import partial
            with ThreadPoolExecutor() as executor:
                for file_path in fc.get_files(args.encrypt_directory):
                    f = executor.submit(fc.task_cryptor, fc.encrypt_file, file_path, args.passphrase)
                    f.add_done_callback(partial(fc.task_cryptor_callback, file_path=file_path))
        else:
            for file_path in fc.get_files(args.encrypt_directory):
                fc.main_thread(fc.task_cryptor, fc.encrypt_file, file_path, args.passphrase)
        fc.print_exception_report()

    if args.decrypt_directory and args.private_key:
        private_key_data = FileCrypter.file.read(args.private_key)
        fc = FileCrypter()
        if args.use_threading:
            print('Using threading module')
            from concurrent.futures import ThreadPoolExecutor
            from functools import partial
            with ThreadPoolExecutor() as executor:
                for file_path in fc.get_files(args.decrypt_directory):
                    if file_path.endswith('.fcrptrencrypted'):
                        f = executor.submit(fc.task_cryptor, fc.decrypt_file, file_path, private_key_data)
                        f.add_done_callback(partial(fc.task_cryptor_callback, file_path=file_path))
        else:
            for file_path in fc.get_files(args.decrypt_directory):
                fc.main_thread(fc.task_cryptor, fc.decrypt_file, file_path, private_key_data)
        fc.print_exception_report()

    end_time = time.time()
    duration = end_time - start_time
    print(f'Script execution time: {duration:.2f} seconds')


if __name__ == '__main__':
    main()
