import os
import sys
import base64
import hmac
import hashlib
import gzip
import mmap
import threading
import winreg
import sys
import tkinter as tk
from tkinter import simpledialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from getpass import getpass
import secrets
import pyotp
import datetime
import logging
import stegano
from stegano import lsb
from cryptography.hazmat.primitives.asymmetric import kyber
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import socket
import ssl
import ephem
import time
import math

# Constants for Argon2 configuration
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 2**16  # 64 MB
ARGON2_PARALLELISM = 8
SALT_SIZE = 64  # 512 bits

# Pi to 100 decimal places
PI_100 = 3.1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679

# Logger setup for audit logging
logging.basicConfig(filename='audit.log', level=logging.INFO, format='%(asctime)s - %(message)s')
audit_key = os.urandom(32)

def add_context_menu():
    try:
        for action in ['Encrypt', 'Decrypt']:
            key_path = f'*\\shell\\{action}File'
            key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path)
            winreg.SetValue(key, '', winreg.REG_SZ, f'{action} File')
            command_key = winreg.CreateKey(key, 'command')
            winreg.SetValue(command_key, '', winreg.REG_SZ, f'"{sys.executable}" "{__file__}" {action.lower()} "%1"')
        print("Context menu entries added successfully.")
    except Exception as e:
        print(f"Error adding context menu entries: {e}")

def remove_context_menu():
    try:
        for action in ['Encrypt', 'Decrypt']:
            key_path = f'*\\shell\\{action}File'
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, key_path + '\\command')
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, key_path)
        print("Context menu entries removed successfully.")
    except Exception as e:
        print(f"Error removing context menu entries: {e}")

def planetary_rng_seed():
    current_time = time.time()
    pluto = ephem.Pluto(current_time)
    mercury = ephem.Mercury(current_time)
    
    pluto_ra = float(pluto.ra) * 180 / math.pi
    pluto_dec = float(pluto.dec) * 180 / math.pi
    mercury_ra = float(mercury.ra) * 180 / math.pi
    mercury_dec = float(mercury.dec) * 180 / math.pi
    
    pluto_value = math.pow(pluto_ra, 1/abs(pluto_dec))
    mercury_value = math.pow(mercury_ra, 1/abs(mercury_dec))
    
    result = (pluto_value * mercury_value * mercury_value + PI_100) % 1
    large_int = int(result * (10**50))
    
    return hashlib.sha512(str(large_int).encode()).hexdigest()

def get_random_bytes(length):
    seed = planetary_rng_seed()
    key = seed[:32].encode()
    iv = seed[32:48].encode()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b'\x00' * length)

def encrypt_filename(filename, key):
    return base64.urlsafe_b64encode(AESGCM(key).encrypt(get_random_bytes(12), filename.encode(), None)).decode()

def secure_allocate(size):
    mem = mmap.mmap(-1, size)
    mem.write(get_random_bytes(size))
    return mem

def secure_free(mem):
    mem.seek(0)
    mem.write(b'\x00' * len(mem))
    mem.close()

def threaded_encrypt_part(data_part, key, algorithm, hmac_key):
    if algorithm == 'AES-GCM':
        iv = get_random_bytes(12)
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(iv, data_part, hmac_key)
    elif algorithm == 'ChaCha20-Poly1305':
        nonce = get_random_bytes(12)
        chacha = ChaCha20Poly1305(key)
        encrypted = chacha.encrypt(nonce, data_part, hmac_key)
    else:
        raise ValueError("Unsupported encryption algorithm")
    return encrypted

def derive_key(password, salt):
    kdf = Argon2(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        salt=salt,
        type=Argon2.Type.I,
    )
    return kdf.derive(password.encode())

def generate_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def compress_data(data):
    return gzip.compress(data)

def decompress_data(data):
    return gzip.decompress(data)

def triple_encrypt(data, keys, hmac_key):
    encrypted_data = data
    algorithms = ['AES-GCM', 'ChaCha20-Poly1305', 'AES-GCM']
    for i, algorithm in enumerate(algorithms):
        encrypted_data = threaded_encrypt_part(encrypted_data, keys[i], algorithm, hmac_key)
    return encrypted_data

def log_audit(operation, file_name):
    log_entry = f"{operation} - {file_name}"
    encrypted_log = AESGCM(audit_key).encrypt(get_random_bytes(12), log_entry.encode(), None)
    with open("audit.log", "ab") as log_file:
        log_file.write(encrypted_log)

def encrypt_file(file_path, password, keyfile=None):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        salt = get_random_bytes(SALT_SIZE)
        if keyfile:
            with open(keyfile, 'rb') as kf:
                key = derive_key(password + kf.read().decode(), salt)
        else:
            key = derive_key(password, salt)

        compressed_data = compress_data(data)
        file_hmac = generate_hmac(key, compressed_data)

        keys = [derive_key(password + planetary_rng_seed(), salt) for _ in range(3)]
        encrypted_data = triple_encrypt(compressed_data, keys, file_hmac)

        encrypted_filename = encrypt_filename(os.path.basename(file_path), key)
        encrypted_file_path = os.path.join(os.path.dirname(file_path), encrypted_filename + '.BOB')

        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted_data)

        print(f"File encrypted: {encrypted_file_path}")
        secure_delete(file_path)
        log_audit("ENCRYPT", file_path)

    except Exception as e:
        print(f"Error encrypting file: {e}")

def decrypt_file(file_path, password, keyfile=None):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        salt = data[:SALT_SIZE]
        encrypted = data[SALT_SIZE:]

        if keyfile:
            with open(keyfile, 'rb') as kf:
                key = derive_key(password + kf.read().decode(), salt)
        else:
            key = derive_key(password, salt)

        try:
            keys = [derive_key(password + planetary_rng_seed(), salt) for _ in range(3)]
            decrypted_data = encrypted
            for algorithm in reversed(['AES-GCM', 'ChaCha20-Poly1305', 'AES-GCM']):
                if algorithm == 'AES-GCM':
                    aesgcm = AESGCM(keys.pop())
                    decrypted_data = aesgcm.decrypt(decrypted_data[:12], decrypted_data[12:], None)
                elif algorithm == 'ChaCha20-Poly1305':
                    chacha = ChaCha20Poly1305(keys.pop())
                    decrypted_data = chacha.decrypt(decrypted_data[:12], decrypted_data[12:], None)

        except Exception:
            raise ValueError("Decryption failed or wrong algorithm used")

        decompressed_data = decompress_data(decrypted_data)
        decrypted_file_path = file_path[:-4] if file_path.endswith('.BOB') else file_path + '.decrypted'
        
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decompressed_data)

        print(f"File decrypted: {decrypted_file_path}")
        log_audit("DECRYPT", file_path)

    except Exception as e:
        print(f"Error decrypting file: {e}")

def secure_delete(file_path):
    try:
        with open(file_path, 'ba+') as delfile:
            length = delfile.tell()
        with open(file_path, 'br+b') as delfile:
            delfile.write(get_random_bytes(length))
        os.remove(file_path)
        print(f"Original file {file_path} securely deleted.")
    except Exception as e:
        print(f"Error securely deleting file: {e}")

def gui_password_input():
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    root.destroy()
    return password

def request_2fa():
    secret = 'BASE32SECRET3232'  # Replace with a secure way to generate/share secrets
    totp = pyotp.TOTP(secret)
    code = input("Enter the 2FA code: ")
    if not totp.verify(code):
        raise ValueError("Invalid 2FA code")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == 'install':
            add_context_menu()
        elif sys.argv[1] == 'uninstall':
            remove_context_menu()
        elif sys.argv[1] in ['encrypt', 'decrypt'] and len(sys.argv) > 2:
            password = gui_password_input()
            request_2fa()
            if sys.argv[1] == 'encrypt':
                encrypt_file(sys.argv[2], password)
            else:
                decrypt_file(sys.argv[2], password)
        else:
            print("Invalid option")
    else:
        print("Usage:")
        print("  install   - Add context menu entries")
        print("  uninstall - Remove context menu entries")
        print("  encrypt <file> - Encrypt the specified file")
        print("  decrypt <file> - Decrypt the specified file")
