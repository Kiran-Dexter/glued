#!/usr/bin/env python3
import argparse
import os
import secrets
import sys
import getpass
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

class EncryptionError(Exception):
    pass

class DecryptionError(Exception):
    pass

def derive_master_key(passphrase: bytes, salt: bytes) -> bytes:
    try:
        master_key = hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=2,
            memory_cost=2**16,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        return master_key
    except Exception as e:
        logging.error("Failed to derive master key: %s", e)
        raise EncryptionError("Master key derivation failed") from e

def encrypt_data(key: bytes, plaintext: bytes) -> (bytes, bytes):
    try:
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext
    except Exception as e:
        logging.error("Encryption error: %s", e)
        raise EncryptionError("Data encryption failed") from e

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        logging.error("Decryption error: %s", e)
        raise DecryptionError("Data decryption failed") from e

def encrypt_file(input_file: str, output_file: str, file_key: bytes) -> None:
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except Exception as e:
        logging.error("Error reading input file: %s", e)
        raise EncryptionError("Could not read input file") from e

    try:
        aesgcm = AESGCM(file_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
    except Exception as e:
        logging.error("Error encrypting file data: %s", e)
        raise EncryptionError("File encryption failed") from e

    try:
        with open(output_file, "wb") as f:
            f.write(nonce + ciphertext)
    except Exception as e:
        logging.error("Error writing encrypted file: %s", e)
        raise EncryptionError("Could not write encrypted file") from e

def decrypt_file(input_file: str, output_file: str, file_key: bytes) -> None:
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except Exception as e:
        logging.error("Error reading encrypted file: %s", e)
        raise DecryptionError("Could not read encrypted file") from e

    try:
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(file_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        logging.error("Error decrypting file data: %s", e)
        raise DecryptionError("File decryption failed") from e

    try:
        with open(output_file, "wb") as f:
            f.write(plaintext)
    except Exception as e:
        logging.error("Error writing decrypted file: %s", e)
        raise DecryptionError("Could not write decrypted file") from e

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files with AES-GCM and Argon2-based key derivation."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the file")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the file")
    parser.add_argument("--input", required=True, help="Path to input file")
    parser.add_argument("--output", required=True, help="Path to output file")
    parser.add_argument("--keyfile", required=True, help="Path to key file (for storing or reading the encrypted file key)")
    parser.add_argument("-p", "--pass", dest="password", help="Master passphrase (WARNING: passing a password in plaintext may be insecure)")
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.password:
        passphrase = args.password.encode()
    else:
        try:
            passphrase = getpass.getpass("Enter master passphrase: ").encode()
        except Exception as e:
            logging.error("Error reading passphrase: %s", e)
            sys.exit(1)

    if args.encrypt:
        try:
            file_key = secrets.token_bytes(32)
            encrypt_file(args.input, args.output, file_key)
        except EncryptionError as ee:
            logging.critical("Encryption process failed: %s", ee)
            sys.exit(1)

        try:
            salt = secrets.token_bytes(16)
            master_key = derive_master_key(passphrase, salt)
            nonce, encrypted_file_key = encrypt_data(master_key, file_key)
        except EncryptionError as ee:
            logging.critical("Key encryption failed: %s", ee)
            sys.exit(1)

        try:
            with open(args.keyfile, "wb") as kf:
                kf.write(salt + nonce + encrypted_file_key)
        except Exception as e:
            logging.error("Error writing key file: %s", e)
            sys.exit(1)

        try:
            os.remove(args.input)
        except Exception as e:
            logging.error("Error deleting original file: %s", e)
            sys.exit(1)

        print("Encryption completed successfully.")

    elif args.decrypt:
        try:
            with open(args.keyfile, "rb") as kf:
                key_data = kf.read()
            salt = key_data[:16]
            nonce = key_data[16:28]
            ciphertext = key_data[28:]
        except Exception as e:
            logging.error("Error reading or parsing key file: %s", e)
            sys.exit(1)

        try:
            master_key = derive_master_key(passphrase, salt)
            file_key = decrypt_data(master_key, nonce, ciphertext)
        except DecryptionError as de:
            logging.critical("Failed to retrieve file key: %s", de)
            sys.exit(1)

        try:
            decrypt_file(args.input, args.output, file_key)
        except DecryptionError as de:
            logging.critical("File decryption failed: %s", de)
            sys.exit(1)

        print("Decryption completed successfully.")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logging.critical("Unhandled error occurred: %s", exc)
        sys.exit(1)
