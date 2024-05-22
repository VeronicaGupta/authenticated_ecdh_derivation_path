from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_aes(plaintext, key, iv):
    # Ensure the key is of proper length (e.g., 256 bits for AES-256)
    assert len(key) in [16, 24, 32], "Key must be either 128, 192, or 256 bits"

    # Create an AES cipher object with the key and IV in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create a padder object to handle PKCS7 padding
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

def decrypt_aes(ciphertext, key, iv):
    # Create an AES cipher object with the key and IV in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the data
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Create an unpadder object to handle PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

# # Example usage
# key = os.urandom(32)  # AES-256 key
# print(key)
# plaintext = b"Hello, World! This is a test of AES encryption."

# # Encrypt the plaintext
# ciphertext = encrypt_aes(plaintext, key, key[:16])
# print("Encrypted:", ciphertext)

# # Decrypt the ciphertext
# decrypted_message = decrypt_aes(ciphertext, key, key[:16])
# print("Decrypted:", decrypted_message)
