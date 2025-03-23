from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom


def encrypt_with_aes(key, plaintext):
    iv = urandom(16)  # Vecteur d'initialisation
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext  # Ajouter l'IV au début pour le déchiffrement


def decrypt_with_aes(key, ciphertext):
    iv = ciphertext[:16]  # Extraire l'IV
    actual_ciphertext = ciphertext[16:]  # Données chiffrées
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()