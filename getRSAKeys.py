from utils.RSAManagement import generate_rsa_keypair
from cryptography.hazmat.primitives import serialization
import os

def get_keys_in_secondary_memory():
    private_key_file = "private_key.pem"
    public_key_file = "public_key.pem"

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, "rb") as priv_file:
            private_key = serialization.load_pem_private_key(
                priv_file.read(),
                password=None
            )
        with open(public_key_file, "rb") as pub_file:
            public_key = serialization.load_pem_public_key(pub_file.read())
        print("Keys charged from the files.\n")
    else:
        private_key, public_key = generate_rsa_keypair()

        with open(private_key_file, "wb") as priv_file:
            priv_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open(public_key_file, "wb") as pub_file:
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        print("New generated keys and stored.\n")

    return private_key, public_key