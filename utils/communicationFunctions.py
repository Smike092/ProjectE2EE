import json
import struct
from utils.AESEncryption import encrypt_with_aes, decrypt_with_aes
from utils.RSAManagement import encrypt_message, decrypt_message
from utils.NumericSignatureAndTimeStamp import sign_message, verify_signature

def send_with_size(conn, data):
    """
    Envoie des données avec une taille préfixée.

    Parameters:
        conn (socket): Le socket de connexion.
        data (bytes): Les données à envoyer (bytes).

    Raises:
        ConnectionError: Si la connexion est fermée de manière inattendue.
    """
    size = len(data)
    conn.sendall(struct.pack('>I', size))  # Envoie la taille des données (4 octets)
    conn.sendall(data)  # Envoie les données


def recv_with_size(conn):
    """
    Reçoit des données avec une taille préfixée.

    Parameters:
        conn (socket): Le socket de connexion.

    Returns:
        bytes: Les données reçues.

    Raises:
        ConnectionError: Si la connexion est fermée ou si les données sont incomplètes.
    """
    raw_size = conn.recv(4)  # Lit la taille (4 octets)
    if not raw_size:
        raise ConnectionError("Connection closed by the remote host.")

    size = struct.unpack('>I', raw_size)[0]  # Décode la taille
    data = conn.recv(size)  # Lit les données
    while len(data) < size:  # Gère les cas où recv ne renvoie pas tout
        data += conn.recv(size - len(data))

    return data


def send_encrypted_message(socket, aes_key, payload):
    try:
        encrypted_payload = encrypt_with_aes(aes_key, json.dumps(payload).encode())
        send_with_size(socket, encrypted_payload)
    except Exception as e:
        raise Exception(f"Failed to send encrypted message: {e}")

def receive_encrypted_message(socket, aes_key):
    try:
        encrypted_response = recv_with_size(socket)
        response = decrypt_with_aes(aes_key, encrypted_response).decode()
        return json.loads(response)
    except Exception as e:
        raise Exception(f"Failed to receive encrypted message: {e}")

