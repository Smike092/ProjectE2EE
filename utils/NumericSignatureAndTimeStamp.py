import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta

"""
A private key can be used to sign a message. 
This allows anyone with the public key to verify that the message 
was created by someone who possesses the corresponding private key. 
RSA signatures require a specific hash function, and padding to be used.
Here is an example of signing message using RSA, with a secure hash function and padding.
"""


def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        print("Error during RSA signature verification")
        exit(1)


def is_timestamp_within_5_minutes(timestamp):
    """
    Check if a timestamp is within 5 minutes of the current UTC time.
    :param timestamp: The timestamp string in the format '%Y-%m-%dT%H:%M:%SZ'.
    :return: True if the timestamp is within 5 minutes, False otherwise.
    """
    try:
        # Convert the string to a datetime object
        timestamp_dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        # Get the current UTC time
        current_time = datetime.utcnow()
        # Check if the timestamp is within 5 minutes
        return abs((current_time - timestamp_dt).total_seconds()) <= 300
    except ValueError:
        # If the timestamp format is invalid
        return False



def create_signed_payload(private_key, payload):
    try:
        payload_bytes = json.dumps(payload).encode()
        signature = sign_message(private_key, payload_bytes)
        payload["SIGNATURE"] = signature.hex()
        return payload
    except Exception as e:
        raise Exception(f"Failed to create signed payload: {e}")

def verify_signed_payload(public_key, payload):
    try:
        signature = bytes.fromhex(payload.pop("SIGNATURE"))
        payload_bytes = json.dumps(payload).encode()
        return verify_signature(public_key, payload_bytes, signature)
    except Exception as e:
        raise Exception(f"Failed to verify signed payload: {e}")
