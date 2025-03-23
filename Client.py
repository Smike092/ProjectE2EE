import threading
from datetime import datetime
import socket
import json
from os import urandom
from cryptography.hazmat.primitives import serialization
from utils.AESEncryption import encrypt_with_aes, decrypt_with_aes
from utils.RSAManagement import generate_rsa_keypair, encrypt_message, decrypt_message
from utils.NumericSignatureAndTimeStamp import sign_message, verify_signature, is_timestamp_within_5_minutes
from utils.randomPhoneNumber import choose_random_phone_number
from utils.communicationFunctions import send_with_size, recv_with_size

class Client:
    def __init__(self, host, port_of_server, port_to_listen, server_public_key, name, phone_number= choose_random_phone_number()):
        self.auth_token = None
        self.host = host
        self.port = port_of_server
        self.port_to_listen = port_to_listen
        self.server_public_key = server_public_key

        self.client_socket_to_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket_listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.phone_number = phone_number
        self.server_client_aes_key = urandom(32)
        self.client_private_key, self.client_public_key = generate_rsa_keypair()
        self.name = name
        self.contacts = {}

    def find_a_port(self):
        while True:
            try:
                self.client_socket_listening.bind((self.host, self.port_to_listen))
                self.client_socket_listening.listen(10)
                print(f"[{self.name}] Listening on port {self.port_to_listen}")
                break
            except OSError:
                print(f"Port {self.port_to_listen} already in use. Trying next...")
                self.port_to_listen += 1

    def start_listening(self):
        listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        listener_thread.start()

    def listen_for_messages(self):
        conn, addr = self.client_socket_listening.accept()
        print(f"[{self.name}] Connection accepted from {addr}\n")
        while True:
            try:
                encrypted_response = recv_with_size(conn)
                response_payload = json.loads(decrypt_with_aes(self.server_client_aes_key, encrypted_response).decode())
                self.handle_incoming_response(response_payload)
            except Exception as e:
                print(f"[{self.name}] Listener stopped: {e}")
                break

    def handle_incoming_response(self, response_payload):
        if response_payload["RESPONSE"] == "MESSAGE":
            self.handle_message_received(response_payload)
        elif response_payload["RESPONSE"] == "MESSAGE_DELIVERED":
            self.handle_message_sent_to_destination(response_payload)

    def connect_to_server(self):
        print(f"[Info][{self.name}] Starting client...")
        self.client_socket_to_send.connect((self.host, self.port))
        print(f"[Info][{self.name}] Connected to the server at {self.host}:{self.port}")


    def send_request_registration_to_server(self):
        print(f"[Step 1][{self.name}] Sending registration request to the server.")

        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.find_a_port()
        public_key_data = self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        first_part = {
            "REQUEST": "REGISTER",
            "AES_KEY": self.server_client_aes_key.hex(),
        }


        second_part = {
            "PHONE_SOURCE": self.phone_number,
            "NAME": self.name,
            "PUBLIC_KEY": public_key_data.hex(),
            "PORT_LISTENER" : self.port_to_listen,
            "TIMESTAMP": timestamp,
            "SIGNATURE": sign_message(
                self.client_private_key,
                json.dumps({
                    "REQUEST": "REGISTER",
                    "AES_KEY": self.server_client_aes_key.hex(),
                    "PHONE_SOURCE": self.phone_number,
                    "NAME": self.name,
                    "PUBLIC_KEY": public_key_data.hex(),
                    "TIMESTAMP": timestamp
                }).encode()
            ).hex()
        }

        encrypted_first_part = encrypt_message(self.server_public_key, json.dumps(first_part).encode())
        encrypted_second_part = encrypt_with_aes(self.server_client_aes_key, json.dumps(second_part).encode())

        full_packet = {
            "FIRST_PART": encrypted_first_part.hex(),
            "SECOND_PART": encrypted_second_part.hex(),
        }

        # Send the packet to the server
        send_with_size(self.client_socket_to_send, json.dumps(full_packet).encode())
        print(f"[Info][{self.name}] Registration Request sent. Waiting for acknowledgment from server...")


    def await_secret_code_from_server(self):
        encrypted_response = recv_with_size(self.client_socket_to_send)
        response = decrypt_with_aes(self.server_client_aes_key, encrypted_response).decode()
        response_payload = json.loads(response)
        secret_code = response_payload.get("DATA")
        if not secret_code:
            print(f"[Error][{self.name}] Failed to receive secret code from the server.")
            self.client_socket_to_send.close()
            exit(1)
        print(f"[Info][{self.name}] Secret code received: {secret_code}")
        return secret_code

    def send_back_secret_code(self, secret_code):
        print(f"[Step 3][{self.name}] Sending secret code back to the server for validation.")
        secret_code_request = {
            "REQUEST": "REGISTER",
            "PHONE": self.phone_number,
            "DATA": secret_code
        }
        full_request = json.dumps(secret_code_request).encode()
        encrypted_request = encrypt_with_aes(self.server_client_aes_key, full_request)
        send_with_size(self.client_socket_to_send, encrypted_request)
        print(f"[Info][{self.name}] Secret code sent. Waiting for authentication token...")

    def await_token_authentication(self):
        encrypted_response = recv_with_size(self.client_socket_to_send)
        response_payload = json.loads(decrypt_with_aes(self.server_client_aes_key, encrypted_response).decode())

        auth_token = response_payload.get("TOKEN")
        signature = bytes.fromhex(response_payload.get("SIGNATURE"))
        timestamp = response_payload.get("TIMESTAMP")

        if not auth_token:
            print(f"[Error][{self.name}] Failed to receive authentication token from the server.")
            self.client_socket_to_send.close()
            exit(1)

        payload_to_verify = json.dumps({
            "RESPONSE": "TOKEN",
            "TOKEN": auth_token,
            "TIMESTAMP": timestamp
        }).encode()

        if not verify_signature(self.server_public_key, payload_to_verify, signature):
            raise ValueError("Invalid signature received from client.")

        if not is_timestamp_within_5_minutes(timestamp):
            raise ValueError("Invalid timestamp received from client.")

        print(f"[Success][{self.name}] Registration completed. Authentication token: {auth_token}\n")
        return auth_token

    def register(self):
        self.connect_to_server()
        self.send_request_registration_to_server()
        secret_code = self.await_secret_code_from_server()
        self.send_back_secret_code(secret_code)
        self.auth_token = self.await_token_authentication()
        self.start_listening()

    def disconnect(self):
        try:
            print(f"\n[Info][{self.name}] Notifying server to switch status to offline...")

            # Préparer et envoyer une requête de déconnexion
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            first_part = {
                "REQUEST": "DISCONNECT",
                "PHONE_SOURCE": self.phone_number
            }

            second_part = {
                "TOKEN": self.auth_token,
                "TIMESTAMP": timestamp,
                "SIGNATURE": sign_message(
                    self.client_private_key,
                    json.dumps({
                        "REQUEST": "DISCONNECT",
                        "PHONE_SOURCE": self.phone_number,
                        "TOKEN": self.auth_token,
                        "TIMESTAMP": timestamp
                    }).encode()
                ).hex()
            }

            encrypted_first_part = encrypt_message(self.server_public_key, json.dumps(first_part).encode())
            encrypted_second_part = encrypt_with_aes(self.server_client_aes_key, json.dumps(second_part).encode())

            full_packet = {
                "FIRST_PART": encrypted_first_part.hex(),
                "SECOND_PART": encrypted_second_part.hex(),
            }

            send_with_size(self.client_socket_to_send, json.dumps(full_packet).encode())
            print(f"[Success][{self.name}] Server updated: Client is now offline.\n")

        except Exception as e:
            print(f"[Error][{self.name}] Failed to notify server: {e}")

    def reconnect(self):
        try:
            print(f"\n[Info][{self.name}] Notifying server to switch status to online...")

            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            first_part = {
                "REQUEST": "RECONNECT",
                "PHONE_SOURCE": self.phone_number
            }

            second_part = {
                "TOKEN": self.auth_token,
                "TIMESTAMP": timestamp,
                "SIGNATURE": sign_message(
                    self.client_private_key,
                    json.dumps({
                        "REQUEST": "RECONNECT",
                        "PHONE_SOURCE": self.phone_number,
                        "TOKEN": self.auth_token,
                        "TIMESTAMP": timestamp
                    }).encode()
                ).hex()
            }

            encrypted_first_part = encrypt_message(self.server_public_key, json.dumps(first_part).encode())
            encrypted_second_part = encrypt_with_aes(self.server_client_aes_key, json.dumps(second_part).encode())

            full_packet = {
                "FIRST_PART": encrypted_first_part.hex(),
                "SECOND_PART": encrypted_second_part.hex(),
            }

            send_with_size(self.client_socket_to_send, json.dumps(full_packet).encode())
            print(f"[Success][{self.name}] Server updated: Client is now online.\n")

        except Exception as e:
            print(f"[Error][{self.name}] Failed to notify server: {e}")


    def get_public_key(self, target_phone):

        try:
            print(f"[Info][{self.name}] Requesting public key of {target_phone}.")
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            first_part = {
                "REQUEST": "GET_PUBLIC_KEY",
                "PHONE_SOURCE": self.phone_number,
                "TARGET_PHONE": target_phone
            }
            second_part = {
                "TOKEN": self.auth_token,
                "TIMESTAMP": timestamp,
                "SIGNATURE": sign_message(
                    self.client_private_key,
                    json.dumps({
                        "REQUEST": "GET_PUBLIC_KEY",
                        "PHONE_SOURCE": self.phone_number,
                        "TARGET_PHONE": target_phone,
                        "TOKEN": self.auth_token,
                        "TIMESTAMP": timestamp
                    }).encode()
                ).hex()
            }

            encrypted_first_part = encrypt_message(self.server_public_key, json.dumps(first_part).encode())
            encrypted_second_part = encrypt_with_aes(self.server_client_aes_key, json.dumps(second_part).encode())

            full_packet = {
                "FIRST_PART": encrypted_first_part.hex(),
                "SECOND_PART": encrypted_second_part.hex(),
            }

            send_with_size(self.client_socket_to_send, json.dumps(full_packet).encode())

            encrypted_response = recv_with_size(self.client_socket_to_send)
            response = decrypt_with_aes(self.server_client_aes_key, encrypted_response).decode()
            response_payload = json.loads(response)

            if response_payload["RESPONSE"] != "PUBLIC_KEY":
                print(f"[Error][{self.name}] Unexpected response from server.")
                exit(1)

            signature = bytes.fromhex(response_payload["SIGNATURE"])

            if not verify_signature(self.server_public_key, json.dumps({
                "RESPONSE": response_payload["RESPONSE"],
                "TARGET_PHONE": response_payload["TARGET_PHONE"],
                "DATA": response_payload["DATA"],
                "TIMESTAMP": response_payload["TIMESTAMP"]
            }).encode(), signature):
                print(f"[Error][{self.name}] Signature verification failed.")
                exit(1)

            if not is_timestamp_within_5_minutes(response_payload["TIMESTAMP"]):
                raise ValueError("Invalid timestamp received from client.")

            public_key_data = bytes.fromhex(response_payload["DATA"])

            print(f"[Info][{self.name}] Public key for {target_phone} successfully received.")
            self.contacts[target_phone] = {"public key": serialization.load_pem_public_key(public_key_data)}

        except Exception as e:
            print(f"[Error][{self.name}] Failed to get public key: {e}")
            exit(1)


    def send_message(self, target_phone, message):
        # Check that the key is available, if not ask for it
        if target_phone not in self.contacts:
            self.get_public_key(target_phone)

        print(f"[Info][{self.name}] Preparing to send a message to {target_phone}.")

        # STEP 1: Generate an AES key for the client_to_client communication
        client_to_client_aes_key = urandom(32)

        # STEP 2: Encrypt the message with the AES key generated
        encrypted_message = encrypt_with_aes(client_to_client_aes_key, message.encode())

        # Step 4: Encrypt the AES key with the public key of the client destination
        encrypted_aes_key = encrypt_message(
            self.contacts[target_phone]["public key"],
            client_to_client_aes_key
        ).hex()

        first_part = {
            "REQUEST": "MESSAGE",
            "TOKEN": self.auth_token,
        }
        encrypted_first_part = encrypt_message(self.server_public_key, json.dumps(first_part).encode())

        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Prepare the fields for the server
        second_part = {
            "PHONE_NUMBER": self.phone_number,
            "TARGET_PHONE": target_phone,
            "AES_KEY": encrypted_aes_key,
            "DATA": encrypted_message.hex(),
            "TIMESTAMP": timestamp,
            "SIGNATURE": sign_message(
                self.client_private_key,
                json.dumps({
                    "REQUEST": "MESSAGE",
                    "TOKEN": self.auth_token,
                    "PHONE_NUMBER": self.phone_number,
                    "TARGET_PHONE": target_phone,
                    "AES_KEY": encrypted_aes_key,
                    "DATA": encrypted_message.hex(),
                    "TIMESTAMP": timestamp
                }).encode()
            ).hex()
        }
        encrypted_second_part = encrypt_with_aes(self.server_client_aes_key, json.dumps(second_part).encode())

        full_packet = {
            "FIRST_PART": encrypted_first_part.hex(),
            "SECOND_PART": encrypted_second_part.hex(),
        }

        send_with_size(self.client_socket_to_send, json.dumps(full_packet).encode())
        print(f"[Info][{self.name}] Message sent to server for delivery.")

    def handle_message_received(self, response_payload):
        try:
            source_phone = response_payload["SOURCE_PHONE"]
            encrypted_aes_key = bytes.fromhex(response_payload["AES_KEY"])
            encrypted_message = bytes.fromhex(response_payload["DATA"])
            timestamp = response_payload["TIMESTAMP"]
            signature = bytes.fromhex(response_payload["SIGNATURE"])

            if not is_timestamp_within_5_minutes(timestamp):
                print(f"[Error][{self.name}] Received message with invalid timestamp.")
                return

            aes_key = decrypt_message(self.client_private_key, encrypted_aes_key)

            message = decrypt_with_aes(aes_key, encrypted_message).decode()

            payload_to_verify = json.dumps({
                "RESPONSE": "MESSAGE",
                "SOURCE_PHONE": response_payload["SOURCE_PHONE"],
                "AES_KEY": response_payload["AES_KEY"],
                "DATA": response_payload["DATA"],
                "TIMESTAMP": timestamp
            }).encode()

            if not verify_signature(self.server_public_key, payload_to_verify, signature):
                print(f"[Error][{self.name}] Signature verification failed for message from {source_phone}.")
                return

            print(f"\n[{self.name}] Message from {source_phone}: {message}\n")

        except Exception as e:
            print(f"[Error][{self.name}] Failed to handle received message: {e}")

    def handle_message_sent_to_destination(self, response_payload):
        try:
            target_phone = response_payload["TARGET_PHONE"]
            data = response_payload["DATA"]
            timestamp = response_payload["TIMESTAMP"]
            signature = bytes.fromhex(response_payload["SIGNATURE"])

            payload_to_verify = json.dumps({
                "RESPONSE": "MESSAGE_DELIVERED",
                "TARGET_PHONE": target_phone,
                "DATA": data,
                "TIMESTAMP": timestamp
            }).encode()

            if not verify_signature(self.server_public_key, payload_to_verify, signature):
                print(f"[Error][{self.name}] Invalid acknowledgment signature received.")
                return

            if not is_timestamp_within_5_minutes(timestamp):
                print(f"[Error][{self.name}] Acknowledgment received with invalid timestamp.")
                return

            print(f"[Success][{self.name}] Message successfully delivered to "
                  f"{target_phone}.")
            print(f"[Info][{self.name}] Acknowledgment data: {data}\n")

        except Exception as e:
            print(f"[Error][{self.name}] Failed to process message delivery acknowledgment: {e}")
