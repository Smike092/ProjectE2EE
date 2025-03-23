import copy
import json
import secrets
import socket
import threading
import time
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from utils.AESEncryption import encrypt_with_aes, decrypt_with_aes
from utils.NumericSignatureAndTimeStamp import sign_message, is_timestamp_within_5_minutes, verify_signature
from utils.communicationFunctions import recv_with_size, send_with_size
from utils.RSAManagement import decrypt_message
import ConnectionManager


def generate_secret_code():
    return f"{secrets.randbelow(10 ** 6):06}"

def sendBySecureChannel(conn, client_server_aes_key, secret_code):
    encrypted_secret_code = encrypt_with_aes(client_server_aes_key, json.dumps({"DATA": secret_code}).encode())
    send_with_size(conn, encrypted_secret_code)


class MessageHandler:
    def __init__(self, manager, server_private_key):
        self.host = 'localhost'
        self.manager = manager
        self.server_private_key = server_private_key

    def connect_to_client(self, phone_number):
        print(f"[Info][{self.manager.get_name(phone_number)}] "
              f"Starting connection to client's listener ...")
        port_of_client_listener = self.manager.get_port_address(phone_number)
        self.manager.get_socket_to_send(phone_number).connect((self.host, port_of_client_listener))
        print(f"[Info][{self.manager.get_name(phone_number)}] Connected to the server at "
              f"{self.host}:{port_of_client_listener}")

    def send_acknowledgment(self, phone_number, aes_key, target_phone, data, private_key):
        try:
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            ack_payload = {
                "RESPONSE": "MESSAGE_DELIVERED",
                "TARGET_PHONE": target_phone,
                "DATA": data,
                "TIMESTAMP": timestamp
            }
            ack_signature = sign_message(private_key, json.dumps(ack_payload).encode()).hex()
            ack_payload["SIGNATURE"] = ack_signature

            encrypted_ack = encrypt_with_aes(aes_key, json.dumps(ack_payload).encode())
            send_with_size(self.manager.get_socket_to_send(phone_number), encrypted_ack)

            print(f"[Info] Acknowledgment for message sent to "
                  f"{self.manager.get_name(phone_number)}.\n")
        except Exception as e:
            print(f"[Error] Failed to send acknowledgment: {e}")

    def handle_register_request(self, conn, encrypted_first_part, encrypted_second_part):
        try:
            first_part = json.loads(decrypt_message(self.server_private_key, encrypted_first_part).decode())
            client_server_aes_key = bytes.fromhex(first_part["AES_KEY"])

            second_part = json.loads(decrypt_with_aes(client_server_aes_key, encrypted_second_part).decode())
            public_key_data = bytes.fromhex(second_part["PUBLIC_KEY"])
            client_public_key = serialization.load_pem_public_key(public_key_data)
            signature = bytes.fromhex(second_part["SIGNATURE"])
            timestamp = second_part["TIMESTAMP"]

            payload_to_verify = json.dumps({
                "REQUEST": "REGISTER",
                "AES_KEY": first_part["AES_KEY"],
                "PHONE_SOURCE": second_part["PHONE_SOURCE"],
                "NAME": second_part["NAME"],
                "PUBLIC_KEY": second_part["PUBLIC_KEY"],
                "TIMESTAMP": second_part["TIMESTAMP"]
            }).encode()

            if not verify_signature(client_public_key, payload_to_verify, signature):
                raise ValueError("Invalid signature received from client.")

            if not is_timestamp_within_5_minutes(timestamp):
                raise ValueError("Invalid timestamp received from client.")

            phone_number = second_part["PHONE_SOURCE"]
            name = second_part["NAME"]

            if self.manager.is_phone_number_present(phone_number):
                raise ValueError(f"Phone number {phone_number} already registered.")

            client_port_to_send = second_part["PORT_LISTENER"]

            secret_code = generate_secret_code()
            sendBySecureChannel(conn, client_server_aes_key, secret_code)

            encrypted_request = recv_with_size(conn)
            decrypted_request = decrypt_with_aes(client_server_aes_key, encrypted_request).decode()
            request_payload = json.loads(decrypted_request)

            if request_payload["DATA"] != secret_code:
                raise ValueError("Secret code mismatch.")

            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            auth_token = secrets.token_hex(16)

            payload_to_sign = json.dumps({ "RESPONSE": "TOKEN", "TOKEN": auth_token, "TIMESTAMP": timestamp}).encode()
            response_payload = {
                "RESPONSE": "TOKEN",
                "TOKEN": auth_token,
                "TIMESTAMP": timestamp,
                "SIGNATURE": sign_message(self.server_private_key, payload_to_sign).hex()
            }

            encrypted_response = encrypt_with_aes(client_server_aes_key, json.dumps(response_payload).encode())
            send_with_size(conn,encrypted_response)

            self.manager.add_client(phone_number, name, client_server_aes_key, client_public_key,
                                    auth_token, client_port_to_send)

            self.connect_to_client(phone_number)

            print(f"[Success][{self.manager.get_name(phone_number)}] Registration completed.\n")

        except Exception as e:
            print(f"[Error] Registration failed: {e}")
            exit(1)

    def handle_get_public_key_request(self, conn, encrypted_first_part, encrypted_second_part):
        try:
            first_part = json.loads(decrypt_message(self.server_private_key, encrypted_first_part).decode())
            requesting_phone = first_part["PHONE_SOURCE"]
            second_part = json.loads(decrypt_with_aes(self.manager.get_aes_key(requesting_phone),
                                                      encrypted_second_part).decode())
            target_phone = first_part["TARGET_PHONE"]

            payload_to_verify = json.dumps({
                "REQUEST": "GET_PUBLIC_KEY",
                "PHONE_SOURCE": first_part["PHONE_SOURCE"],
                "TARGET_PHONE": first_part["TARGET_PHONE"],
                "TOKEN": second_part["TOKEN"],
                "TIMESTAMP": second_part["TIMESTAMP"]
            }).encode()

            if not verify_signature(self.manager.get_public_client_key(requesting_phone), payload_to_verify,
                                    bytes.fromhex(second_part["SIGNATURE"])):
                raise ValueError("Invalid signature received from client.")

            if not is_timestamp_within_5_minutes(second_part["TIMESTAMP"]):
                raise ValueError("Invalid timestamp received from client.")

            if not second_part["TOKEN"] == self.manager.get_auth_token(requesting_phone):
                raise ValueError("Invalid token from client.")

            if target_phone not in self.manager.clients:
                raise ValueError(f"Target phone {target_phone} not found.")

            print(f"[Info] {self.manager.get_name(requesting_phone)} requested "
                  f"{self.manager.get_name(target_phone)}'s public key.")

            target_public_key = self.manager.get_public_client_key(target_phone)
            public_key_data = target_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            response_payload = {
                "RESPONSE": "PUBLIC_KEY",
                "TARGET_PHONE": target_phone,
                "DATA": public_key_data.hex(),
                "TIMESTAMP": timestamp
            }

            signature = sign_message(self.server_private_key, json.dumps(response_payload).encode())
            response_payload["SIGNATURE"] = signature.hex()

            aes_key = self.manager.get_aes_key(requesting_phone)
            encrypted_response = encrypt_with_aes(aes_key, json.dumps(response_payload).encode())
            send_with_size(conn, encrypted_response)

            print(f"[Info] Public key for {self.manager.get_name(target_phone)}"
                  f" sent to {self.manager.get_name(requesting_phone)}.\n")
        except Exception as e:
            print(f"[Error] Public key request failed: {e}")

    def transfer_message_to_client(self, message_data):

        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        response_payload = {
            "RESPONSE": "MESSAGE",
            "SOURCE_PHONE": message_data[0],
            "AES_KEY": message_data[2],
            "DATA": message_data[3],
            "TIMESTAMP": timestamp
        }

        payload_to_sign = json.dumps(response_payload).encode()

        response_signature = sign_message(self.server_private_key, payload_to_sign).hex()
        response_payload["SIGNATURE"] = response_signature

        encrypted_response = encrypt_with_aes(
            self.manager.get_aes_key(message_data[1]),
            json.dumps(response_payload).encode()
        )

        send_with_size(self.manager.get_socket_to_send(message_data[1]), encrypted_response)

    def handle_message_request(self, encrypted_first_part, encrypted_second_part):
        try:
            first_part = json.loads(decrypt_message(self.server_private_key, encrypted_first_part).decode())
            token = first_part["TOKEN"]

            client_aes_key = self.manager.get_aes_key(self.manager.get_phone_number_by_token(token))
            second_part = json.loads(decrypt_with_aes(client_aes_key, encrypted_second_part).decode())

            requesting_phone = second_part["PHONE_NUMBER"]

            if not first_part["TOKEN"] == self.manager.get_auth_token(requesting_phone):
                raise ValueError("Invalid token from client.")

            if not is_timestamp_within_5_minutes(second_part["TIMESTAMP"]):
                raise ValueError("Invalid timestamp received from client.")

            payload_to_verify = json.dumps({
                "REQUEST": "MESSAGE",
                "TOKEN": token,
                "PHONE_NUMBER": requesting_phone,
                "TARGET_PHONE": second_part["TARGET_PHONE"],
                "AES_KEY": second_part["AES_KEY"],
                "DATA": second_part["DATA"],
                "TIMESTAMP": second_part["TIMESTAMP"]
            }).encode()

            if not verify_signature(
                    self.manager.get_public_client_key(requesting_phone),
                    payload_to_verify,
                    bytes.fromhex(second_part["SIGNATURE"])
            ):
                raise ValueError("Invalid signature received from client.")

            target_phone = second_part["TARGET_PHONE"]
            if target_phone not in self.manager.clients:
                raise ValueError(f"Target phone {target_phone} not found.")

            message_data = [ requesting_phone, target_phone, second_part["AES_KEY"], second_part["DATA"]]


            if self.manager.is_client_online(target_phone):
                print(f"[Info][{self.manager.get_name(requesting_phone)}] "
                      f"Delivering message to online client: {self.manager.get_name(target_phone)}.")

                self.transfer_message_to_client(message_data)

                print(f"[Info][{self.manager.get_name(requesting_phone)}] "
                      f"Message delivered to {self.manager.get_name(target_phone)}.")

                self.send_acknowledgment(
                    phone_number=requesting_phone,
                    aes_key=client_aes_key,
                    target_phone=target_phone,
                    data=second_part["DATA"],
                    private_key=self.server_private_key
                )

            else:
                print(f"[Info] Storing message for offline client: {target_phone}.")
                self.manager.store_offline_message(target_phone, message_data)

        except Exception as e:
            print(f"[Error] Message handling failed: {e}")

    def handle_reconnect_request(self, encrypted_first_part, encrypted_second_part):

        first_part = json.loads(decrypt_message(self.server_private_key, encrypted_first_part).decode())

        phone_number = first_part["PHONE_SOURCE"]
        second_part = json.loads(
            decrypt_with_aes(self.manager.get_aes_key(phone_number), encrypted_second_part).decode())
        print(f"[Info] Reconnect request from {self.manager.get_name(phone_number)}.")

        if self.manager.get_auth_token(phone_number) != second_part["TOKEN"]:
            raise ValueError("Invalid token for reconnect request.")

        self.manager.clients[phone_number]["online"] = True
        print(f"[Info] {self.manager.get_name(phone_number)} is now online.")
        self.send_offline_messages(phone_number)

    def send_offline_messages(self, target_phone):
        print(f"[Info] Sending offline messages for {self.manager.get_name(target_phone)}.\n")
        for message in self.manager.retrieve_offline_messages(target_phone):
            self.transfer_message_to_client(message)
            source_phone = message[0]
            data = message[3]
            client_aes_key = self.manager.get_aes_key(source_phone)
            self.send_acknowledgment(
                phone_number=source_phone,
                aes_key=client_aes_key,
                target_phone=target_phone,
                data=data,
                private_key=self.server_private_key
            )


class ClientHandler:
    def __init__(self, conn, addr, manager, server_private_key):
        self.conn = conn
        self.addr = addr
        self.manager = manager
        self.server_private_key = server_private_key
        self.message_handler = MessageHandler(manager, server_private_key)

    def handle(self):
        print(f"[Connection] Client connected from {self.addr}.")
        try:
            while True:
                full_packet = recv_with_size(self.conn)
                full_packet = json.loads(full_packet.decode())

                encrypted_first_part = bytes.fromhex(full_packet["FIRST_PART"])
                encrypted_second_part = bytes.fromhex(full_packet["SECOND_PART"])

                first_part = json.loads(decrypt_message(self.server_private_key, encrypted_first_part).decode())

                if first_part["REQUEST"] == "REGISTER":
                    self.message_handler.handle_register_request(self.conn, encrypted_first_part, encrypted_second_part)
                elif first_part["REQUEST"] == "GET_PUBLIC_KEY":
                    self.message_handler.handle_get_public_key_request(self.conn,
                                                                       encrypted_first_part, encrypted_second_part)
                elif first_part["REQUEST"] == "MESSAGE":
                    self.message_handler.handle_message_request(encrypted_first_part, encrypted_second_part)
                elif first_part["REQUEST"] == "DISCONNECT":
                    phone_number = first_part["PHONE_SOURCE"]
                    print(f"[Info] Disconnect request from {self.manager.get_name(phone_number)}.")
                    self.manager.clients[phone_number]["online"] = False
                    print(f"[Info] {self.manager.get_name(phone_number)} is now offline.")
                elif first_part["REQUEST"] == "RECONNECT":
                    self.message_handler.handle_reconnect_request(encrypted_first_part,
                                                                  encrypted_second_part)
                else:
                    raise ValueError(f"Unsupported request type: {first_part['REQUEST']}.")
        except Exception as e:
            print(f"[Error] Client handling failed: {e}")
        finally:
            self.conn.close()
            print(f"[Connection] Client from {self.addr} disconnected.")


class Server:
    def __init__(self, host, port, server_private_key):
        self.host = host
        self.port = port
        self.server_private_key = server_private_key
        self.manager = ConnectionManager.ConnectionManager()

    def start(self):
        print("[Info] Starting server...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        print(f"[Info] Server listening on {self.host}:{self.port}")

        while True:
            conn, addr = server_socket.accept()
            client_handler = threading.Thread(target=self._handle_client, args=(conn, addr))
            client_handler.start()

    def _handle_client(self, conn, addr):
        handler = ClientHandler(conn, addr, self.manager, self.server_private_key)
        handler.handle()
