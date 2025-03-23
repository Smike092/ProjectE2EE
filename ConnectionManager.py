import socket


class ConnectionManager:
    """A class to manage client connections and messages."""

    MAX_OFFLINE_MESSAGES = 10

    def __init__(self):
        self.clients = {}  # Dictionnaire des clients

    def add_client(self, phone_number, name, aes_key, public_key, token, port):
        """Add a new client or update an existing one."""
        self.clients[phone_number] = {
            "name": name,
            "aes_key": aes_key,
            "public_key": public_key,
            "token": token,
            "online": True,
            "messages": [],
            "port_listener": port,
            "socket_to_send": socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        }

    def store_offline_message(self, phone_number, message_data):
        if phone_number in self.clients and not self.clients[phone_number]["online"]:
            messages = self.clients[phone_number]["messages"]
            if len(messages) >= self.MAX_OFFLINE_MESSAGES:
                messages.pop(0)
            messages.append(message_data)

    def retrieve_offline_messages(self, phone_number):
        if phone_number in self.clients:
            messages = self.clients[phone_number]["messages"]
            self.clients[phone_number]["messages"] = []  # Clear messages after retrieval
            return messages
        return []

    def is_client_online(self, phone_number):
        """Check if a client is online."""
        return self.clients.get(phone_number, {}).get("online", False)

    def get_client_token(self, phone_number):
        """Retrieve the token for a client."""
        return self.clients.get(phone_number, {}).get("token")

    def get_aes_key(self, phone_number):
        return self.clients.get(phone_number, {}).get("aes_key")

    def get_public_client_key(self, phone_number):
        return self.clients.get(phone_number, {}).get("public_key")

    def get_name(self, phone_number):
        return self.clients.get(phone_number, {}).get("name")

    def get_auth_token(self, phone_number):
        return self.clients.get(phone_number, {}).get("token")

    def get_port_address(self, phone_number):
        return self.clients.get(phone_number, {}).get("port_listener")

    def get_socket_to_send(self, phone_number):
        return self.clients.get(phone_number, {}).get("socket_to_send")

    def get_phone_number_by_token(self, token):
        for phone_number, client_data in self.clients.items():
            if client_data.get("token") == token:
                return phone_number
        return None

    def is_phone_number_present(self, phone_number):
        """Check if a phone number exists in the client list."""
        return phone_number in self.clients
