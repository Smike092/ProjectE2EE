import sys
import time

import Client
import Server
from utils.getRSAKeys import get_keys_in_secondary_memory


def main():
    server_private_key, server_public_key = get_keys_in_secondary_memory()

    host = "localhost"
    port_server_listening = 12345
    port_client1_listening = 12346
    port_client2_listening = 12347


    if len(sys.argv) < 2:
        print("Usage: python main.py [server|client]")
        sys.exit(1)

    role = sys.argv[1].lower()
    if role == "server":
        my_server = Server.Server(host, port_server_listening, server_private_key)
        my_server.start()
    elif role == "client":
        bob = Client.Client(host, port_server_listening, server_public_key, "Bob", 1234567890)
        bob.register()
    elif role == "2clients":
        bob = Client.Client(host, port_server_listening, port_client1_listening, server_public_key, "Bob", 1234567890)
        alice = Client.Client(host, port_server_listening, port_client2_listening, server_public_key, "Alice", 2345678901)

        bob.register()
        time.sleep(1)

        alice.register()
        time.sleep(1)

        bob.send_message(2345678901, "Hello Alice, it's Bob!")
        time.sleep(1)

        alice.send_message(1234567890, "Hi Bob, what's up ?")
        time.sleep(1)

        alice.disconnect()
        time.sleep(1)

        bob.send_message(2345678901, "Fine, and you ?")
        time.sleep(1)

        bob.send_message(2345678901, "Have you seen Eve recently ?")
        time.sleep(1)

        alice.reconnect()
        time.sleep(1)

        bob.disconnect()
        alice.disconnect()


    else:
        print("Invalid role. Use 'server' or 'client'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
