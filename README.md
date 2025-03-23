📡 Secure Messaging System

A secure client-server messaging system in Python using RSA and AES to ensure confidentiality, authenticity, and reliable message delivery. The server handles registration, key exchange, and message forwarding between clients identified by phone numbers.
✨ Features

    🔐 Client registration with two-step authentication

    🔑 Secure RSA & AES key exchange

    💬 End-to-end encrypted messaging

    🕓 Message integrity via timestamps and digital signatures

    📥 Offline message storage and delivery upon reconnection

📁 Project Structure

main.py
├── Server.py
│── ConnectionManager.py
├── Client.py
├── utils/
│   ├── AESEncryption.py
│   ├── RSAManagement.py
│   ├── NumericSignatureAndTimeStamp.py
│   ├── communicationFunctions.py
│   ├── getRSAKeys.py
│   └── randomPhoneNumber.py

🚀 How to Run
Start the Server

python main.py server

Start a Client

python main.py client

Simulate Two Clients Communicating

python main.py 2clients

🛡️ Technologies Used

    RSA 2048-bit & AES 256-bit encryption

    Python socket, threading, cryptography

    UTC timestamps & JSON message formatting
