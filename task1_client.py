import os
import random
import socket
import struct
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Encryption and decryption functions
def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct

# Function to create an ICMP packet with type 47
def create_icmp_packet(payload):
    icmp_type = 47  # Type 47 for custom ICMP packets
    icmp_code = 0   # Arbitrary code
    checksum = 0    # Initialize checksum
    identifier = random.randint(0, 65535)
    sequence_number = 1  # Arbitrary sequence number

    # Construct the ICMP header
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence_number)

    # Calculate checksum
    checksum = socket.htons(calculate_checksum(icmp_header + payload))

    # Reconstruct the ICMP header with correct checksum
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence_number)

    # Create the full ICMP packet
    icmp_packet = icmp_header + payload

    return icmp_packet

# Function to calculate checksum
def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'  # Padding if data length is odd
    checksum = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

# Function to send the ICMP packet
def send_icmp_packet(destination_ip, payload):
    # Create raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # Set socket options to allow sending ICMP packets
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Create the ICMP packet with type 47
    icmp_packet = create_icmp_packet(payload)

    # Send the packet
    s.sendto(icmp_packet, (destination_ip, 0))

# Main function
def main():
    # Obtain destination IP address from command line
    destination_ip = input("Enter destination IP address: ")

    # Generate a random key and IV
    key = os.urandom(32)
    iv = os.urandom(16)

    # Continuously prompt for messages and send them
    while True:
        message = input("Enter message to send (empty message to exit): ")
        if not message:
            break
        
        # Encrypt the message
        encrypted_message = encrypt_message(message, key, iv)

        # Send the encrypted message as ICMP packet with type 47
        send_icmp_packet(destination_ip, encrypted_message)

        print("Message sent successfully.")
        time.sleep(1)  # Sleep for 1 second to avoid detection by firewall

if __name__ == "__main__":
    main()
