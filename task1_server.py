import socket
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Decryption function
def decrypt_message(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Function to handle incoming ICMP packets
def handle_packet(packet):
    # Extract payload from ICMP packet
    payload = packet[28:]  # Assuming IPv4 header length is 20 bytes and ICMP header length is 8 bytes

    # Decrypt the payload
    decrypted_message = decrypt_message(payload, key, iv)

    print("Decrypted message:", decrypted_message)

# Main function
def main():
    # Generate random key and IV
    key, iv = generate_random_key_and_iv()
    print("Generated key:", key)
    print("Generated IV:", iv)

    # Create raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # Set socket options to allow receiving ICMP packets
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Start listening for incoming ICMP packets
    while True:
        packet = s.recvfrom(65565)[0]
        handle_packet(packet)

if __name__ == "__main__":
    main()
