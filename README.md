1. At First I created certificates for both client and server using OpenSSL.
   In the terminal I wrote the following commands to generate the cerificates:
   1. openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
   2. openssl req -x509 -newkey rsa:4096 -keyout client_key.pem -out client_cert.pem -days 365 -nodes
   These two commands allow me to generate certificates and a private key for serever and client respectively.

I stored both of them in the same directory also in order to run the code smoothly.
