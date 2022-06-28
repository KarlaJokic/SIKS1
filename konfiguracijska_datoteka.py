import os
import binascii
from x25519 import multscalar, base_point_mult
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import socket
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import ipaddress

def clamp2(n):
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n

# https://medium.com/asecuritysite-when-bob-met-alice/authenticated-ecdh-in-python-using-x25519-7fcf66cc455c
def X25519RazmjenaKljuceva():
    a = os.urandom(32)  # 32 bita
    b = os.urandom(32)
    a_pub = base_point_mult(a) # napravi javni kljuc od a
    b_pub = base_point_mult(b)
    x = os.urandom(32)          # jos jedna varijabla
    y = os.urandom(32)
    client_send = multscalar(y, a_pub) # (y) aG
    client_send = multscalar(b, client_send) # (yb) aG
    server_send = multscalar(x, b_pub) # (x) bG
    server_send = multscalar(a, server_send) # (xa) bG
    k_a = multscalar(x, client_send) # x (yb) aG
    k_b = multscalar(y, server_send) # y ( xa) bG
    if(k_a == k_b):
      print('uspjesna razmjena kljuceva')
      return True, b'uspjesna razmjena kljuceva'

# X509
# https://gist.github.com/bloodearnest/9017111a313777b9cce5
def generate_selfsigned_cert(hostname, auth_korisnik, ip_addresses=None, key_client=None, key_server=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""    
    # Generate our key
    if key_client is None:
        key_client = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    if key_server is None:
        key_server = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
 
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.    
    alt_names = [x509.DNSName(hostname)]
    
    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios 
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    
    san = x509.SubjectAlternativeName(alt_names)
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert_client = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key_client.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key_client, hashes.SHA256(), default_backend())
    )
    cert_server = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key_server.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key_server, hashes.SHA256(), default_backend())
    )
    cert_pem_client = cert_client.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem_client = key_client.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_pem_server = cert_server.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem_server = key_server.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_client = cert_client.public_key()
    public_key_server = cert_server.public_key()

    if(auth_korisnik == 'klijent'):
      if(isinstance(public_key_server, rsa.RSAPublicKey)):
        print("Autentifikacija: Server je uspjesno potvrden")
    if(auth_korisnik == 'server'):
      if(isinstance(public_key_client, rsa.RSAPublicKey)):
        print("Autentifikacija: Klijent je uspjesno potvrden")
    
kljucic_klijent = b'nMrhMgIiAsMMEMfuPudvP4_LfA6U85NOGdAJZBdGN1Q='         # fernet
kljucic_posluzitelj = b'HSnWMGB4QhzcvX36MTPeSzYJ7h1_HBu6TugelbmX7BI='     # fernet
fernet_kljucic_klijent = Fernet(kljucic_klijent)
fernet_kljucic_posluzitelj = Fernet(kljucic_posluzitelj)













