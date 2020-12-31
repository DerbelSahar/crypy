import cryptography
from cryptography.fernet import Fernet
import os
import base64
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .utils import Menu
import hashlib
from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Cipher import Blowfish
from struct import pack
import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, dh, padding

def sym_encryption():
    Menu([
        ("symmetric encrypt of a message", sym_encrypt),
        ("symmetric decryption of an encrypted message", sym_decrypt)
    ]).run()

def sym_encrypt():
    message = input("enter the message to encrypt")
    algorithm = Menu([
        ("Fernet Encryption", lambda: fernet_encryption),
        ("AES Encryption", lambda: aes_encryption),
        ("DES Encryption", lambda: des_encryption),
        ("blowfish Encryption", lambda: blowfish_encryption),
    ], choice_message="choose an encryption algorithm").run()
    password = getpass.getpass("enter the password")
    encrypted = algorithm(message, password)
    print("encrypted:\n", encrypted)
    

def sym_decrypt():
    message = input("enter the message to decrypt")
    algorithm = Menu([
        ("Fernet Decryption", lambda: fernet_decryption),
        ("AES Decryption", lambda: aes_decryption),
        ("DES Decryption", lambda: des_decryption),
        ("blowfish Decryption", lambda: blowfish_decryption),
    ], choice_message="choose a decryption algorithm").run()
    password = getpass.getpass("enter the password")
    decrypted = algorithm(message, password)
    print("decrypted:\n", decrypted)
    
### Fernet Algorithm ### works perferctly
class Fernet_algorithm:
    key = None
    salt = None
    @staticmethod
    def encrypt(message, password):
        Fernet_algorithm.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=Fernet_algorithm.salt,
            iterations=100000)
        Fernet_algorithm.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(Fernet_algorithm.key)
        encrypted = fernet.encrypt(message.encode()).decode('ascii')  
        return encrypted

    @staticmethod
    def decrypt(message, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=Fernet_algorithm.salt,
            iterations=100000)
        Fernet_algorithm.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(Fernet_algorithm.key)
        decrypted = fernet.decrypt(message.encode()).decode('ascii')  
        return decrypted
    

def fernet_encryption(message, password):
    encrypted = Fernet_algorithm.encrypt(message,password)
    return encrypted

def fernet_decryption(message, password):
    decrypted = Fernet_algorithm.decrypt(message,password)
    return decrypted



###  AES 256 algorithme  ### works perfectly
class AES_algorithm:
    salt = None
    nonce = None
    tag = None

    @staticmethod 
    def encrypt(message, password):
        salt = get_random_bytes(AES.block_size)
        private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher_config = AES.new(private_key, AES.MODE_GCM)
        cipher_text,tag = cipher_config.encrypt_and_digest(message.encode('utf-8'))
        AES_algorithm.salt = b64encode(salt).decode('utf-8')
        AES_algorithm.nonce =  b64encode(cipher_config.nonce).decode('utf-8')
        AES_algorithm.tag = b64encode(tag).decode('utf-8')
        encrypted = b64encode(cipher_text).decode('utf-8')
        return encrypted
    
    @staticmethod
    def decrypt(message, password):
        salt = b64decode(AES_algorithm.salt)
        cipher_text = b64decode(message)
        nonce = b64decode(AES_algorithm.nonce)
        tag = b64decode(AES_algorithm.tag)
        private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(cipher_text, tag)
        return decrypted.decode("utf-8")

def aes_encryption(message, password):
    encrypted = AES_algorithm.encrypt(message,password)
    return encrypted
def aes_decryption(message, password):
    decrypted = AES_algorithm.decrypt(message, password)
    return decrypted

###  DES algorithme  ###  Works perfectly
class DES_algorithm:
    block_size = 16
    key = None
    iv = None
    @staticmethod
    def encrypt(message, password):
        DES_algorithm.key = hashlib.sha256(password.encode("utf-8")).digest()[:DES_algorithm.block_size]
        DES_algorithm.iv = Random.new().read(DES3.block_size)
        cipher = DES3.new(DES_algorithm.key, DES3.MODE_OFB, DES_algorithm.iv)
        encrypted = cipher.encrypt(message.encode('utf-8'))
        return b64encode(encrypted).decode('utf-8') 
    @staticmethod
    def decrypt(message, password):
        cipher = DES3.new(DES_algorithm.key, DES3.MODE_OFB, DES_algorithm.iv)
        decrypted = cipher.decrypt(b64decode(message))
        return decrypted.decode('utf-8')

def des_encryption(message, password):
    encrypted = DES_algorithm.encrypt(message, password) 
    return encrypted 

def des_decryption(message, password):
    decrypted = DES_algorithm.decrypt(message,password)
    return decrypted



## Blowfish algorithme ## decryption Data must be padded to 8 byte boundary in CBC mode
class Blowfish_algorithm:
    @staticmethod
    def encrypt(message, password):
        bs = Blowfish.block_size
        key = password.encode("utf-8")
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        plen = bs - len(message) % bs
        padding = [plen]*plen
        padding = pack('b'*plen, *padding)
        encrypted =cipher.iv + cipher.encrypt(message.encode('utf-8') + padding)
        return b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt(message, password):
        message = b64decode(message)
        bs = Blowfish.block_size
        iv = message[:bs]
        ciphertext = message[bs:]

        key = password.encode("utf-8")
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted =cipher.decrypt(ciphertext)
        last_byte = decrypted[-1]
        decrypted = decrypted[:- (last_byte if type(last_byte) is int else ord(last_byte))]
        return decrypted.decode('utf-8')

def blowfish_encryption(message, password):
    encrypted = Blowfish_algorithm.encrypt(message,password)
    return encrypted

def blowfish_decryption(message, password):
    decrypted = Blowfish_algorithm.decrypt(message, password)
    return decrypted




#########################################################################""
def generate_asym_key(algorithm='rsa'):
    pwd = getpass.getpass("enter a passphrase:")
    if algorithm=='rsa':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
    elif algorithm=='dsa':
        private_key = dsa.generate_private_key(
            key_size=2048
        )
        
    elif algorithm=='elliptic_curve':
        elliptic_curve = ec.EllipticCurve()
        private_key = ec.generate_private_key(
            elliptic_curve
        )
        


    public_key = private_key.public_key()
    # private key
    serial_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pwd.encode('utf-8'))
    )
    with open('private_noshare.pem', 'wb') as f: f.write(serial_private)

    # public key
    serial_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_shared.pem', 'wb') as f: f.write(serial_pub)
    return public_key, private_key

def read_private (filename = "private_noshare.pem"):
    pwd = getpass.getpass("enter the passphrase")
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=pwd.encode('utf-8'),
            backend=default_backend()
        )
    return private_key
                  
def read_public (filename = "public_shared.pem"):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def asym_encrypt():
    message = input("enter the message to encrypt")

    algorithm = Menu([
        ("RSA Key", lambda: 'rsa'),
        ("DSA Key", lambda: 'dsa'),
        ("Elliptic Curve", lambda: 'elliptic_curve'),
    ], choice_message="choose an asymmetric algorithm").run()

    public_key, private_key = generate_asym_key(algorithm)
    
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted = b64encode(encrypted).decode('utf-8')
    print("encrypted:\n", encrypted)

def asym_decrypt():
    encrypted = b64decode(input("enter the message to decrypt"))
    private_key = read_private()
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
    )).decode('utf-8')
    print("decrypted:\n", decrypted)


def manage_keys():
    pass

def asym_encryption():
    Menu([
        ("encrypt message", asym_encrypt),
        ("decrypt message", asym_decrypt),
        ("key management", manage_keys)
    ]).run()
    

