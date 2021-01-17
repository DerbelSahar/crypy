from __future__ import annotations
import abc 
from abc import ABC, abstractmethod, ABCMeta
from base64 import b64encode, b64decode
from typing import Union, Optional , List
import inspect
import sys
import shelve

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ObjectIdentifier
import getpass

from .utils import Menu
  

class Key(ABC):
    @abstractmethod
    def write(self, filename: str):
        pass

    @staticmethod
    @abstractmethod
    def read(filename: str):
        pass

    @abstractmethod
    def get_available_operations(self) -> List[str]:
        pass
    
    @classmethod
    def KEYS(cls):
        return [
            obj for _, obj in inspect.getmembers(sys.modules[__name__])
            if inspect.isclass(obj) and issubclass(obj, cls) and obj != cls
        ]
    
    @classmethod
    def from_file(cls, filename: str) -> Optional[Key]:
        key = cls.read(filename)
        key_class = next(filter(lambda _class: isinstance(key, _class.KEY_CLASS), cls.KEYS()))
        if key_class:
            return key_class(key=key)
        else:
            return None

class DecryptKey(ABC):
    @abstractmethod
    def decrypt(self, encrypted_message: bytes) -> bytes:
        pass

class EncryptKey(ABC):
    @abstractmethod
    def encrypt(self, message: bytes) -> bytes:
        pass

class SignKey(ABC):
    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        pass
    
class VerifyKey(ABC):
    @abstractmethod
    def verify(self, signature: bytes, message: bytes) -> bool:
        pass

class PublicKey(Key):
    KEY_CLASS = object
    AVAILABLE_OPERATIONS = ["encrypt", "verify"]

    def __init__(self,
            key: Union[rsa.RSAPublicKey, dsa.DSAPublicKey, ec.EllipticCurvePublicKey, None] = None,
            filename: Optional[str] = None):
        if key:
            self.public_key = key
        elif filename:
            self.public_key = self.read(filename)
        else:
            ValueError("public_key or filename must be provided")
        
        assert isinstance(self.public_key, self.KEY_CLASS)
    
    def write(self, filename: str):
        serial_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f'{filename}.pem', 'wb') as f: f.write(serial_pub)

    @staticmethod
    def read(filename: str) -> Union[rsa.RSAPublicKey, dsa.DSAPublicKey, ec.EllipticCurvePublicKey, None]:
        with open(filename, "rb") as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    
    def get_available_operations(self) -> List[str]:
        return self.AVAILABLE_OPERATIONS
    
    @classmethod
    def PRIVATE_KEY_CLASS(cls):
        return next(filter(
            lambda _class: _class.PUBLIC_KEY_CLASS == cls,
            PrivateKey.KEYS()
        ))
    
    @classmethod
    def ALGORITHM(cls):
        private_key_class = cls.PRIVATE_KEY_CLASS()
        if private_key_class:
            return private_key_class.ALGORITHM
        return None


class RSAPublicKey(PublicKey, EncryptKey, VerifyKey):
    KEY_CLASS = rsa.RSAPublicKey
    AVAILABLE_OPERATIONS = ["encrypt", "verify"]

    def encrypt(self, message: bytes) -> bytes:
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        
        return True
    


class DSAPublicKey(PublicKey, VerifyKey):
    KEY_CLASS = dsa.DSAPublicKey
    AVAILABLE_OPERATIONS = ["verify"]

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        
        return True


class EllipticCurvePublicKey(PublicKey, VerifyKey):
    KEY_CLASS = ec.EllipticCurvePublicKey
    AVAILABLE_OPERATIONS = ["verify"]

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return False
        
        return True

class PrivateKey(Key):
    KEY_CLASS = object
    PUBLIC_KEY_CLASS = object
    AVAILABLE_OPERATIONS = ["decrypt", "sign"]
    ALGORITHM = None

    def __init__(self,
            key: Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, None] = None,
            filename: Optional[str] = None):
        if key:
            self.private_key = key
        elif filename:
            self.private_key  = self.read(filename)
        else:
            self.private_key = self.generate()
        
        assert isinstance(self.private_key, self.KEY_CLASS)
    
    @classmethod
    @abstractmethod
    def generate(cls) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        pass
    
    def write(self, filename: str):
        pwd = getpass.getpass("enter a passphrase:")
        serial_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pwd.encode('utf-8'))
        )
        with open(f'{filename}.pem', 'wb') as f: f.write(serial_private)

    @staticmethod
    def read(filename: str) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, None]:
        pwd = getpass.getpass("enter the passphrase")
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=pwd.encode('utf-8'),
                backend=default_backend()
            )

    def public_key(self) -> PublicKey:
        return self.PUBLIC_KEY_CLASS(key=self.private_key.public_key())
    
    def get_available_operations(self) -> List[str]:
        return self.AVAILABLE_OPERATIONS


class RSAPrivateKey(PrivateKey, DecryptKey, SignKey):
    KEY_CLASS = rsa.RSAPrivateKey
    PUBLIC_KEY_CLASS = RSAPublicKey
    AVAILABLE_OPERATIONS = ["decrypt", "sign"]
    ALGORITHM = "RSA"

    @classmethod
    def generate(cls) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    
    def decrypt(self, encrypted_message: bytes) -> bytes:
        return self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


class DSAPrivateKey(PrivateKey, SignKey):
    KEY_CLASS = dsa.DSAPrivateKey
    PUBLIC_KEY_CLASS = DSAPublicKey
    AVAILABLE_OPERATIONS = ["sign"]
    ALGORITHM = "DSA"

    @classmethod
    def generate(cls) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        return dsa.generate_private_key(
            key_size=2048
        )
    
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            hashes.SHA256()
        )

class EllipticCurvePrivateKey(PrivateKey, SignKey):
    KEY_CLASS = ec.EllipticCurvePrivateKey
    PUBLIC_KEY_CLASS = EllipticCurvePublicKey
    AVAILABLE_OPERATIONS = ["sign"]
    ALGORITHM = "Elliptic Curve"
    
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    
    @classmethod
    def generate(cls) -> Union[rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        elliptic_curve = Menu([
            ("SECT571R1", lambda: ec.SECT571R1),
            ("SECP192R1", lambda: ec.SECP192R1),
            ("SECP256R1", lambda: ec.SECP256R1),
            ("SECP521R1", lambda: ec.SECP521R1),
            ("SECT163R2", lambda: ec.SECT163R2),
            ("SECT163R2", lambda: ec.SECT163R2),
            ("SECT163R2", lambda: ec.SECT163R2),
            ("Lookup by Object Identifier", cls.lookup_ec_by_oid)
        ], choice_message="choose a decryption algorithm").run()

        return ec.generate_private_key(
            elliptic_curve
        )
    
    @staticmethod
    def lookup_ec_by_oid():
        dotted_string = input("Give the Elliptic Curve's dotted string")
        return ec.get_curve_for_oid(ObjectIdentifier(dotted_string))


class KeyRing:
    KEYRING_DIR = "crypy/keyring"
    KEYRING_FILENAME = "keyring"
    KEYRING = shelve.open(f"{KEYRING_DIR}/{KEYRING_FILENAME}", writeback=True)

    def __init__(self, keyring_dir="crypy/keyring", keyring_filename="keyring"):
        self.KEYRING_DIR = keyring_dir
        self.KEYRING_FILENAME = keyring_filename
    
    def add_key_pair(self, key_pair: KeyPair):
        self.KEYRING["keys"][key_pair.key_pair_name] = {
            "type": "key_pair",
            "algorithm": key_pair.ALGORITHM
        }
    
    def add_public_key(self, key: PublicKey, key_name: str):
        self.KEYRING["keys"][key_name] = {
            "type": "public_key",
            "algorithm": key.ALGORITHM()
        }
    
    @property
    def keys(self):
        return self.KEYRING["keys"]
    
    def import_key_pair(self):
        key_pair_name = input("Give a key pair name")
        public_key_filename = input("Give the public key's file path")
        private_key_filename = input("Give the private key's file path")
        key_pair = KeyPair.from_files(private_key_filename, public_key_filename)
        key_pair.key_pair_name = key_pair_name
        key_pair.write()
        self.add_key_pair(key_pair)
    
    def import_public_key(self):
        key_name = input("Give a key name")
        public_key_filename = input("Give the public key's file path")
        public_key = PublicKey.from_file(public_key_filename)
        if not public_key:
            raise ValueError("Invalid or unsupported public key file")
        
        public_key.write(f"{self.KEYRING_DIR}/public_{key_name}")
        self.add_public_key(public_key, key_name)


KEYRING = KeyRing()


class KeyPairMeta(ABCMeta):
    def __init__(cls, *args):
        cls.ALGORITHM = cls.PRIVATE_KEY_CLASS.ALGORITHM
    

class KeyPair(ABC, metaclass=KeyPairMeta):
    
    PRIVATE_KEY_CLASS = PrivateKey
    KEYRING = KEYRING
    
    def __init__(self,
            key_pair_name: str = None,
            private_key: Optional[PrivateKey] = None,
            private_key_filename: Optional[str] = None,
            public_key: Optional[PublicKey] = None,
            public_key_filename: Optional[str] = None):
        self.key_pair_name = key_pair_name
        if private_key:
            self.private_key = private_key
        elif private_key_filename:
            self.private_key = PrivateKey.from_file(private_key_filename)
        else:
            self.private_key = self.PRIVATE_KEY_CLASS()
            self.public_key = self.private_key.public_key()
        
        assert isinstance(self.private_key, self.PRIVATE_KEY_CLASS), \
            f"private key ({self.private_key.__class__.__name__}) does not match class {self.PRIVATE_KEY_CLASS.__name__}"
        
        if public_key and (private_key or private_key_filename):
            self.public_key = public_key
        elif public_key_filename and (private_key or private_key_filename):
            self.public_key = PublicKey.from_file(public_key_filename)
        else:
            self.public_key = self.private_key.public_key()
        
        assert self.public_key.__class__ == self.private_key.PUBLIC_KEY_CLASS, \
            f"Public key and private key don't have matching classes: " \
            f"private: {self.private_key.__class__.__name__}, " \
            f"public: {self.public_key.__class__.__name__}, "
    
    def write(self):
        self.public_key.write(f"{self.KEYRING.KEYRING_DIR}/public_{self.key_pair_name}")
        self.private_key.write(f"{self.KEYRING.KEYRING_DIR}/private_{self.key_pair_name}")

    @classmethod
    def generate(cls):
        key_pair_name = input("Give a key pair name")
        key_pair = cls(key_pair_name=key_pair_name)
        key_pair.write()
        cls.KEYRING.add_key_pair(key_pair)
    
    @classmethod
    def from_files(cls, private_key_filename: str, public_key_filename: str) -> Optional[KeyPair]:
        private_key = PrivateKey.from_file(private_key_filename)
        key_pair_class = next(filter(lambda _class: _class.PRIVATE_KEY_CLASS == private_key.__class__, cls.KEY_PAIRS()))
        if key_pair_class:
            return key_pair_class(private_key=private_key, public_key_filename=public_key_filename)
        else:
            return None
    
    def get_available_operations(self) -> List[str]:
        return self.private_key.get_available_operations() \
            + self.public_key.get_available_operations()
    
    @classmethod
    def KEY_PAIRS(cls):
        return [
            obj for _, obj in inspect.getmembers(sys.modules[__name__])
            if inspect.isclass(obj) and issubclass(obj, cls) and obj != cls
        ]


class EncryptionKeyPair(EncryptKey, DecryptKey):
    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        self.private_key = private_key
        self.public_key = public_key
    
    def decrypt(self, encrypted_message: bytes) -> bytes:
        return self.private_key.decrypt(encrypted_message)
    
    def encrypt(self, message: bytes) -> bytes:
        return self.private_key.encrypt(message)

class SigningKeyPair(SignKey, VerifyKey):
    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        self.private_key = private_key
        self.public_key = public_key
    
    def sign(self, message: bytes) -> bytes:
        return self.public_key.sign(message)
    
    def verify(self, signature: bytes, message: bytes) -> bool:
        return self.public_key.verify(signature, message)

class RSAKeyPair(KeyPair, EncryptionKeyPair, SigningKeyPair):
    PRIVATE_KEY_CLASS = RSAPrivateKey

class DSAKeyPair(KeyPair, SigningKeyPair):
    PRIVATE_KEY_CLASS = DSAPrivateKey

class EllipticCurveKeyPair(KeyPair, SigningKeyPair):
    PRIVATE_KEY_CLASS = EllipticCurvePrivateKey

if __name__=="__main__":
    KEYRING.import_key_pair()
    print(KEYRING.keys)