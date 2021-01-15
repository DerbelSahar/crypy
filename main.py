from crypy import sym_encryption, asym_encryption, encode_decode, crack_hash, hash_function
from crypy.utils import Menu

menu = [
    "encoding and decoding",
    "message hashing",
    "cracking hash",
    "symmetric encryption and decryption",
    "asymmectric encryption and decryption",
    "quit"
]

def render_message():
    for index, message in enumerate(menu, start=1):
        print(f"{index}- {message}")


if __name__=="__main__":
    Menu([
        ("encoding and decoding", encode_decode),
        ("message hashing", hash_function),
        ("cracking hash", crack_hash),
        ("symmetric encryption and decryption", sym_encryption),
        ("asymmectric encryption and decryption", asym_encryption),
    ], once=False, include_back=False).run()

    
    