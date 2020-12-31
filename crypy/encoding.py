from .utils import Menu
import base64
def encode_decode():
    Menu([
        ("encoding a message", encode),
        ("decoding a code", decode),
    ]).run()

def encode():
    message = input("enter the message to encode")
    code = base64.b64encode(message.encode('ascii'))
    print(code.decode('ascii'))

def decode():
    code = input("enter the code to decode")
    message = base64.b64decode(code.encode('ascii'))
    print(message.decode('ascii'))