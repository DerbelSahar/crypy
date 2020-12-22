from crypy import sym_encryption, asym_encryption, encode_decode, crack_hash

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
    while True:
        render_message()
        choice=input("enter your choice\n")

        if choice=='1':
            encode_decode()
        
        elif choice=='2':
            hash()
        
        elif choice=='3':
            crack_hash()
        
        elif choice=='4':
            sym_encryption()
        
        elif choice=='5':
            asym_encryption()
        
        elif choice==str(len(menu)):
            break
        
        else:
            print("invalid choice, retry...")
    
    