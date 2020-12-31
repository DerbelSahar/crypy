from crypy.utils import Menu
from hashlib import sha256, sha512, sha384, md5, sha1, sha224
### hashing ###
def hash():
    message = input("enter the message to hash")
    hashing_algorithm = Menu([
        ("SHA1 ", lambda: sha1_hash),
        ("SHA224", lambda: sha224_hash),
        ("SHA256", lambda: sha256_hash),
        ("SHA384", lambda: sha384_hash),
        ("SHA512", lambda: sha512_hash),
        ("MD5", lambda: md5_hash),
    ],choice_message="choose a hashing algorithm").run()
    hashed = hashing_algorithm(message)
    print(hashed)

def sha1_hash(message):
    return sha1(message.encode()).hexdigest()

def sha224_hash(message):
    return sha224(message.encode()).hexdigest()

def sha256_hash(message):
    return sha256(message.encode()).hexdigest()

def sha384_hash(message):
    return sha384(message.encode()).hexdigest()

def sha512_hash(message):
    return sha512(message.encode()).hexdigest()

def md5_hash(message):
    return md5(message.encode()).hexdigest()


### cracking hash ###

def hash_word(word, hash_algo):
    if hash_algo.upper() == 'SHA256':
        return sha256(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA512':
        return sha512(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA384':
        return sha384(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA1':
        return sha1(word.encode()).hexdigest()
    elif hash_algo.upper() == 'MD5':
        return md5(word.encode()).hexdigest()
    elif hash_algo.upper() == 'SHA224':
        return sha224(word.encode()).hexdigest()


def detect_hash(hashed):
    if len(hashed) == 128:
        return 'SHA512'
    elif len(hashed) == 96:
        return 'SHA384'
    elif len(hashed) == 64:
        return 'SHA256'
    elif len(hashed) == 40:
        return 'SHA1'
    elif len(hashed) == 32:
        return 'MD5'
    elif len(hashed) == 56:
        return 'SHA224'
    else:
        print('Could not auto detect hash type\n')
        return None

### dictionary attack ###
def crack_hash():
    hached = input("enter the message to hash").strip()
    cracking_technique = Menu([
        ("Dictionary attack", lambda: dictionary_attack),
        ("Brute force attack", lambda: brute_force_attack),
    ],choice_message="choose the technique to use").run()
    message = cracking_technique(hached)
    print(message)

def dictionary_attack(hashed):
    algo = detect_hash(hashed)
    if (algo):
        with open("./names.txt") as dictionary:
            for line in dictionary:
                words = line.split()
                for word in words:
                    hashed_word = hash_word(word, algo)
                    if hashed_word == hashed:
                        return word
    return "failed to crack"

def brute_force_attack(hashed):
    pass
