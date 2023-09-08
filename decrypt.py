import base64
from Crypto.Cipher import ChaCha20
import random
import secrets
from math import sqrt

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return -1

def is_prime(n):
    if n < 2:
        return False
    elif n == 2:
        return True
    else:
        for i in range(2, int(sqrt(n)) + 1, 2):
            if n % i == 0:
                return False
    return True

def layer3_decryption(ciphertext, private_key):
    d, n = private_key
    decrypted_message = ''.join([chr(pow(c, d, n)) for c in ciphertext])
    return decrypted_message

def layer1_decryption(encrypted_flag, nonce, chacha_key):
    cipher = ChaCha20.new(key=chacha_key, nonce=base64.b64decode(nonce.encode('utf-8')))
    decrypted_flag = cipher.decrypt(base64.b64decode(encrypted_flag.encode('utf-8')))
    return decrypted_flag.decode('utf-8')

if __name__ == "__main__":
    # Provide the values from the encrypted data
    encrypted_flag = "4HGJ/3Y6iekXR+FXdpdpa+ww4601QUtLGAzHO/8="
    nonce = "nFE+9jfXTKM="
    private_key_d = 56771
    private_key_n = 57833
    encrypted_message = [41179, 49562, 30232, 7343, 51179, 49562, 24766, 36190, 30119, 33040, 22179, 44468, 15095, 22179, 3838, 28703, 32061, 17380, 34902, 51373, 41673, 6824, 41673, 26412, 27116, 51179, 34646, 15095, 10590, 11075, 1613, 20320, 31597, 51373, 20320, 44468, 23130, 47991, 11075, 15095, 34928, 20768, 15095, 8054]

    # Layer 3 Decryption
    private_key = (private_key_d, private_key_n)
    obfuscated_key = base64.b64decode(layer3_decryption(encrypted_message, private_key).encode('utf-8'))

    # Layer 2 (Reversing XOR)
    xor_key = "0x1337"
    chacha_key = bytearray(obfuscated_key[i] ^ ord(xor_key[i % len(xor_key)]) for i in range(len(obfuscated_key)))

    # Layer 1 Decryption
    decrypted_flag = layer1_decryption(encrypted_flag, nonce, chacha_key)
    print(f"[+] Decrypted Flag: {decrypted_flag}")
