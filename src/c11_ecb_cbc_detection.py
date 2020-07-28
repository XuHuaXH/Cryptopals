from secrets import token_bytes
from random import randint
from Crypto.Cipher import AES
from c10_implement_cbc_mode import cbc_encrypt
from c9_pkcs7_padding import pad, unpad


BLOCK_SIZE = 16

# preprocess the plaintext by adding 5-10 random bytes at the beginning and the end


def preprocess(plaintext):
    prefix_length = randint(5, 10)
    suffix_length = randint(5, 10)
    prefix = token_bytes(prefix_length)
    suffix = token_bytes(suffix_length)
    return prefix + plaintext + suffix


# encrypt the plaintext using cbc 1/2 of the time and ecb 1/2 of the time
def encryption_blackbox(plaintext):
    plaintext = preprocess(plaintext)
    key = token_bytes(16)
    IV = token_bytes(16)
    cbc_mode = randint(0, 1) == 1
    if cbc_mode:
        ciphertext = cbc_encrypt(plaintext, IV=IV, key=key)
        print("Blackbox is using CBC Mode")
    else:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
        print("Blackbox is using ECB Mode")
    return ciphertext


# feed plaintext into the blackbox, then determines the encryption mode from the ciphertext
def encryption_oracle(plaintext):
    test_str = 'r' * 11 + 'r' * 16 + 'r' * 16
    data = bytes(test_str, 'utf-8')
    ciphertext = encryption_blackbox(data)

    if ciphertext[16: 32] == ciphertext[32: 48]:
        return 'ECB Mode'
    return 'CBC Mode'


if __name__ == "__main__":
    plaintext = bytes('hello hello', 'utf-8')
    print("The oracle detects " + encryption_oracle(plaintext))
