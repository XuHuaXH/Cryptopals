from secrets import token_bytes
from base64 import b64decode
from Crypto.Cipher import AES
from c9_pkcs7_padding import pad, unpad


# these constants are used by the blackbox and not accessible by the attacker
KEY = token_bytes(16)
SECRET_STR = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
BLOCK_SIZE = 16


# append SECRET_STR to plaintext and encrypt it using AES ECB
def blackbox(plaintext):
    secret_data = b64decode(SECRET_STR)
    plaintext += secret_data
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def detect_block_size():
    previous_length = len(blackbox(b''))
    ciphertext_length = previous_length
    test_str_length = 1
    while True:
        ciphertext_length = len(blackbox(bytes('a' * test_str_length, 'utf-8')))
        test_str_length += 1
        if ciphertext_length > previous_length:
            first_jump_length = ciphertext_length
            previous_length = first_jump_length
            break

    while True:
        ciphertext_length = len(blackbox(bytes('a' * test_str_length, 'utf-8')))
        test_str_length += 1
        if ciphertext_length > previous_length:
            second_jump_length = ciphertext_length
            break

    return second_jump_length - first_jump_length


# detects whether the blackbox is using ECB or CBC mode
def detect_encryption_mode(block_size):
    test_str = 'r' * block_size + 'r' * block_size
    data = bytes(test_str, 'utf-8')
    ciphertext = blackbox(data)

    if ciphertext[0: block_size] == ciphertext[block_size: 2 * block_size]:
        return 'ECB Mode'
    return 'CBC Mode'


def oracle():
    block_size = detect_block_size()
    print("The block size is " + str(block_size))
    print("The encryption mode is " + detect_encryption_mode(block_size))


if __name__ == "__main__":
    oracle()
