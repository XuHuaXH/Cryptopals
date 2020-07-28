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


# determines the length of the secret string
def detect_length(block_size):
    initial_length = len(blackbox(b''))
    prepend_length = 1
    while True:
        ciphertext_length = len(blackbox(bytes('a' * prepend_length, 'utf-8')))
        if ciphertext_length > initial_length:
            return (block_size - prepend_length) + (initial_length - 16)
        prepend_length += 1


def make_dictionary(dict_prefix):
    dict = {}
    keys = [bytes([x]) for x in range(256)]
    for key in keys:
        dict[key] = blackbox(dict_prefix + key)[0: 16]
    return dict


def extract(length):
    result = b''
    index = 0

    while index < length:
        if index <= 15:
            dict_prefix = bytes('a' * (15 - index), 'utf-8') + result[0: index]
            prepend_length = 15 - index
            output_block = blackbox(bytes('a' * prepend_length, 'utf-8'))[0: 16]
        else:
            dict_prefix = result[index - 15: index]
            prepend_length = 15 - index
            while prepend_length < 0:
                prepend_length += 16
            output_block = blackbox(bytes('a' * prepend_length, 'utf-8')
                                    )[index - 15 + prepend_length: index + 1 + prepend_length]

        dict = make_dictionary(dict_prefix)
        for key in dict:
            if dict[key] == output_block:
                result += key
                break
        index += 1

    return result


def oracle():
    block_size = detect_block_size()
    print("The block size is " + str(block_size))
    print("The encryption mode is " + detect_encryption_mode(block_size))
    length = detect_length(block_size)
    print("The length of the secret string is " + str(length))
    secret_str = extract(length).decode('utf-8')
    print(secret_str)


if __name__ == "__main__":
    oracle()
