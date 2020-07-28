from Crypto.Cipher import AES
import base64
from c9_pkcs7_padding import pad, unpad


BLOCK_SIZE = 16


# takes two equal length byte objects and return their xor in bytes
def xor(data1, data2):
    if (len(data1) != len(data2)):
        print("Two strings must be of equal length!")
        return

    result = ''
    for (i, j) in zip(data1, data2):
        result += chr(i ^ j)
    return result


def encrypt_block(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


if __name__ == "__main__":
    data = bytes('abcd' * 4, 'utf-8')
    print(encrypt_block(data, data))
