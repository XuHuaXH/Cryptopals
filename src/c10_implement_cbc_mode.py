from Crypto.Cipher import AES
import base64
from c9_pkcs7_padding import pad, unpad


BLOCK_SIZE = 16


# takes two equal length byte objects and return their xor in bytes
def xor(data1, data2):
    if (len(data1) != len(data2)):
        print("Two byte objects must be of equal length!")
        return

    result = b''
    for i, j in zip(data1, data2):
        result += bytes([i ^ j])
    return result


def encrypt_block(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def decrypt_block(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def cbc_encrypt(plaintext, IV, key):
    padded = pad(plaintext, BLOCK_SIZE)
    plaintext_blocks = [padded[i: i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]

    ciphertext_blocks = []
    P1 = plaintext_blocks[0]
    C1 = encrypt_block(xor(P1, IV), key)
    prev_ciphertext = C1
    ciphertext_blocks.append(C1)

    for i in range(1, len(plaintext_blocks)):
        curr_plaintext = plaintext_blocks[i]
        ciphertext = encrypt_block(xor(curr_plaintext, prev_ciphertext), key)
        prev_ciphertext = ciphertext
        ciphertext_blocks.append(ciphertext)

    return b''.join(ciphertext_blocks)


def cbc_decrypt(ciphertext, IV, key):
    if len(ciphertext) % 16 != 0:
        print("ciphertext length is incorrect!")
        return

    ciphertext_blocks = [ciphertext[i: i + BLOCK_SIZE]
                         for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext_blocks = []
    B1 = xor(decrypt_block(ciphertext_blocks[0], key), IV)
    plaintext_blocks.append(B1)

    for i in range(1, len(ciphertext_blocks)):
        plaintext = xor(decrypt_block(ciphertext_blocks[i], key), ciphertext_blocks[i - 1])
        plaintext_blocks.append(plaintext)

    return unpad(('').join(plaintext_blocks), BLOCK_SIZE)


if __name__ == "__main__":

    key = bytes('YELLOW SUBMARINE', 'utf-8')
    IV = bytes('0' * 16, 'utf-8')

    with open("c10_cbc_ciphertext.txt", "r") as f:
        ciphertext = f.read()
    ciphertext = base64.b64decode(ciphertext)
    print("ciphertext is " + ciphertext)
    # plaintext = cbc_decrypt(ciphertext, IV, key)
    # print(plaintext)
