from Crypto.Cipher import AES
import base64


if __name__ == "__main__":
    key = 'YELLOW SUBMARINE'
    cipher = AES.new(key, AES.MODE_ECB)

    with open("c7_aes_in_ecb_mode.txt", "r") as f:
        data = f.read()

    ciphertext = base64.b64decode(data)
    plaintext = cipher.decrypt(ciphertext).decode('ascii')
    print(plaintext)
