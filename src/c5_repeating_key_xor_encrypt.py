from c2_fixed_xor import xor_bytes
from binascii import hexlify


# returns a string of length length which is str on repeat
def repeat_string(str, length):
    return str * (int)(length / len(str)) + str[0: length % len(str)]

# returns str encrypted with repeated key, hex encoded


def repeating_key_xor_encrypt(str, key):
    bytes = str.encode()
    key_bytes = repeat_string(key, len(str)).encode()
    return hexlify(xor_bytes(bytes, key_bytes)).decode("ascii")


# doubles as encryption and decryption function
def repeating_key_xor_transform(data, key):
    key_bytes = repeat_string(key, len(data)).encode()
    return xor_bytes(data, key_bytes)


if __name__ == "__main__":
    str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    print(repeating_key_xor_encrypt(str, "ICE") ==
          "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
