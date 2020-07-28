import binascii
import base64


def hex_to_base64(data):
    data = binascii.b2a_base64(binascii.unhexlify(data)).decode("ascii").strip()
    return data


if __name__ == "__main__":
    data = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print(hex_to_base64(data) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
