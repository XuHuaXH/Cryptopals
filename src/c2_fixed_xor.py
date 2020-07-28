import binascii


# takes two equal length bytes object and return their xor in bytes
def xor_bytes(data1, data2):
    if (len(data1) != len(data2)):
        print("Two bytes object must be of equal length!")
        return

    result = b''
    for (i, j) in zip(data1, data2):
        result += chr(i ^ j).encode()
    return result


# takes two equal length hex encoded strings and return their xor, hex encoded
def xor_hex(hexstr1, hexstr2):
    # convert to bytes for XOR operation
    data1 = binascii.unhexlify(hexstr1)
    data2 = binascii.unhexlify(hexstr2)
    return binascii.hexlify(xor_bytes(data1, data2)).decode("ascii")


if __name__ == "__main__":
    s1 = "1c0111001f010100061a024b53535009181c"
    s2 = "686974207468652062756c6c277320657965"
    res = "746865206b696420646f6e277420706c6179"
    print(xor_hex(s1, s2) == res)  # should output True
