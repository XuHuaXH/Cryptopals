import binascii


def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = chr(padding_length) * padding_length
    return data + bytes(padding, 'utf-8')


def unpad(padded, block_size):
    if len(padded) % block_size != 0:
        print("Warning: the padded data does not have the correct size.")
    padding_length = padded[len(padded) - 1]
    return padded[: -padding_length]


if __name__ == "__main__":
    data = bytes("YELLOW SUBMARINE", 'utf-8')
    padded = pad(data, 30)
    print(unpad(padded, 30).decode('utf-8'))
