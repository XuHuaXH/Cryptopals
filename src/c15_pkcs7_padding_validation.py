

def unpad(padded):
    if len(padded) == 0:
        raise ValueError("no padding found")
    padding_length = int(padded[len(padded) - 1])
    if len(padded) < padding_length:
        raise ValueError("padding is invalid, padded string not long enough")
    padding = padded[-padding_length:]
    if padding != bytes([padded[len(padded) - 1]]) * padding_length:
        raise ValueError("padding is invalid, padding characters are inconsistent")
    else:
        return padded[: -padding_length]


if __name__ == "__main__":
    data = bytes('ICE ICE BABY', 'utf-8') + 4 * bytes([5])
    print(unpad(data))
