from Crypto.Cipher import AES
from binascii import unhexlify


if __name__ == "__main__":
    CHUNK_SIZE = 32
    candidates = []

    with open("c8_detect_aes_in_ecb_mode.txt", "r") as f:
        line = f.readline().rstrip('\n')

        while line:
            # split each line into 32 hex character chunks
            chunks = [line[i: i + CHUNK_SIZE] for i in range(0, len(line), CHUNK_SIZE)]
            candidates.append(set(chunks))
            line = f.readline().rstrip('\n')

    for chunks in candidates:
        print(len(chunks))

    # from the printed number of unique chunks in each cadidate we see that one of them is significantly smaller. Since it is encrypted using ECB mode, repeated data at 16-byte offsets becomes the same ciphertext chunks.
