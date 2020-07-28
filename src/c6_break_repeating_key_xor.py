import binascii
from c3_single_byte_xor import single_byte_xor_solver
from c5_repeating_key_xor_encrypt import repeating_key_xor_transform
from c5_repeating_key_xor_encrypt import repeating_key_xor_encrypt


def hamming_distance(data1, data2):
    if (len(data1) != len(data2)):
        print("Two inputs do not have the same length.")
        return

    count = 0
    for i, j in zip(data1, data2):
        diff = i ^ j
        for k in range(8):
            count += (diff & 1)
            diff >>= 1
    return count


def guess_keysize(data, min_keysize, max_keysize):
    candidate = 0
    min_normalized_distance = 0.0

    for keysize in range(min_keysize, max_keysize + 1):
        chunks = [data[i: i + keysize] for i in range(0, len(data), keysize)]
        average = 0

        # take the average of 3 hamming distances
        for i in range(0, 6):
            average += hamming_distance(chunks[i], chunks[i + 1])
        average = average / 6.0
        normalized = average / (keysize + 0.0)
        print("Gussing key length " + str(keysize) + " normalized distance: " + str(normalized))

        if (keysize == min_keysize) or (normalized < min_normalized_distance):
            candidate = keysize
            min_normalized_distance = normalized

    return candidate


def break_repeating_key_xor(data, keysize):
    key = ''
    for i in range(0, keysize):
        slice = data[i: len(data): keysize]
        key += single_byte_xor_solver(slice)
    print("key is " + key)
    return repeating_key_xor_transform(data, key)


if __name__ == "__main__":

    # print(hammingDistance('this is a test', 'wokka wokka!!!'))
    f = open("c6_break_repeating_key_xor.txt", "r")
    content = ''.join(f.read().split('\n'))
    data = binascii.a2b_base64(content)

    plaintext = "Midwinter spring is its own season\nSempiternal though sodden towards sundown,\nSuspended in time, between pole and tropic.\nWhen the short day is brightest, with frost and fire,\nThe brief sun flames the ice, on pond and ditches,\nReflecting in a watery mirror\nA glare that is blindness in the early afternoon.\nAnd glow more intense than blaze of branch, or brazier,\nStirs the dumb spirit: no wind, but pentecostal fire\nIn the dark time of the year. Between melting and freezing\nThe soul's sap quivers. There is no earth smell\nOr smell of living thing. This is the spring time\nBut not in time's covenant. Now the hedgerow\nIs blanched for an hour with transitory blossom\nOf snow, a bloom more sudden\nThan that of summer, neither budding nor fading,\nNot in the scheme of generation.\nWhere is the summer, the unimaginable\nZero summer?"
    encrypted = repeating_key_xor_encrypt(plaintext, "rising")
    print(encrypted)
    data = binascii.unhexlify(encrypted)
    # hexstr = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    # data = binascii.unhexlify(hexstr)

    keysize = guess_keysize(data, 1, 20)
    print("keysize is ", keysize)

    print(break_repeating_key_xor(data, keysize))
