import string
import binascii
from c2_fixed_xor import xor_bytes


# takes a hex encoded string and returns all possible results
# of it being xored against a single character in lowercase
def single_byte_xor_brute_force(data):
    result = {}
    for i in string.printable:
        key = (i * len(data)).encode()
        try:
            result[i] = xor_bytes(data, key).decode("ascii")
        except UnicodeDecodeError:
            result[i] = 'z' * len(data)
    return result


# convert str to lowercase and then compute its frequency
# score. The lower the score is, the closer
# the frequencies are to those of English text.
def get_frequency_score(str):
    abs_freq = {'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025, 'm': 0.02406,
                'n': 0.06749, 'o': 0.07507, 'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056, 'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974, 'z': 0.00074, ' ': 0.1831685}

    # obs_freq stores the observed frequency in str
    # exp_freq stores the expected frequency in English text
    obs_freq = {}
    exp_freq = {}
    str = str.lower()

    # initialize the frequency tables
    for i in string.printable:
        obs_freq[i] = 0
        exp_freq[i] = 0

    # populate the observed frequency table with data
    for c in str:
        if c in obs_freq:
            obs_freq[c] += 1

    # populate the expected frequency table with data
    for c in exp_freq:
        if c in abs_freq:
            exp_freq[c] = abs_freq[c] * len(str)

    # compute the score
    score = 0
    for c in string.printable:
        score += (exp_freq[c] - obs_freq[c]) ** 2
    return score


def single_byte_xor_solver(data):
    all_results = single_byte_xor_brute_force(data)
    key = string.printable[0]
    min_score = get_frequency_score(all_results[string.printable[0]])

    for i in string.printable:
        score = get_frequency_score(all_results[i])
        # print("%f using %s" % (score, i))
        if (score < min_score):
            key = i
            min_score = score
    # print("Key: " + key)
    # print("Plaintext: " + all_results[key])
    # print(min_score)
    key = key * len(data)
    return xor_bytes(data, key.encode()).decode('ascii')


if __name__ == "__main__":
    hexstr = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    data = binascii.unhexlify(hexstr)
    print(single_byte_xor_solver(data))
