from c3_single_byte_xor import single_byte_xor_solver
import binascii

if __name__ == "__main__":
    with open("c4_detect_single_char_xor.txt", "r") as f:
        line = f.readline().rstrip('\n')
        index = 1
        while line:
            print(index)
            print(single_byte_xor_solver(binascii.unhexlify(line)))
            line = f.readline().rstrip('\n')
            index += 1
