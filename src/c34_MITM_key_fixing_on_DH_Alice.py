import socket
import hashlib
from c33_implement_diffie_hellman import modexp
from secrets import randbelow
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def send_msg(sock, msg):
    # prepend each message with the length of that message using 4 bytes
    data = len(msg).to_bytes(4, byteorder='big') + msg.encode()
    sock.send(data)


def recv_msg(sock):
    # get the message length first, then receive that many bytes
    msg_length = int.from_bytes(sock.recv(4), byteorder='big')
    data = sock.recv(msg_length)
    if data:
        return data.decode('utf-8')
    else:
        return None


# sends msg encrypted with AES CBC mode with IV appended
def send_encrypted_msg(sock, msg, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(msg.encode(), AES.block_size))
    data = encrypted + cipher.iv
    data = len(data).to_bytes(4, byteorder='big') + data
    sock.send(data)


# receive the AES CBC encrypted data and decrypts it
def recv_encrypted_msg(sock, key):
    data_length = int.from_bytes(sock.recv(4), byteorder='big')
    data = sock.recv(data_length)
    if not data:
        return None
    iv = data[-AES.block_size:]
    data = data[:-AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = unpad(cipher.decrypt(data), AES.block_size).decode('utf-8')
    return msg



# Alice acts as the client
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('0.0.0.0', 3333))  # connects to (supposed Bob but)Eve on port 3333

# send DH public parameters
p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
g = 2
a = randbelow(p)
A = modexp(g, a, p)
print("Sending DH public parameters...")
send_msg(sock, str(p))
send_msg(sock, str(g))
send_msg(sock, str(A))

# receives Bob's public key and computes the shared secret
received = recv_msg(sock)
while not received:
    received = recv_msg(sock)
B = int(received)
s = modexp(B, a, p)

print("the shared secret is " + str(s))

# Alice starts sending encrypted messages
full_lyrics = "BA BA BA BABANANA\nBA BA BA BABANANA BANANA NA AHH, POTATO NA AH AH BANANA AH AH\nTO GA LI NO PO TAH TO NI GAH NI BAH LO BAH NI KAH NO JI GAH BA BA BA BABANANA\nYO PLANO HU LA PA NO NO TU MA BANANA LIKE A NUPI TALAMOO\nBANANA BA BA BABANANA BA BA BA BABANANA\nPOTATO HO HOOOOOO\nTO GA LI NO PO TAH TO NI GAH NI BAH LO BAH NI KAH NO JI\nGAH BA BA BA BABANANAAAAAAAAA".split(
    '\n')
lyrics = [full_lyrics[i] for i in range(0, len(full_lyrics)) if i % 2 == 0]

# derives AES key from the shared secret
hash = hashlib.sha256()
hash.update(str(s).encode('utf-8'))
key = hash.digest()[0: 16]


for sentence in lyrics:
    print("Sending: " + sentence)
    send_encrypted_msg(sock, sentence, key)
    received = recv_encrypted_msg(sock, key)
    while not received:
        received = recv_encrypted_msg(sock, key)
    print("Received: " + received)

sock.close()
