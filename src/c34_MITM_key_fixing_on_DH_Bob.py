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


# Bob acts as the server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('0.0.0.0', 2222))
sock.listen()

conn, addr = sock.accept()

# Receives DH public parameters from Eve(supposedly from Alice)
p = int(recv_msg(conn))
print("Received p = " + str(p))
g = int(recv_msg(conn))
print("Received g = " + str(g))
A = int(recv_msg(conn))
print("Received A = " + str(A))

# computes Bob's public key B
b = randbelow(p)
B = modexp(g, b, p)

# computes the shared secret
s = modexp(A, b, p)
print("the shared secret is " + str(s))

# sends Alice the public key
send_msg(conn, str(B))

# derives AES key from the shared secret
hash = hashlib.sha256()
hash.update(str(s).encode('utf-8'))
key = hash.digest()[0: 16]

# Bob starts sending encrypted messages
full_lyrics = "BA BA BA BABANANA\nBA BA BA BABANANA BANANA NA AHH, POTATO NA AH AH BANANA AH AH\nTO GA LI NO PO TAH TO NI GAH NI BAH LO BAH NI KAH NO JI GAH BA BA BA BABANANA\nYO PLANO HU LA PA NO NO TU MA BANANA LIKE A NUPI TALAMOO\nBANANA BA BA BABANANA BA BA BA BABANANA\nPOTATO HO HOOOOOO\nTO GA LI NO PO TAH TO NI GAH NI BAH LO BAH NI KAH NO JI\nGAH BA BA BA BABANANAAAAAAAAA".split(
    '\n')
lyrics = [full_lyrics[i] for i in range(0, len(full_lyrics)) if i % 2 != 0]

for sentence in lyrics:
    received = recv_encrypted_msg(conn, key)
    while not received:
        received = recv_encrypted_msg(conn, key)
    print("Received: " + received)
    print("Sending: " + sentence)
    send_encrypted_msg(conn, sentence, key)

sock.close()
