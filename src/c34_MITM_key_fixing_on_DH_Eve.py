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


# Eve opens up two sockets, sock1 accepts connection from Alice, sock2 sends messages to Bob
sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock1.bind(('0.0.0.0', 3333))
sock1.listen()

sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock2.connect(('0.0.0.0', 2222))

conn1, addr1 = sock1.accept()

# receives DH public parameters from Alice
p = int(recv_msg(conn1))
print("p is " + str(p))
g = int(recv_msg(conn1))
print("g is " + str(g))
A = int(recv_msg(conn1))
print("A is " + str(A))

# forwards modified parameters to Bob
send_msg(sock2, str(p))
send_msg(sock2, str(g))
send_msg(sock2, str(p))

# receives Bob's public key
B = int(recv_msg(sock2))
# sends bogus Bob's public key to Alice
send_msg(conn1, str(p))

# prepares the fixed AES key to decrypt further messages
hash = hashlib.sha256()
hash.update(str(0).encode('utf-8'))
key = hash.digest()[0: 16]

# relays encrypted messages between Alice and Bob, at the same time decrypting them
while True:
    from_Alice = recv_encrypted_msg(conn1, key)
    while not from_Alice:
        from_Alice = recv_encrypted_msg(conn1, key)
    print("Alice said: " + from_Alice)
    send_encrypted_msg(sock2, from_Alice, key)

    from_Bob = recv_encrypted_msg(sock2, key)
    while not from_Bob:
        from_Bob = recv_encrypted_msg(sock2, key)
    print("Bob said: " + from_Bob)
    send_encrypted_msg(conn1, from_Bob, key)

sock1.close()
sock2.close()
