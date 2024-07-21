import socket as s

socket = s.socket(s.AF_INET, s.SOCK_DGRAM)
socket.bind(("0.0.0.0", 8080))
print("Sock name: ", socket.getsockname())

while True:
    msg, addr = socket.recvfrom(1024)
    print(msg.decode(), " from ", addr)
