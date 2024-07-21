import socket as s

socket = s.socket(s.AF_INET, s.SOCK_DGRAM)
socket.sendto(b"hey", ("195.90.213.214", 8080))
print("send.")
