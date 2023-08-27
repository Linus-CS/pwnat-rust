import socket as s
import threading

socket = s.socket(s.AF_INET, s.SOCK_DGRAM)
socket.bind(("", 799))


def set_interval(func, sec):
    def func_wrapper():
        set_interval(func, sec)
        func()
    t = threading.Timer(sec, func_wrapper)
    t.start()
    return t


def sending():
    global socket
    out = socket.sendto(b"\x01\x02\x03\x04", ("192.168.0.3", 3478))
    print(out)


# set_interval(sending, 1)
data, addr = socket.recvfrom(1024)
print(data)
socket.close()
