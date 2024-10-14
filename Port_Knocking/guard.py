#!/usr/bin/python
import socket
from os import system

series = [0, 2, 1]

def build_socket():
    lock = []
    for i in range(4000, 5000, 100):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', i))
        s.listen(1)
        lock.append(s)
    return lock

def recv_data(s, length=1):
    conn, addr = s.accept()
    data = conn.recv(length)
    return data, addr[0]

def checkKnock(s, accessIP):
    data, addr = recv_data(s)
    if addr == accessIP and data == b'1': return True
    return False

def knock(lock):
    isPass = 0
    data, accessIP = recv_data(lock[4])
    
    for i in range(3):
        if checkKnock(lock[series[i]], accessIP): 
            print("Knock: " + series[i])
            isPass += 1
        else: break
    
    if isPass == 3:
        print("Opening the door")
        return True
    
    return False

if __name__ == '__main__':
    lock = build_socket()
    print("Guard is up!")
    try:
        if knock(lock): 
            print("Welcome!")
            system("python TFTP/server.py")
        else: print("Go away!")
    except Exception as e:
        print("Error: ", e)
