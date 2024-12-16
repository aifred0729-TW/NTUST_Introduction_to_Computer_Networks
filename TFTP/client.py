#!/usr/bin/python
import socket, random, sys
from struct import pack

HOST = "127.0.0.1"
PORT = 69
NULL = b'\0'

def initialize():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return s

def receiveData(s):
    data, addr = s.recvfrom(1024)
    return data, addr

def getOpcode(data):
    return int.from_bytes(data[0:2], byteorder='big')


def buildRequest(opcode, filename=None, mode=None, block=None, data=None):
    #   0x1 = Read (RRQ)
    #   0x2 = Write (WRQ)
    #   0x3 = Data (DATA)
    #   0x4 = Acknowledgment (ACK)
    #   0x5 = Error (ERROR)
    
    buffer = pack("!H", opcode)

    if opcode == 0:
        pass
    elif opcode == 1 or opcode == 2:
        buffer += filename + NULL
        buffer += mode + NULL
    elif opcode == 3:
        buffer += pack("!H", block)
        buffer += data
    elif opcode == 4:
        buffer += pack("!H", block)
    elif opcode == 5:
        buffer += pack("!H", block)
        buffer += data + NULL
    else:
        return None

    return buffer

def sendFile(s, addr, filename):

    file = open(filename, "rb")
    block = 1

    while True:

        fileData = file.read(512)
        data = buildRequest(3, block=block, data=fileData)
        s.sendto(data, addr)
        print("[+] DST : " + addr[0] + ":" + str(addr[1]) + " - Sent block: " + str(block) + " Size: " + str(len(data)))
        print("[+] ----- Waiting for ACK from " + addr[0] + ":" + str(addr[1]) + " -----")
        blockACK = processRequest(s)
        if blockACK != block:
            print("[!] SRC : " + addr[0] + ":" + str(addr[1]) + " Failed to receive ACK for block: " + str(block))
            data = buildRequest(5, block=block, data=b"Failed to send block" + NULL)
            s.sendto(data, addr)
            break
        elif len(fileData) < 512: break
        block += 1
    
    file.close()

def receiveFile(s, addr, filename):
    
    blockACK, newPort = processRequest(s)
    if blockACK != 0: return
    addr = (addr[0], newPort)

    print("[+] CheckACK ID is zero from " + addr[0] + ":" + str(addr[1]))

    block = 1
    blockData = b""

    while True:
        blockReceive, tmpBlockData, dataEnd = processRequest(s)
        blockData += tmpBlockData

        print("[+] SRC : " + addr[0] + ":" + str(addr[1]) + " - Received block: " + str(blockReceive))
        sendACK(s, addr, block)

        if block != blockReceive: 
            print("[+] " + addr[0] + ":" + str(addr[1]) + " Failed to receive block: " + str(block))
            data = buildRequest(5, block=block, data=b"Failed to receive block" + NULL)
            s.sendto(data, addr)
            return
        elif dataEnd: break

        block += 1

    file = open(filename, "wb")
    file.write(blockData)
    file.close()

def sendACK(s, addr, block):
    data = buildRequest(4, block=block)
    s.sendto(data, addr)
    print("[+] DST : " + addr[0] + ":" + str(addr[1]) + " - Sent ACK block: " + str(block))
    return

def parseRRQ(data):

    #  string       string
    #  +---~~---+---+---~~---+---+
    #  |filename| 0 |  mode  | 0 |
    #  +---~~---+---+---~~---+---+

    filename = data.split(NULL)[0]
    mode = data[len(filename)+1:].split(NULL)[0]
    return filename, mode

def parseWRQ(data):

    #   string       string
    #  +---~~---+---+---~~---+---+
    #  |filename| 0 |  mode  | 0 |
    #  +---~~---+---+---~~---+---+

    filename = data.split(NULL)[0]
    mode = data[len(filename)+1:].split(NULL)[0]
    return filename, mode

def parseDATA(data):
    
    #    2 bytes       n bytes
    #  +-------------------------+
    #  |   Block #  |   Data     |
    #  +-------------------------+

    block = int.from_bytes(data[:2], byteorder='big')
    data = data[2:]
    if len(data) < 512 : return block, data, True
    return block, data, False

def parseACK(data):
    
    #   2 bytes
    #  +----------+
    #  |  Block # |
    #  +----------+

    return int.from_bytes(data, byteorder='big')

def processRequest(s):

    data, addr = receiveData(s)
    opcode = getOpcode(data)
    data = data[2:] # Remove opcode

    # print("====================================================")
    # print("[+] Received opcode: " + str(opcode))
    # print("[+] Received data size: " + str(len(data)))
    # print("[+] Received data:", data)
    # print("[+] Received addr: " + addr[0] + ":" + str(addr[1]))
    # print("--------------------------------------------------------")

    if opcode == 0:
        
        print("[+] Received response from server")  
        print("[+] DST : " + addr[0] + ":" + str(addr[1]) + " - Sent list of files")
        print(data.decode())
        
    elif opcode == 1:
        filename, mode = parseRRQ(data)

        print("[+] SRC : " + addr[0] + ":" + str(addr[1]) + " - Requested to read file: " + filename.decode() + " with mode: " + mode.decode())

        sFile = initialize(random.randint(50000, 65535))

        sendACK(sFile, addr, 0)
        sendFile(sFile, addr, filename)

        print("====================================================")
    elif opcode == 2:
        filename, mode = parseWRQ(data)
        print("[+] SRC : " + addr[0] + ":" + str(addr[1]) + " - Requested to write file: " + filename.decode() + " with mode: " + mode.decode())
        receiveFile(s, addr, filename)
    elif opcode == 3:
        return parseDATA(data)
    elif opcode == 4:
        block = parseACK(data)
        print("[+] SRC : " + addr[0] + ":" + str(addr[1]) + " - Received ACK for block: " + str(block))
        print("====================================================")
        if block == 0 : return block, addr[1]
        return block
    else:
        print("[+] " + addr[0] + ":" + str(addr[1]) + " Invalid request")
        return None

    print("____________________________________________________")
    return

if __name__ == "__main__":

    if len(sys.argv) < 3 and sys.argv[1] != "ls":
        print("[!] Usage: python client.py {option} {filename}")
        print("[!] Option: 0 = read | 1 = write")
        print("[!] Filename: file to read or write")
        print("[!] Special Option: ls")
        sys.exit(1)

    s = initialize()
    
    if sys.argv[1] == "ls":
        print("[+] Sending request to " + HOST + " on port " + str(PORT))
        print("[+] Request to list files")

        data = buildRequest(0)
        s.sendto(data, (HOST, PORT))
        processRequest(s)
        s.close()
        sys.exit(0)

    filename = sys.argv[2].encode()

    if sys.argv[1] == "0":
        print("[+] Sending request to " + HOST + " on port " + str(PORT))
        print("[+] Request RRQ")


        data = buildRequest(1, filename, b"ascii")
        s.sendto(data, (HOST, PORT))
        receiveFile(s, (HOST, PORT), filename)

        print("[+] Received response from server: " + data.decode())
        s.close()
        sys.exit(0)

    elif sys.argv[1] == "1":
        print("[+] Sending request to " + HOST + " on port " + str(PORT))
        print("[+] Request WRQ")

        data = buildRequest(2, filename, b"ascii")
        s.sendto(data, (HOST, PORT))
        sendACK(s, (HOST, PORT), 0)
        sendFile(s, (HOST, PORT), filename)

        print("[+] Received response from server: " + data.decode())
        s.close()
        sys.exit(0)
    