#!/usr/bin/env python2

# Do NOT change this file!

import sys
import socket
import threading


SERVER_PORT = 9182
BYTES_PER_MSG = 4096
NUM_MSGS = 10

clientRelease = threading.Semaphore(0)    # Used to ensure that the client thread
                                          # doesn't try to connect to the server
                                          # thread until the server has opened
                                          # its listening socket.


def die(msg):
    print msg
    sys.exit(-1)


def client(serverIpAddr):
    print "client: starting . . ."
    clientRelease.acquire()
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSock.connect((serverIpAddr, SERVER_PORT))
    for i in range(NUM_MSGS):
        bytesRemaining = BYTES_PER_MSG
        while bytesRemaining > 0:
            buf = clientSock.recv(bytesRemaining)
            if len(buf) == 0:
                die("client: zero-length socket read()")
            bytesRemaining -= len(buf)
        print "client: received msg[%d]" % i
    clientSock.close()
    print "client: done."


def server(serverIpAddr):
    print "server: starting . . ."
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSock.bind((serverIpAddr, SERVER_PORT))
    serverSock.listen(1)

    clientRelease.release()
    (clientSock, clientAddr) = serverSock.accept()
    print "server: received connection from [%s]" % `clientAddr`
    for i in range(NUM_MSGS):
        msg = "x" * BYTES_PER_MSG
        bytesSent = clientSock.send(msg)
        if bytesSent != len(msg):
            die("server: unexpected short count on send()")
        print "server: sent msg[%d]" % i
    clientSock.close()
    serverSock.close()
    print "server: done."


def runTest(localIpAddr):
    c = threading.Thread(target=client, args=(localIpAddr,))
    s = threading.Thread(target=server, args=(localIpAddr,))

    c.start()
    s.start()

    c.join()
    s.join()


def main():
    if len(sys.argv) != 2:
        die("USAGE: %s ipAddrToBindTo" % sys.argv[0])
    runTest(sys.argv[1])


if __name__ == "__main__":
    main()
