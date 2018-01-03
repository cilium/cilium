import socket, sys

if len(sys.argv) != 6:
  print('Wrong number of arguments. Usage: ./ct-clean-up-nc.py <localport> <timeout> <remote-address> <remote-port> <HTTP path>')

localport = int(sys.argv[1])
timeout = int(sys.argv[2])
serverAddr = sys.argv[3]
serverPort = int(sys.argv[4])
httpPath = sys.argv[5]

if ":" not in serverAddr:
  clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  host = serverAddr
else:
  clientsocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  host = "["+serverAddr+"]"

clientsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
clientsocket.bind(('', localport))
clientsocket.settimeout(timeout)
clientsocket.connect((serverAddr, serverPort))
clientsocket.send('GET '+httpPath+' HTTP/1.1\r\nHost: '+host+
                  '\r\nConnection: close\r\nUser-Agent: curl/7.38.0\r\nAccept: */*\r\n\r\n')

data = clientsocket.recv(4096)
print(data)
