import socket, sys

if len(sys.argv) != 6:
  print('Wrong number of arguments. Usage: ./21-ct-clean-up-nc.py <localport> <timeout> <remote-address> <remote-port> <HTTP path>')

localport = int(sys.argv[1])
timeout = int(sys.argv[2])
serverAddr = sys.argv[3]
serverPort = int(sys.argv[4])
httpPath = sys.argv[5]

if ":" not in serverAddr:
  clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
else:
  clientsocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

clientsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
clientsocket.bind(('', localport))
clientsocket.settimeout(timeout)
clientsocket.connect((serverAddr, serverPort))
clientsocket.send('GET '+httpPath+' HTTP/1.0\r\n\r\n')

data = clientsocket.recv(4096)
print(data)
