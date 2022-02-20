import logging
import time
import socket
import socketserver
from server_lib import UDPHandler

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO,
                        datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    ipaddress = socket.gethostbyname(socket.gethostname() + ".local")
    port = 5070
    logging.info(ipaddress)
    print("IP address:", ipaddress)
    print("Port:", port)
    print("Server is running...")
    server = socketserver.UDPServer((ipaddress, port), UDPHandler)
    server.serve_forever()
