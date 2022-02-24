import logging
import time
import socket
import socketserver
from server_lib import server

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO,
                        datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    port = 5070
    #server = socketserver.UDPServer((ipaddress, port), UDPHandler)
    server.serve_forever()
