#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
import copy
import socketserver as SocketServer
import re
import socket
# import threading
import sys
import time
import logging
import json

file = open("codes.json", "r")
code_messages = json.load(file)
file.close()

PORT = 5070
HOST = socket.gethostbyname(socket.gethostname() + ".local")
rx_ok = re.compile(b".*200")
rx_trying = re.compile(b".*100")
rx_ringing = re.compile(b".*180")


rx_register = re.compile(b"^REGISTER")
rx_invite = re.compile(b"^INVITE")
rx_ack = re.compile(b"^ACK")
rx_prack = re.compile(b"^PRACK")
rx_cancel = re.compile(b"^CANCEL")
rx_bye = re.compile(b"^BYE")
rx_options = re.compile(b"^OPTIONS")
rx_subscribe = re.compile(b"^SUBSCRIBE")
rx_publish = re.compile(b"^PUBLISH")
rx_notify = re.compile(b"^NOTIFY")
rx_info = re.compile(b"^INFO")
rx_message = re.compile(b"^MESSAGE")
rx_refer = re.compile(b"^REFER")
rx_update = re.compile(b"^UPDATE")
rx_from = re.compile(b"^From:")
rx_cfrom = re.compile(b"^f:")
rx_to = re.compile(b"^To:")
rx_cto = re.compile(b"^t:")
rx_tag = re.compile(b";tag")
rx_contact = re.compile(b"^Contact:")
rx_ccontact = re.compile(b"^m:")
rx_uri = re.compile(b"sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile(b"sip:([^ ;>$]*)")
# rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile(b"^SIP/2.0 ([^ ]*)")
rx_invalid = re.compile(b"256") # re.compile(b"^192\.168")
rx_invalid2 = re.compile(b"256") # re.compile(b"^10\.")
# rx_cseq = re.compile("^CSeq:")
# rx_callid = re.compile("Call-ID: (.*)$")
# rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile(b"^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile(b"^Route:")
rx_contentlength = re.compile(b"^Content-Length:")
rx_ccontentlength = re.compile(b"^l:")
rx_via = re.compile(b"^Via:")
rx_cvia = re.compile(b"^v:")
rx_branch = re.compile(b";branch=([^;]*)")
rx_rport = re.compile(b";rport$|;rport;")
rx_contact_expires = re.compile(b"expires=([^;$]*)")
rx_expires = re.compile(b"^Expires: (.*)$")

# global dictionnary
#recordroute = ""
#topvia = ""
registrar = {}

recordroute = "Record-Route: <sip:%s:%d;lr>" % (HOST, PORT)
topvia = "Via: SIP/2.0/UDP %s:%d" % (HOST, PORT)


class Call:
    def __init__(self, caller, calling, start_time):
        self.caller = caller
        self.calling = []
        self.calling.append(calling)
        self.start_time = start_time
        self.end_time = None
        self.bye_count = 0


class Logs:
    def __init__(self):
        self.log_array = []
        self.file = None
        self.calls = []

    def write_to_file(self, call: Call):
        self.file = open("logs.txt", "a")
        self.file.writelines(["----Call----\n",
                              "From: " + str(call.caller) + "\n",
                              "To: " + str(call.calling) + "\n",
                              "Start time: " + str(call.start_time) + "\n",
                              "End time:" + str(call.end_time) + "\n",
                              "\n"])
        self.file.close()

    def add_log(self, log):
        log = copy.deepcopy(log)
        for i in range(len(log)):
            if isinstance(log[i], str):
                log[i] = bytes(log[i], "utf-8")
        self.log_array = log
        self.find_logs()

    def check_call(self, caller, calling, index):
        call_class: Call
        call_class = self.calls[index]
        if call_class.caller == caller and calling in call_class.calling:
            return True
        elif call_class.caller == caller:
            call_class.calling.append(calling)
            self.calls[index] = call_class
            return True
        else:
            return False

    def check_finished_calls(self):
        for i in range(len(self.calls)):
            if self.calls[i].bye_count == len(self.calls[i].calling):
                self.calls[i].end_time = str(time.strftime("%H:%M:%S ", time.localtime()))
                self.write_to_file(self.calls[i])
                self.calls.pop(i)
                return
        return

    def find_logs(self):
        caller = ""
        calling = ""
        if rx_ringing.search(self.log_array[0]):
            for line in self.log_array:
                if rx_from.search(line):
                    caller = str(rx_uri.search(line).group(), "utf-8")

                elif rx_to.search(line):
                    calling = str(rx_uri.search(line).group(), "utf-8")

            written = False
            for i in range(len(self.calls)):
                if written is False:
                    written = self.check_call(caller, calling, i)
                else:
                    break
            if written is False:
                self.calls.append(Call(caller, calling, str(time.strftime("%H:%M:%S ", time.localtime()))))

        elif rx_bye.search(self.log_array[0]):
            for line in self.log_array:
                if rx_from.search(line):
                    caller = str(rx_uri.search(line).group(), "utf-8")

                elif rx_to.search(line):
                    calling = str(rx_uri.search(line).group(), "utf-8")
            for i in range(len(self.calls)):
                if self.calls[i].caller == caller or self.calls[i].caller == calling:
                    self.calls[i].bye_count += 1
                    break
            self.check_finished_calls()


    """   def find_register(self, start_index):
        # 1 register and 1 OK
        uri_id = ""
        for i in range(start_index, len(self.log_array)):
            log = self.log_array[i]
            if rx_register.search(log[0]):
                # find the unique address
                uri_id = self.find_uri_id(log)
    
            for k in range(i, len(self.log_array)):
                sec_log = self.log_array[k]
                if rx_ok.search(sec_log[0]):
                    if uri_id == self.find_uri_id(sec_log):
                        # register found
                        self.write_to_file("User registered: " + str(uri_id))
                        self.delete_logs.append(i)
                        self.delete_logs.append(k)
                        return
    
    def find_uri_id(self, log):
        for line in log:
            if rx_uri.search(line):
                #s = str(line, "utf-8")
                #start = s.find("sip:") + len("sip:")
                #end = s.find("@")
                #uri_id = s[start:end]
                uri_id = rx_uri.search(line).group()
                return uri_id
        return ""
    
    """




log_class = Logs()


def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, b'\000')
        #logging.debug("%s%s%s" % (sep.join("%02x" % ord(c) for c in line), sep, quotechars(line)))


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)


def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))


class UDPHandler(SocketServer.BaseRequestHandler):

    def debugRegister(self):
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key, registrar[key][0]))
        logging.debug("*****************")

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
        branch = ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch.decode('utf-8'))
                    data.append(bytes(via[2:], encoding="utf-8"))
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace(b"rport", bytes(text, encoding="utf-8"))
                    via = via.decode('utf-8')
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line.decode('utf-8'), text)
                data.append(bytes(via, encoding="utf-8"))

            else:
                data.append(line)
        return data

    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(bytes(topvia, "utf-8")):
                    data.append(line)
            else:
                data.append(line)
        return data

    def checkValidity(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("registration for %s has expired" % uri)
            return False

    def getSocketInfo(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return (socket, client_addr)

    def getDestination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" % (md.group(1), md.group(2))
                break
        return origin

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = bytes(request_uri, "utf-8")
        index = 0
        data = []
        for line in self.data:
            # data.append(line)
            try:
                line = bytes(line, "utf-8")
            except TypeError:
                if len(line) == 0:
                    line = b""
                pass
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = b"%s%s" % (line, b";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace(b"rport", bytes(text, "utf-8"))
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line, text)
            if rx_contentlength.search(line):
                data[index] = b"Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = b"l: 0"
            index += 1
            if len(line) == 0:
                break
        data.append(b"")
        text = b"\r\n".join(data)
        self.socket.sendto(text, self.client_address)
        showtime()
        logging.info("<<< %s" % data[0])
        logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRegister(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        for line in self.data:
            if isinstance(line, str):
                line = bytes(line, "utf-8")
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)

        if rx_invalid.search(contact) or rx_invalid2.search(contact):
            if fromm in registrar:
                del registrar[fromm]
            self.sendResponse("488 Not Acceptable Here")
            return
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.sendResponse("200 0K")
                return
        else:
            now = int(time.time())
            validity = now + expires

        logging.info("From: %s - Contact: %s" % (fromm, contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        registrar[fromm] = [contact, self.socket, self.client_address, validity]
        self.debugRegister()
        self.sendResponse("200 0K")

    def processInvite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, bytes(recordroute, "utf-8"))
                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse("480 Temporarily Unavailable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processAck(self):
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, bytes(recordroute, "utf-8"))
                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processNonInvite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, bytes(recordroute, "utf-8"))
                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse("406 Not Acceptable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if origin in registrar:
                socket, claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                #text = b"\r\n".join(data)

                tmp_data = str(data[0], "utf-8")
                for code in code_messages:
                    if tmp_data.find(code) != -1:  # if we find a match
                        tmp_data = tmp_data.replace(code, code_messages[code])
                        data[0] = bytes(tmp_data, "utf-8")
                        # print(data[0])
                        break

                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRequest(self):
        # print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0]

            #log_to_file.get_log(self.data)
            log_class.add_log(self.data)

            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)
                # print "message %s unknown" % self.data

    def handle(self):
        # socket.setdefaulttimeout(120)
        data = self.request[0]
        self.data = data.split(b"\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            logging.info(">>> %s" % request_uri)
            logging.debug("---\n>> server received [%d]:\n%s\n---" % (len(data), data))
            logging.debug("Received from %s:%d" % self.client_address)
            self.processRequest()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")


"""if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO,
                        datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    hostname = socket.gethostname()
    logging.info(hostname)
    ipaddress = socket.gethostbyname(hostname)
    if ipaddress == "127.0.0.1":
        ipaddress = sys.argv[1]
    logging.info(ipaddress)
    recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress, PORT)
    topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress, PORT)
    server = SocketServer.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()"""
