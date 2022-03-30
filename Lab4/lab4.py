#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import struct
import ipaddress
from threading import Thread

CLIENT_TO_CRD_CMDS = {
    "getdir"        : 1,
    "makeroom"      : 2,
    "deleteroom"    : 3
}

CLIENT_CMDS = ["connect", "bye", "name", "chat"]


########################################################################
# Multicast Address and Port
########################################################################

MULTICAST_ADDRESS = "239.0.0.10"
MULTICAST_PORT    =  2000

########################################################################
# Multicast Server
########################################################################

class Server:

    HOSTNAME = socket.gethostname()

    CRDS_address_port = (HOSTNAME, 50000)

    RECV_SIZE = 256
    
    MSG_ENCODING = "utf-8"

    chat_rooms = []
    client_threads = []

    # Create a 1-byte maximum hop count byte used in the multicast
    # packets (i.e., TTL, time-to-live).
    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    def __init__(self):
        self.create_sockets()
        self.accept_clients_forever()

    def create_sockets(self):
        try:
            # Create an IPv4 UDP and TCP sockets.
            self.CRDS_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Get socket layer socket options.
            self.CRDS_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.CRDS_socket.bind( Server.CRDS_address_port )
            
            # Set the multicast TTL.
            self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Server.TTL_BYTE)

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def accept_clients_forever(self):
        self.CRDS_socket.listen(10)
        print("Chat Room Directory Server: Listening on port {} ...".format(Server.CRDS_address_port[1]))
        try:
            while True:
                # Block while waiting for accepting incoming connections
                client = self.CRDS_socket.accept()
                new_client_thread = Thread(target=self.connection_handler, args=[client])
                new_client_thread.daemon = True
                new_client_thread.start()
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.CRDS_socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))

        while (True):        
            # get command ID
            cmd_field = connection.recv(1)
            # If the read fails, give up.
            if len(cmd_field) == 0:
                print("Closing connection ...")
                connection.close()
                return
            # Convert the command to our native byte order.
            cmd = int.from_bytes(cmd_field, byteorder='big')
            if cmd in CLIENT_TO_CRD_CMDS.values():
                if CLIENT_TO_CRD_CMDS["getdir"] == cmd:
                    # send client the list of chat rooms
                    chatroom_names = [cr["name"] for cr in Server.chat_rooms]
                    connection.send(str(chatroom_names).encode(Server.MSG_ENCODING))
                
                elif CLIENT_TO_CRD_CMDS["makeroom"] == cmd:
                    # recieve more bytes containing chatroom name and multicast ip and port
                    chatroom_name_byte_len = connection.recv(1)
                    chatroom_name = connection.recv(chatroom_name_byte_len).decode(Server.MSG_ENCODING)

                    multicast_ip = socket.inet_ntoa(connection.recv(4))
                    multicast_port = connection.recv(Server.RECV_SIZE)

                    print("CHATROOM: ", chatroom_name, multicast_ip, multicast_port)

                elif CLIENT_TO_CRD_CMDS["deleteroom"] == cmd:
                    # recieve more bytes to get chatroom name
                    pass
            else:
                print("INVALID command received. Closing connection ...")
                connection.close()
                return 

            


########################################################################
# Multicast Client 
########################################################################

RX_BIND_ADDRESS = "0.0.0.0"

# Receiver socket will bind to the following.
BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)

########################################################################

class Client:

    RECV_SIZE = 256

    def __init__(self):
        self.create_sockets()
        self.handle_console_input_forever()

    def register_for_multicast_group(self, multicast_addr):           

            multicast_group_bytes = socket.inet_aton(multicast_addr)
            print("Multicast Group: ", multicast_addr)

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_BIND_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes
            print("multicast_request = ", multicast_request)

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", multicast_addr,"/", RX_BIND_ADDRESS)
            self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

    def create_sockets(self):
        try:
            self.CRDS_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            self.multicast_socket.bind(BIND_ADDRESS_PORT)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        self.CRDS_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # recreate socket - allows for multiple "connect"/"bye" cmds in one session
        print("Connecting to:", Server.CRDS_address_port)
        try:
            # Connect to the server using its socket address tuple.
            self.CRDS_socket.connect( Server.CRDS_address_port )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def enter_chat_room(self, chatroom):
        while True:
            try:
                data, address_port = self.multicast_socket.recvfrom(Client.RECV_SIZE)
                address, port = address_port
                print("Received: {} {}".format(data.decode('utf-8'), address_port))
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

    def getdir(self):
        cmd_field = CLIENT_TO_CRD_CMDS["getdir"].to_bytes(1, byteorder='big')
        self.CRDS_socket.send(cmd_field)

        dir = self.CRDS_socket.recv(Client.RECV_SIZE)
        if len(dir) == 0:
            self.CRDS_socket.close()
            return
        dir_list = dir.decode(Server.MSG_ENCODING)
        print(dir_list)

    def handle_console_input_forever(self):
        while True:
            try:
                self.input_text = input("Enter Command: ")
                if self.input_text != "":
                    print("Command Entered: ", self.input_text)

                    if self.input_text == "connect":
                        print("Conneting to CRDS...")
                        self.connect_to_server()

                    elif self.input_text == "bye":
                        print("Closing server connection ...")
                        self.CRDS_socket.close()

                    elif self.input_text.split()[0] == "name":
                        self.name = self.input_text.split()[1:]

                    elif self.input_text.split()[0] == "chat":
                        self.enter_chat_room(self.input_text.split()[1:])

                    elif self.input_text.split()[0] == "makeroom":
                        cmd_params = self.input_text.split()[1:]
                        port = cmd_params[-1]
                        address = cmd_params[-2]
                        chatroom_name = ' '.join(cmd_params[:-2])

                        print("Chatroom: ", chatroom_name, address, port)

                    elif self.input_text.split()[0] == "deleteroom":
                        pass

                    elif self.input_text == "getdir":
                        self.getdir()

                    else:
                        print("Unrecongized cmd..")
                        continue

            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.CRDS_socket.close()
                sys.exit(1)


########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################
