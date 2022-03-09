import argparse
import socket
import sys
import threading

### Commands
# Server
SERVER_SCAN_CMD     = "scan"
SERVER_LIST_CMD     = "list"
SERVER_PUT_CMD      = "put"
SERVER_GET_CMD      = "get"  
# Client
CLIENT_SCAN_CMD         = "scan"
CLIENT_CONNECT_CMD      = "Connect"
CLIENT_LOCAL_LIST_CMD   = "llist"
CLIENT_REMOTE_LIST_CMD  = "rlist"
CLIENT_PUT_CMD          = "put"
CLIENT_GET_CMD          = "get"
CLIENT_BYE_CMD          = "bye"

# Defaults
DEFAULT_SHARING_DIR     = "./"
SERVICE_DISCOVERY_PORT  = 30000
FILE_SHARING_PORT       = 30001


########################################################################
# Service Discovery/File Sharing Server 
########################################################################

class Server:

    ALL_IF_ADDRESS = "0.0.0.0"
    SERVICE_DISCOVERY_ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_DISCOVERY_PORT)
    FILE_SHARING_ADDRESS_PORT = (ALL_IF_ADDRESS, FILE_SHARING_PORT)

    MSG_ENCODING = "utf-8"    
    
    SCAN_MSG = "SERVICE DISCOVERY"

    SCAN_RESP_MSG = "Nick's File Sharing Service"
    SCAN_RESP_MSG_ENCODED = SCAN_RESP_MSG.encode(MSG_ENCODING)

    RECV_SIZE = 1024
    BACKLOG = 10

    def __init__(self):
        self.create_sockets()

        service_disc_thread = threading.Thread(target=self.receive_broadcast_forever, args=())
        file_share_thread   = threading.Thread(target=self.receive_file_share_forever, args=())

        # Start threads
        # ** main program will stay alive as long as threads are running ** #
        service_disc_thread.start()
        file_share_thread.start()

    def create_sockets(self):
        try:
            # Create an IPv4 UDP and TCP sockets.
            self.disc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.disc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.file_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.disc_socket.bind( Server.SERVICE_DISCOVERY_ADDRESS_PORT )
            self.file_socket.bind( Server.FILE_SHARING_ADDRESS_PORT )

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_file_share_forever(self):
        # Listen on file sharing socket
        self.file_socket.listen(Server.BACKLOG)
        print("FILE SHARING SERVICE: Listening on port {} ...".format(FILE_SHARING_PORT))
        try:
            while True:
                # Block while waiting for accepting incoming connections
                self.connection_handler(self.file_socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def process_cmd(self, cmd_str):
        pass

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                print("Accepted")
                recvd_bytes = connection.recv(Server.RECV_SIZE)
            
                # If recv returns with zero bytes, the other end of the
                # TCP connection has closed
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                # Decode the received bytes back into strings.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                # print("Received: {}".format(recvd_str))

                # Process the incoming command
                response_str = self.process_cmd(recvd_str)
                
                # Send response back to client
                sendvd_bytes = response_str.encode(Server.MSG_ENCODING)
                connection.sendall(sendvd_bytes)
                print("Sent: {}".format(sendvd_bytes))

            except KeyboardInterrupt:
                print()
                print("- Closing client connection ... ")
                connection.close()
                break

    def receive_broadcast_forever(self):
        print("SERVICE DISCOVERY: Listening on port {} ...".format(FILE_SHARING_PORT))
        while True:
            try:
                recvd_bytes, address = self.disc_socket.recvfrom(Server.RECV_SIZE)

                print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)
            
                # Decode the received bytes back into strings.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                # Check if the received packet contains a service scan command.
                if recvd_str == Server.SCAN_MSG.strip():
                    # Send the service advertisement message back to the client.
                    self.disc_socket.sendto(Server.SCAN_RESP_MSG_ENCODED, address)
            except KeyboardInterrupt:
                print()
                sys.exit(1)


########################################################################
# Client
########################################################################

class Client:

    RECV_SIZE = 1024
    MSG_ENCODING = "utf-8"    

    BROADCAST_ADDRESS = "255.255.255.255"
    # BROADCAST_ADDRESS = "192.168.1.255"    

    BROADCAST_ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_DISCOVERY_PORT)

    SCAN_TIMEOUT = 2

    SCAN_MSG = "SERVICE DISCOVERY"
    SCAN_MSG_ENCODED = SCAN_MSG.encode(MSG_ENCODING)

    def __init__(self):
        self.socket_setup()
        _, (server_addr, _) = self.scan_for_service()
        self.file_sharing_address_port = (server_addr, FILE_SHARING_PORT)
        self.connect_to_server(self.file_sharing_address_port)
        self.send_console_input_forever()

    def connect_to_server(self, address_port):
        print("Connecting to:", address_port)
        try:
            # Connect to the server using its socket address tuple.
            self.file_socket.connect( address_port )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def socket_setup(self):
        try:
            # Service discovery done using UDP packets.
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Arrange to send a broadcast service discovery packet.
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Set the socket for a socket.timeout if a scanning recvfrom fails.
            self.broadcast_socket.settimeout(Client.SCAN_TIMEOUT)
            
            # TCP socket for later use
            self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def scan_for_service(self):
        # Collect our scan results in a list.
        scan_results = None

        # Send a service discovery broadcast.
        print("Sending broadcast scan: '{}'".format(Client.SCAN_MSG))            
        self.broadcast_socket.sendto(Client.SCAN_MSG_ENCODED, Client.BROADCAST_ADDRESS_PORT)
    
        try:
            recvd_bytes, address_port = self.broadcast_socket.recvfrom(Client.RECV_SIZE) # socket configured to use timeout
            recvd_msg = recvd_bytes.decode(Client.MSG_ENCODING)
            scan_results = (recvd_msg, address_port)
        # If we timeout listening for a new response, we are finished
        except socket.timeout:
            pass

        # Output all of our scan results, if any
        if scan_results:
            for result in scan_results:
                print(result)
        else:
            print("No services found.")

        return scan_results

    def get_console_input(self):
        while True:
            self.input_text = input("Enter Command: ")

            if self.input_text != "":
                print("Command Entered: ", self.input_text)
                if self.input_text == CLIENT_LOCAL_LIST_CMD:
                    print_str = "local list"
                elif self.input_text == CLIENT_REMOTE_LIST_CMD:
                    print_str = "remote list"
                elif self.input_text == CLIENT_SCAN_CMD:
                    print_str = "scan"
                elif self.input_text.split()[0] == CLIENT_CONNECT_CMD:
                    print_str = "connect"
                elif self.input_text.split()[0] == CLIENT_PUT_CMD:
                    print_str = "PUT"
                elif self.input_text.split()[0] == CLIENT_GET_CMD:
                    print_str = "GET"
                elif self.input_text == CLIENT_BYE_CMD:
                    print_str = "GET"
                else:
                    print_str = "Unrecongized cmd.."
                print(print_str)

                break
    
    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.file_socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            # print("(sendv: {})".format(self.input_text))
            self.file_socket.sendall(self.input_text.encode(Client.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.file_socket.recv(Client.RECV_BUFFER_SIZE)
            # print("(recv: {})".format(recvd_bytes))

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.file_socket.close()
                sys.exit(1)

            # decode message
            recvd_msg = recvd_bytes.decode(Server.MSG_ENCODING)

            print("Received: ", recvd_msg)

        except Exception as msg:
            print(msg)
            sys.exit(1)


## Program Entry
if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, 
                        type=str, 
                        default='client')

    args = parser.parse_args()
    roles[args.role]()
