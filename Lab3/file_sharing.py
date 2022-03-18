import argparse
from ctypes.wintypes import MSG
import socket
import sys
import threading
import os

# Server Command
SERVER_LIST_CMD     = "list"
SERVER_PUT_CMD      = "put"
SERVER_GET_CMD      = "get"  

SERVER_CMDS = {
    SERVER_LIST_CMD : 2,
    SERVER_PUT_CMD  : 3,
    SERVER_GET_CMD  : 4
}

# Client Commands
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

# File Sharing Params
CMD_FIELD_LEN            = 1 # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN  = 1 # 1 byte file name size field.
FILESIZE_FIELD_LEN       = 8 # 8 byte file size field.
MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 4

SERVER_DIR = "./server_dir/"
CLIENT_DIR = "./client_dir/"

########################################################################
# recv_bytes frontend to recv
########################################################################

# Call recv to read bytecount_target bytes from the socket. Return a
# status (True or False) and the received butes (in the former case).
def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    # sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0 # total received bytes
        recv_bytes = b''    # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target-byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return(False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        # sock.settimeout(None)            
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)        
        print("recv_bytes: Recv socket timeout!")
        return (False, b'')


def send_bytes(sock, msg_send):
    try:
        # Send string objects over the connection. The string must
        # be encoded into bytes objects first.
        # print("(sendv: {})".format(self.input_text))
        sock.sendall(msg_send.encode(MSG_ENCODING))
    except Exception as msg:
        print(msg)
        sys.exit(1)

########################################################################
# Service Discovery/File Sharing Server 
########################################################################

class Server:

    ALL_IF_ADDRESS = "0.0.0.0"
    SERVICE_DISCOVERY_ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_DISCOVERY_PORT)
    FILE_SHARING_ADDRESS_PORT = (ALL_IF_ADDRESS, FILE_SHARING_PORT) 
    
    SCAN_MSG = "SERVICE DISCOVERY"

    SCAN_RESP_MSG = "Nick's File Sharing Service"
    SCAN_RESP_MSG_ENCODED = SCAN_RESP_MSG.encode(MSG_ENCODING)

    RECV_SIZE = 1024
    BACKLOG = 5

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
            self.file_socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))

        while (True):
            ################################################################
            # Process a connection and see if the client wants a file that
            # we have.
            
            # Read the command and see if it is a GET command.
            status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
            # If the read fails, give up.
            if not status:
                print("Closing connection ...")
                connection.close()
                return
            # Convert the command to our native byte order.
            cmd = int.from_bytes(cmd_field, byteorder='big')
            print(cmd)
            if cmd == SERVER_CMDS[SERVER_GET_CMD]:
                self.send_file(connection)
            elif cmd == SERVER_CMDS[SERVER_LIST_CMD]:
                self.send_dir_list(connection)
            elif cmd == SERVER_CMDS[SERVER_PUT_CMD]:
                self.recieve_file(connection)
            else:
                print("INVALID command received. Closing connection ...")
                connection.close()
                return 

    def send_dir_list(self, connection):
        dir_list = str(os.listdir(SERVER_DIR))
        dir_list_bytes = dir_list.encode(MSG_ENCODING)
        dir_list_size_bytes = len(dir_list_bytes)
        dir_list_size_field = dir_list_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = dir_list_size_field + dir_list_bytes
        
        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending directory list: ", dir_list)
            print("directory list size field: ", dir_list_size_field.hex(), "\n")
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return  

    def send_file(self, connection):
            # GET command is good. Read the filename size (bytes).
            status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
            if not status:
                print("Closing connection ...")            
                connection.close()
                return
            filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
            if not filename_size_bytes:
                print("Connection is closed!")
                connection.close()
                return
            
            print('Filename size (bytes) = ', filename_size_bytes)

            # Now read and decode the requested filename.
            status, filename_bytes = recv_bytes(connection, filename_size_bytes)
            if not status:
                print("Closing connection ...")            
                connection.close()
                return
            if not filename_bytes:
                print("Connection is closed!")
                connection.close()
                return
            
            filename = filename_bytes.decode(MSG_ENCODING)
            print('Requested filename = ', filename)

            ################################################################
            # See if we can open the requested file. If so, send it.
            
            # If we can't find the requested file, shutdown the connection
            # and wait for someone else.
            try:
                file = open(os.path.join(SERVER_DIR, filename), 'r').read()
            except FileNotFoundError:
                print("Error: Requested file is not available!")
                connection.close()                   
                return

            # Encode the file contents into bytes, record its size and
            # generate the file size field used for transmission.
            file_bytes = file.encode(MSG_ENCODING)
            file_size_bytes = len(file_bytes)
            file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

            # Create the packet to be sent with the header field.
            pkt = file_size_field + file_bytes
            
            try:
                # Send the packet to the connected client.
                connection.sendall(pkt)
                print("Sending file: ", filename)
                print("file size field: ", file_size_field.hex(), "\n")
                # time.sleep(20)
            except socket.error:
                # If the client has closed the connection, close the
                # socket on this end.
                print("Closing client connection ...")
                connection.close()
                return    

    def recieve_file(self, connection):
        # Read the file size field returned by the server.
        status, filename_size_bytes = recv_bytes(connection, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return

        print("Filename size bytes = ", filename_size_bytes.hex())
        if len(filename_size_bytes) == 0:
            connection.close()
            return

        # Make sure that you interpret it in host byte order.
        filename_size = int.from_bytes(filename_size_bytes, byteorder='big')
        print("Filename size = ", filename_size)

        # self.socket.settimeout(4)                                  
        status, filename = recv_bytes(connection, filename_size)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return

        # print("recvd_bytes_total = ", recvd_bytes_total)
        # Receive the file itself.

        status, file_size_bytes = recv_bytes(connection, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return

        print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            connection.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size = ", file_size)

        # self.socket.settimeout(4)                                  
        status, recvd_bytes_total = recv_bytes(connection, file_size)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return

        try:
            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), filename))

            with open(os.path.join(SERVER_DIR, filename.decode(MSG_ENCODING)), 'w') as f:
                recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
                f.write(recvd_file)
            print(recvd_file)
        except:
            print("Error writing file")
            exit(1)

    def receive_broadcast_forever(self):
        print("SERVICE DISCOVERY: Listening on port {} ...".format(FILE_SHARING_PORT))
        while True:
            try:
                recvd_bytes, address = self.disc_socket.recvfrom(Server.RECV_SIZE)

                print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)
            
                # Decode the received bytes back into strings.
                recvd_str = recvd_bytes.decode(MSG_ENCODING)

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

    BROADCAST_ADDRESS = "255.255.255.255"
    # BROADCAST_ADDRESS = "192.168.1.255"    

    BROADCAST_ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_DISCOVERY_PORT)

    SCAN_TIMEOUT = 2

    SCAN_MSG = "SERVICE DISCOVERY"
    SCAN_MSG_ENCODED = SCAN_MSG.encode(MSG_ENCODING)

    def __init__(self):
        self.socket_setup()
        self.handle_console_input_forever()

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
            recvd_msg = recvd_bytes.decode(MSG_ENCODING)
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
    
    def get_remote_list(self):
        cmd_field = SERVER_CMDS[SERVER_LIST_CMD].to_bytes(CMD_FIELD_LEN, byteorder='big')
        pkt = cmd_field

        # Send the request packet to the server.
        self.file_socket.sendall(pkt)

        # Read the list size field returned by the server.
        status, file_size_bytes = recv_bytes(self.file_socket, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            self.file_socket.close()
            return

        if len(file_size_bytes) == 0:
            self.file_socket.close()
            return

        # Make sure that you interpret it in host byte order.
        resp_bytes_length = int.from_bytes(file_size_bytes, byteorder='big')

        # self.socket.settimeout(4)                                  
        status, recvd_bytes_total = recv_bytes(self.file_socket, resp_bytes_length)
        if not status:
            print("Closing connection ...")            
            self.file_socket.close()
            return
        
        remote_dir = eval(recvd_bytes_total.decode(MSG_ENCODING))
        print("directory size = ", len(remote_dir))
        print(remote_dir)


    def handle_console_input_forever(self):
        while True:
            try:
                self.input_text = input("Enter Command: ")
                if self.input_text != "":
                    print("Command Entered: ", self.input_text)
                    if self.input_text == CLIENT_LOCAL_LIST_CMD:
                        print_str = "local list"
                        print(os.listdir(CLIENT_DIR))
                    elif self.input_text == CLIENT_REMOTE_LIST_CMD:
                        print_str = "remote list"
                        self.get_remote_list()
                    elif self.input_text == CLIENT_SCAN_CMD:
                        print_str = "scan"
                        _, (self.server_addr, _) = self.scan_for_service()
                    elif self.input_text.split()[0] == CLIENT_CONNECT_CMD:
                        print_str = "connect"
                        self.connect_to_server((self.server_addr, FILE_SHARING_PORT))
                    elif self.input_text.split()[0] == CLIENT_PUT_CMD:
                        print_str = "PUT"
                        self.send_file(self.input_text.split()[1])
                    elif self.input_text.split()[0] == CLIENT_GET_CMD:
                        print_str = "GET"
                        self.download_filename = self.input_text.split()[1]
                        self.get_file(self.download_filename)
                    elif self.input_text == CLIENT_BYE_CMD:
                        print_str = "BYE"
                        print("Closing Connection")
                        self.file_socket.close()
                    else:
                        print_str = "Unrecongized cmd.."
                        print(print_str)
                        continue
                    # print(print_str)

            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.file_socket.close()
                sys.exit(1)

    def send_file(self, filename):
        try:
            file = open(os.path.join(CLIENT_DIR, filename), 'r').read()
        except FileNotFoundError:
            print("Error: Requested file was not found!")
            self.file_socket.close()                   
            return

        cmd_field = SERVER_CMDS[SERVER_PUT_CMD].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        filename_bytes = filename.encode(MSG_ENCODING)
        filename_size_field = len(filename_bytes).to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = cmd_field + filename_size_field + filename_bytes + file_size_field + file_bytes
        
        try:
            # Send the packet to the connected client.
            self.file_socket.sendall(pkt)
            print("Sending file: ", filename)
            print("file size field: ", file_size_field.hex(), "\n")
            with open(os.path.join(CLIENT_DIR, filename)) as f:
                print(f.read())
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            self.file_socket.close()
            return    

    def get_file(self, filename):

        ################################################################
        # Generate a file transfer request to the server
        
        # Create the packet cmd field.
        cmd_field = SERVER_CMDS[SERVER_GET_CMD].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field_bytes = filename.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet.
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())
        
        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server.
        self.file_socket.sendall(pkt)

        ################################################################
        # Process the file transfer repsonse from the server
        
        # Read the file size field returned by the server.
        status, file_size_bytes = recv_bytes(self.file_socket, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            self.file_socket.close()
            return

        print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            self.file_socket.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size = ", file_size)

        # self.socket.settimeout(4)                                  
        status, recvd_bytes_total = recv_bytes(self.file_socket, file_size)
        if not status:
            print("Closing connection ...")            
            self.file_socket.close()
            return
        # print("recvd_bytes_total = ", recvd_bytes_total)
        # Receive the file itself.
        try:
            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), self.download_filename))

            with open(os.path.join(CLIENT_DIR, self.download_filename), 'w') as f:
                recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
                f.write(recvd_file)
            print(recvd_file)
        except:
            print("Error writing file")
            exit(1)


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
