import argparse
from collections import defaultdict
import socket
import hashlib
import getpass
import sys


## Commands
GET_MIDTERM_AVG_CMD  = "GMA"
GET_LAB_1_AVG_CMD    = "GL1A"
GET_LAB_2_AVG_CMD    = "GL2A"
GET_LAB_3_AVG_CMD    = "GL3A"
GET_LAB_4_AVG_CMD    = "GL4A"
GET_EXAM_1_AVG_CMD   = "GE1A"
GET_EXAM_2_AVG_CMD   = "GE2A"
GET_EXAM_3_AVG_CMD   = "GE3A"
GET_EXAM_4_AVG_CMD   = "GE4A"
GET_GRADES_CMD       = "GG"


## Student class
class Student:
    def __init__(self, data, headers):
        self.data = {headers[i]:data[i] for i in range(len(headers))}
    
    def get(self, attr):
        return self.data[attr]


## Server class
class Server:
    HOSTNAME = "0.0.0.0"
    PORT = 50000
    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10    
    MSG_ENCODING = "utf-8"
    SOCKET_ADDRESS = (HOSTNAME, PORT)

    def __init__(self):
        self.parse_csv("course_grades_2022.csv")
        self.create_listen_socket()
        self.process_connections_forever()

    def parse_csv(self, filename):
        self.students = {}
        with open(filename, 'r') as f:
            print("Data read from CSV file:")

            headers = f.readline()
            print(headers.strip())
            headers = headers.strip().split(',')

            lines = f.readlines()
            students_raw = []
            for line in lines:
                print(line.strip())
                students_raw.append(line.strip().split(','))

            for s in students_raw:
                student = Student(s, headers)
                student_hash = hashlib.sha256()
                student_hash.update(
                    f"{student.get('ID Number')} {student.get('Password')}".encode('utf-8'))
                student_hash = student_hash.hexdigest()
                self.students[student_hash] = student
            
            # pre-compute all the averages
            self.averages = defaultdict(lambda: 0)
            num_students = len(self.students)
            for s in self.students.values(): 
                self.averages[GET_MIDTERM_AVG_CMD] += float(s.get("Midterm")) / num_students
                self.averages[GET_LAB_1_AVG_CMD]   += float(s.get("Lab 1"))   / num_students
                self.averages[GET_LAB_2_AVG_CMD]   += float(s.get("Lab 2"))   / num_students
                self.averages[GET_LAB_3_AVG_CMD]   += float(s.get("Lab 3"))   / num_students
                self.averages[GET_LAB_4_AVG_CMD]   += float(s.get("Lab 4"))   / num_students
                self.averages[GET_EXAM_1_AVG_CMD]  += float(s.get("Exam 1"))  / num_students
                self.averages[GET_EXAM_2_AVG_CMD]  += float(s.get("Exam 2"))  / num_students
                self.averages[GET_EXAM_3_AVG_CMD]  += float(s.get("Exam 3"))  / num_students
                self.averages[GET_EXAM_4_AVG_CMD]  += float(s.get("Exam 4"))  / num_students

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This allows us to reuse
            # the socket without waiting for any timeouts.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind(Server.SOCKET_ADDRESS)

            # Set socket to listen state.
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                # Block while waiting for accepting incoming connections
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def process_cmd(self, cmd_str):
        if cmd_str in self.averages:
            print(f"Received {cmd_str} cmd from client")
            return str(self.averages[cmd_str])
        else:
            # interpret as hash or error out
            print(f"Received IP/password hash {cmd_str}")
            if cmd_str in self.students:
                print("Correct password, record found")
                s = self.students[cmd_str]
                # actual sorcery - return only grades - no identifying info
                return str({key:value for key,value in list(s.data.items())[list(s.data).index("Lab 1"):]})
            else:
                print("Password Failure")
                return "Password Failure"

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)
            
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
                
                # extend response if exactly 128 bytes - prevent client from waiting for more
                if len(response_str) == Client.RECV_BUFFER_SIZE:
                    response_str += " "
                
                # Send response back to client
                sendvd_bytes = response_str.encode(Server.MSG_ENCODING)
                connection.sendall(sendvd_bytes)
                print("Sent: {}".format(sendvd_bytes))

            except KeyboardInterrupt:
                print()
                print("- Closing client connection ... ")
                connection.close()
                break


## Client class
class Client:
    SERVER_HOSTNAME = socket.gethostname() # if client and server on the same machine, gethostname() will work
    RECV_BUFFER_SIZE = 128

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
        self.send_console_input_forever()

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        while True:
            self.input_text = input("Enter Command: ")

            if self.input_text != "":
                print("Command Entered: ", self.input_text)

                if self.input_text == GET_GRADES_CMD:
                    ID = input('User ID: ')
                    PWD = getpass.getpass('Password: ')
                    print("ID number: ", ID)
                    print("Password: ", '*'*len(PWD))

                    auth_hash = hashlib.sha256()
                    auth_hash.update(f"{ID} {PWD}".encode('utf-8'))
                    self.input_text = auth_hash.hexdigest()
                else: # print "Fetching ..."
                    if self.input_text == GET_MIDTERM_AVG_CMD:
                        print_str = "Fetching Midterm Average"
                    elif self.input_text == GET_LAB_1_AVG_CMD:
                        print_str = "Fetching Lab 1 Average"
                    elif self.input_text == GET_LAB_2_AVG_CMD:
                        print_str = "Fetching Lab 2 Average"
                    elif self.input_text == GET_LAB_3_AVG_CMD:
                        print_str = "Fetching Lab 3 Average"
                    elif self.input_text == GET_LAB_4_AVG_CMD:
                        print_str = "Fetching Lab 4 Average"
                    elif self.input_text == GET_EXAM_1_AVG_CMD:
                        print_str = "Fetching Exam 1 Average"
                    elif self.input_text == GET_EXAM_2_AVG_CMD:
                        print_str = "Fetching Exam 2 Average"
                    elif self.input_text == GET_EXAM_3_AVG_CMD:
                        print_str = "Fetching Exam 3 Average"
                    elif self.input_text == GET_EXAM_4_AVG_CMD:
                        print_str = "Fetching Exam 4 Average"
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
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            # print("(sendv: {})".format(self.input_text))
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            recvd_msg_length = 0
            recvd_msg = ""

            while(recvd_msg_length == Client.RECV_BUFFER_SIZE or not recvd_msg_length):
                # Receive and print out text. The received bytes objects
                # must be decoded into string objects.
                recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
                # print("(recv: {})".format(recvd_bytes))

                recvd_msg += recvd_bytes.decode(Server.MSG_ENCODING)
                recvd_msg_length += len(recvd_bytes)

                # recv will block if nothing is available. If we receive
                # zero bytes, the connection has been closed from the
                # other end.
                if recvd_msg_length == 0:
                    print("Closing server connection ... ")
                    self.socket.close()
                    sys.exit(1)

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






