# Don't forget to change this file's name before submission.
import sys
import os
import enum
import struct
import socket


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

    This class is also responsible for reading/writing files to the
    hard disk.

    Failing to comply with those requirements will invalidate
    your submission.

    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERRROR = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """ 
        list = []
        opcode = struct.unpack('!H',packet_bytes[0:2])
        opcode = opcode[0]
        list.append(opcode)
        if opcode == 1 or opcode == 2:
            l = packet_bytes[2:].split('0')
            list.append(l[1])
            list.append(l[2])
        elif opcode == 4:
            block = struct.unpack('!H',packet_bytes[2:4])
            block = block[0]
            list.append(block)
            pass
        elif opcode == 3:
            block = struct.unpack('!H',packet_bytes[2:4])
            block = block[0]
            list.append(block)
            data = struct.unpack('!s',packet_bytes[4:])
            list.append(data)
            pass
        elif opcode == 5:
            ErrorCode = struct.unpack('!H',packet_bytes[2:4])
            ErrorCode = ErrorCode[0]
            list.append(ErrorCode)
            ErrMsg = struct.unpack('!s',packet_bytes[4:])
            ErrMsg = ErrMsg[0]
            list.append(ErrMsg)
            pass
         
        return list

    def _do_some_logic(self, input_packet):
        if input_packet[0] == 3:
            lastPacket = generate_ack(input_packet[1])
            #write data in file
            return lastPacket
        elif input_packet[0] == 4:
            #data = readfile
            #lastPacket = generate_data(input_packet[1],data)
            return lastPacket
        elif input_packet[0] == 5:
            print ("Error: " + input_packet[2])
            return None
        else:
            return None

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        pass

def generate_WRQ(filename):
    writerequest = chr(0) + chr(2) + filename +  chr(0) + 'octet' + chr(0)
    writerequestB = bytes(writerequest,'utf-8')
    print(writerequestB)
    return writerequestB

def generate_RRQ(filename):
    readrequest =  chr(0) + chr(1) + filename +  chr(0) + 'octet' + chr(0)
    readrequestB = bytes(readrequest,'utf-8')
    print(readrequestB)
    return readrequestB

def generate_data(block_no, data):
    return struct.pack("!HH", 3, block_no) + data

def generate_ack(block_no):
    return struct.pack("!H", 4) + struct.pack("!H", block_no)

def generate_error(errcode, errmsg):
    return struct.pack("!HH", 5, errcode) + errmsg + struct.pack("!H", 0)

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """    
    if sys.argv[2] == 'pull':
        writerequest = generate_RRQ(sys.argv[3])
        print("reading")
        download(writerequest,address)
    elif sys.argv[2] == 'push':
        readrequest = generate_WRQ(sys.argv[3])
        print("writing")
        upload(readrequest,address)
    else:
        print('ERROR')
    pass

def download(writerequest,address):
    cSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cSocket.sendto(writerequest, (address,69))
    process = TftpProcessor()
    while True:
        data,server = cSocket.recvfrom(1024)
        process.process_udp_packet(data,server)
        if process.has_pending_packets_to_be_sent():
            temp = process.get_next_output_packet()
            cSocket.sendto(temp,address)
            pass
        else:
            break
        if (len(temp) < 512):
            print ("last block")
            break

    pass

def upload(readrequest,address):

    pass

def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    
    pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    #"127.0.0.1"
    ip_address = get_arg(1, "10.0.2.15")
    setup_sockets(ip_address)
    # Modify this as needed.


if __name__ == "__main__":
    main()
