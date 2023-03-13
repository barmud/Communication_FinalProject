import socket
import sqlite3
import struct
import time
from collections import namedtuple

# Define the server address and port number
SERVER_ADDRESS = 'localhost'
SERVER_PORT = 30797
CLIENT_PORT = 20621

# Define the packet format and size
PACKET_FORMAT_UDP = 'I1024s'
PACKET_SIZE_UDP = struct.calcsize(PACKET_FORMAT_UDP)

# Define the packet format and size
PACKET_FORMAT = 'I1024sH'
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)
CHECKSUM_ERROR = 0xFFFF

# Create a database connection and cursor
conn = sqlite3.connect('mydatabase.db')
c = conn.cursor()


def calculate_checksum(data):
    """
    Calculates the checksum for the given data.
    """
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            checksum += (data[i] << 8) + data[i + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum


class Server:

    def __init__(self, window_size=6):
        """
        Initializes the Server class with the window size and other necessary variables for the sliding window protocol.
        :param window_size: The size of the sliding window used for RUDP protocol. Default value is 10.
        """
        self.socket = None
        self.last_seq_num = 1
        self.window_size = window_size
        self.window_start = 1
        self.window_end = self.window_size - 1
        self.received_packets = {}
        self.protocol = ""

        # Create the database and table if they don't already exist
        # self.create_table()

    def start_server(self):
        """
        Starts the server by listening to incoming packets from the client and determines which protocol to use (RUDP or
        TCP) based on the received protocol in the first packet.
        """

        print('Application server started')

        while True:

            # Receiving protocol from client
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind((SERVER_ADDRESS, SERVER_PORT))
            self.socket.listen(1)
            print('Application server is listening..')

            # Wait for a client to connect
            client_conn, client_addr = self.socket.accept()
            print('Accept occurred.')

            # Receive a packet from the client
            packet = client_conn.recv(PACKET_SIZE_UDP)

            # Unpack the packet
            seq_num, prot = struct.unpack(PACKET_FORMAT_UDP, packet)

            # Init protocol
            self.protocol = prot.decode('utf-8', 'ignore').rstrip('\x00')

            # Close the socket
            self.socket.close()

            if self.protocol == 'RUDP':
                server.rudp_conn()

            if self.protocol == 'TCP':
                server.tcp_conn()

    def rudp_conn(self, counter=1):
        """
        Implements the Reliable UDP (RUDP) protocol for data transfer between the client and server. Uses a sliding window
        to manage data transfer and ensures reliability of data delivery.
        """

        global address

        if self.protocol == 'RUDP':
            print('Opening RUDP connection')
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((SERVER_ADDRESS, SERVER_PORT))

            queries = []
            sent_packets = {}  # Track sent packets and their timestamps
            PacketInfo = namedtuple('PacketInfo', ['packet', 'timestamp'])

            while len(queries) <= 10:

                # Receive a packet from the client
                packet, address = self.socket.recvfrom(PACKET_SIZE)
                print("Received a new query!")

                # Unpack the packet
                seq_num, query_bytes, checksum = struct.unpack(PACKET_FORMAT, packet)

                # Calculate the checksum of the received packet
                data = struct.pack(PACKET_FORMAT_UDP, seq_num, query_bytes)
                if calculate_checksum(data) != checksum:
                    print(f'calculated checksum: {calculate_checksum(data)}\nchecksum from packet:{checksum}')
                    # Send a negative acknowledgement for the packet with a checksum error
                    nack_packet = struct.pack(PACKET_FORMAT, seq_num, b'NACK', CHECKSUM_ERROR)
                    self.socket.sendto(nack_packet, address)
                    continue  # Receive the next packet

                if query_bytes.decode('utf-8', 'ignore').rstrip('\x00') == 'END':
                    break

                print(f"Seq num: {seq_num}, Window: [{self.window_start}, {self.window_end}]")

                # Check if packet is within the sliding window
                if self.window_start <= seq_num <= self.window_end:

                    # Add the packet to the received packets dictionary
                    self.received_packets[seq_num] = query_bytes.decode('utf-8', 'ignore').rstrip('\x00')

                    # Send a positive acknowledgement for the received packet
                    ack_packet = struct.pack(PACKET_FORMAT, seq_num, b'ACK', checksum)

                    # Include the packet number in the ack field
                    ack_packet = ack_packet[:4] + struct.pack("!I", seq_num) + ack_packet[8:]

                    self.socket.sendto(ack_packet, address)

                    print(f'Sent an ACK packet for packet: {seq_num}')

                    print(f"Window start: {self.window_start}, received_packets: {self.received_packets}")

                    # Slide the window if possible
                    while self.window_start in self.received_packets:
                        # Add the query to the list of queries
                        queries.append(self.received_packets[self.window_start])
                        del self.received_packets[self.window_start]

                        # Update the window
                        self.window_start += 1
                        self.window_end += 1

                elif seq_num < self.window_start:

                    # Send a positive acknowledgement for the received packet
                    ack_packet = struct.pack(PACKET_FORMAT, seq_num, b'ACK', checksum)

                    # Include the packet number in the ack field
                    ack_packet = ack_packet[:4] + struct.pack("!I", seq_num) + ack_packet[8:]

                    self.socket.sendto(ack_packet, address)

                    print(f'Sent an ACK packet for packet: {seq_num}')

                elif len(queries) == 10:

                    # Send a positive acknowledgement for the received packet
                    ack_packet = struct.pack(PACKET_FORMAT, seq_num, b'ACK', checksum)

                    # Include the packet number in the ack field
                    ack_packet = ack_packet[:4] + struct.pack("!I", seq_num) + ack_packet[8:]

                    self.socket.sendto(ack_packet, address)

                    print(f'Sent an ACK packet for packet: {seq_num}')

            self.socket.settimeout(5)

            i = 0
            # Execute the queries and send the results back to the client
            for query in queries:

                count = 0
                i += 1
                print('Executing the query and send the response back to the client')
                # Execute the query
                try:
                    c.execute(query)
                    result = c.fetchall()

                    # Convert row to bytes and add null terminator
                    result_bytes = bytes(str(result), 'utf-8', 'ignore') + b'\x00'

                    # Create packet with unique sequence number and checksum
                    data = struct.pack(PACKET_FORMAT_UDP, self.last_seq_num, result_bytes)
                    checksum = calculate_checksum(data)
                    packet = struct.pack(PACKET_FORMAT, self.last_seq_num, result_bytes, checksum)

                    # Send packet to client and track ACKs
                    sent_packets[self.last_seq_num] = PacketInfo(packet, time.time())
                    print(f'Result of query {i} = {result} has been sent')
                    self.socket.sendto(packet, address)

                    # Increment the sequence number for the next packet
                    self.last_seq_num += 1

                    last_seq = 0

                    # Check for ACKs and retransmit any packets as necessary
                    current_time = time.time()
                    while sent_packets:

                        # Check for timeouts and resend any unacknowledged packets
                        for seq_num, packet_info in sent_packets.items():
                            if current_time - packet_info.timestamp > 5:
                                if last_seq == seq_num:
                                    count += 1
                                # Resend packet
                                self.socket.sendto(packet_info.packet, address)
                                sent_packets[seq_num] = PacketInfo(packet_info.packet, current_time)
                                print("Timeout occurred for packet: ", seq_num)
                                last_seq = seq_num
                                if count == 4:
                                    del sent_packets[seq_num]
                                    count = 0

                        # Receive ACKs from the client
                        try:
                            ack_packet, address = self.socket.recvfrom(PACKET_SIZE)

                            # Unpack the ACK packet
                            ack_seq_num, ack_bytes, ack_checksum = struct.unpack(PACKET_FORMAT, ack_packet)
                            print(f"Received an ACK for packet: {ack_seq_num}")

                            # Check if ACK is for a packet we sent
                            if ack_seq_num in sent_packets:
                                # Remove packet from sent_packets dictionary
                                del sent_packets[ack_seq_num]

                        except socket.timeout:

                            # Resend any unacknowledged packets
                            for seq_num, packet_info in sent_packets.items():
                                # Resend packet
                                self.socket.sendto(packet_info.packet, address)
                                sent_packets[seq_num] = PacketInfo(packet, current_time)
                                print("Timeout occurred for packet: ", seq_num)

                except Exception as e:

                    # Send error message back to client
                    result_bytes = str(e).encode('utf-8') + b'\x00'

                    # Create packet with unique sequence number and checksum
                    data = struct.pack(PACKET_FORMAT_UDP, self.last_seq_num, result_bytes)
                    checksum = calculate_checksum(data)
                    packet = struct.pack(PACKET_FORMAT, self.last_seq_num, result_bytes, checksum)

                    self.socket.sendto(packet, address)

                    # Increment the sequence number for the next packet
                    self.last_seq_num += 1

                    # Check for ACKs and retransmit any packets as necessary
                    current_time = time.time()
                    while sent_packets:
                        a = 0
                        # Check for timeouts and resend any unacknowledged packets
                        for seq_num, packet_info in sent_packets.items():
                            if current_time - packet_info.timestamp > 5:
                                # Resend packet
                                self.socket.sendto(packet_info.packet, address)
                                sent_packets[seq_num] = PacketInfo(packet_info.packet, current_time)
                                print("Timeout occurred for packet: ", seq_num)
                                a = seq_num
                                if seq_num >= 11:
                                    break
                        if a >= 11:
                            break
                        # Receive ACKs from the server
                        try:
                            ack_packet, address = self.socket.recvfrom(PACKET_SIZE)
                            print("Received an ACK")

                            # Unpack the ACK packet
                            ack_seq_num, ack_bytes, ack_checksum = struct.unpack(PACKET_FORMAT, ack_packet)

                            if len(sent_packets) == 1 and 11 in sent_packets:
                                break

                            # Check if ACK is for a packet we sent
                            if ack_seq_num in sent_packets:
                                # Remove packet from sent_packets dictionary
                                del sent_packets[ack_seq_num]

                        except socket.timeout:

                            # Resend any unacknowledged packets
                            for seq_num, packet_info in sent_packets.items():
                                # Resend packet
                                self.socket.sendto(packet_info.packet, address)
                                sent_packets[seq_num] = PacketInfo(packet, current_time)
                                print("Timeout occurred for packet: ", seq_num)

            print('Closing RUDP connection..')
            conn.commit()
            self.protocol = ""
            self.window_start = 1
            self.window_end = self.window_size - 1
            self.socket.close()
            self.last_seq_num = 1

    def tcp_conn(self):
        """
        Handles the TCP connection with the client. Receives two SQL queries from the client and executes them. Sends the
        results of each query back to the client.
        """

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((SERVER_ADDRESS, SERVER_PORT))
        self.socket.listen(1)

        # create_table()
        print('Server listening..')
        queries = []

        # Wait for a client to connect
        client_conn, addr = self.socket.accept()
        print('Accept occurred')

        while len(queries) < 10:
            # Receive data from the client
            data = client_conn.recv(PACKET_SIZE_UDP)

            # Unpack the packet
            seq_num, query_bytes = struct.unpack(PACKET_FORMAT_UDP, data)

            # Decode the query
            query = query_bytes.decode('utf-8', 'ignore').rstrip('\x00')

            # Add the query to the list of queries
            queries.append(query)
            print(f'Query {len(queries)} arrived and stored')

        # Execute the queries and send the results back to the client
        db_conn = sqlite3.connect('mydatabase.db')
        cursor = db_conn.cursor()
        i = 1
        for query in queries:

            print(f'Executing query {i} and sending the response to the client')
            # Execute the query
            try:
                cursor.execute(query)
                result = cursor.fetchall()

                # Convert row to bytes and add null terminator
                result_bytes = bytes(str(result), 'utf-8', 'ignore') + b'\x00'

                # Create packet with unique sequence number
                packet = struct.pack(PACKET_FORMAT_UDP, 0, result_bytes)

                # Send packet to client
                client_conn.sendall(packet)

            except Exception as e:

                # Send error message back to client
                result_bytes = str(e).encode('utf-8') + b'\x00'
                packet = struct.pack(PACKET_FORMAT_UDP, 0, result_bytes)
                client_conn.sendall(packet)

            i += 1

        print('Closing TCP connection..')
        # Close the connection and the database
        db_conn.commit()
        db_conn.close()
        client_conn.close()
        self.protocol = ""

if __name__ == '__main__':
    server = Server()
    server.start_server()