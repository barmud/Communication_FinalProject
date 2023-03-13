import sqlvalidator
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from collections import namedtuple

# Define the server address and port number
SERVER_ADDRESS = 'localhost'
SERVER_PORT = 30797
CLIENT_PORT = 20621
DNS_SERVER_PORT = 53

# Define the packet format and size
PACKET_FORMAT_UDP = 'I1024s'
PACKET_SIZE_UDP = struct.calcsize(PACKET_FORMAT_UDP)

# Define the packet format and size for RUDP
PACKET_FORMAT = 'I1024sH'
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)
CHECKSUM_ERROR = 0xFFFF

# Define the timeout and maximum number of retransmissions
timeout = 1.0
max_retransmissions = 3

# Define the congestion window size and maximum segment size
cwnd = 1
mss = 1024

# Define the slow start threshold
ssthresh = 16

# Define a maximum number of retries
MAX_RETRIES = 3


def is_valid_query(query):
    try:
        validator = sqlvalidator.parse(query)
        if validator.is_valid():
            return True
    except Exception as e:
        return False


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


class Client:

    def __init__(self, window_size=6):
        self.ip_lease_time = None
        self.subnet_mask = None
        self.gateway_ip = None
        self.my_ip = None
        self.queries = []
        self.socket = None
        self.seq_num = 1
        self.window_size = window_size
        self.window_start = 1
        self.window_end = self.window_size - 1
        self.received_packets = {}
        self.protocol = ""

    def client_start(self):
        """
        This method prompts the user to select an operation to perform, and then performs that operation.
        The user can choose to assign an IP address, send a DNS request, send SQL queries, or exit.
        """

        print("Hello there!\n")
        choice = None

        choice = input("[*] Enter '1' to assign an IP address\n"
                       "[*] Enter '2' for a DNS request\n"
                       "[*] Enter '3' to send SQL queries\n"
                       "[*] Enter '4' to exit\n")

        if choice == '1':
            print("Getting IP Address")
            client.get_ip()
            print('\n')

        elif choice == '2':
            domain_name = input("Enter a domain name: ")
            client.send_dns_query(domain_name)
            print('\n')

        elif choice == '3':
            client.queries_input()
            client.init_protocol()
            client.send_and_print_queries(client.queries, client.protocol)
            print('\n')

        elif choice == '4':
            exit(1)

        elif choice != '4':
            print("Invalid choice.")

    def send_dns_query(self, domain_name):
        """
        Send a DNS query to resolve the given domain name to an IP address.
        :param domain_name: The domain name to be resolved.
        """

        # Establish a TCP connection to the DNS server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((SERVER_ADDRESS, 53))
        self.socket.settimeout(6)

        # Build the DNS query packet
        dns_query = DNS(rd=1, qd=DNSQR(qname=domain_name, qtype="A"))
        ip_packet = IP(dst=SERVER_ADDRESS)
        tcp_packet = TCP(dport=53)
        dns_request_packet = ip_packet / tcp_packet / dns_query

        # Send the DNS query packet to the server over the TCP connection
        self.socket.sendall(bytes(dns_request_packet))
        print('Sent the query to the DNS server')

        # Receive the DNS response packet from the server over the TCP connection
        dns_response_packet_bytes = self.socket.recv(1024)
        dns_response_packet = IP(dns_response_packet_bytes)

        # Check if the response packet contains answer records
        if not dns_response_packet.haslayer(DNSRR):
            print(f"Could not resolve {domain_name}")
            return

        # Extract the IP address from the DNS response packet
        ip_addr = dns_response_packet[DNSRR].rdata
        print(f"{domain_name} resolved to {ip_addr}")

        # Close the TCP connection to the server
        self.socket.close()

    def send_queries_rudp(self, queries):
        """
        Sends multiple queries to a server using the Reliable UDP protocol and returns their responses.
        :param queries: A list of queries to be sent to the server.
        :return: A list of responses received from the server.
        """

        global pckt
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('localhost', CLIENT_PORT))
        self.socket.settimeout(5)

        # Keep track of how many responses are expected
        expected_responses = len(queries)

        responses = []
        sent_packets = {}  # Track sent packets and their timestamps
        PacketInfo = namedtuple('PacketInfo', ['packet', 'timestamp'])
        address = (SERVER_ADDRESS, SERVER_PORT)

        queries.append('END')
        for query in queries:

            # Encode the query and add null terminator
            query_bytes = query.encode('utf-8', 'ignore') + b'\x00'

            # Create the packet
            data = struct.pack(PACKET_FORMAT_UDP, self.seq_num, query_bytes)
            calculted_checksum = calculate_checksum(data)
            packet = struct.pack(PACKET_FORMAT, self.seq_num, query_bytes, calculted_checksum)

            # Send packet to client and track ACKs
            sent_packets[self.seq_num] = PacketInfo(packet, time.time())
            self.socket.sendto(packet, (SERVER_ADDRESS, SERVER_PORT))

            # Increment the sequence number for the next packet
            self.seq_num += 1

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
                        a = seq_num
                        if seq_num >= 11:
                            break
                        print("Timeout occurred for packet: ", seq_num)
                if a >= 11:
                    break

                # Receive ACKs from the server
                try:
                    ack_packet, address = self.socket.recvfrom(PACKET_SIZE)

                    # Unpack the ACK packet
                    ack_seq_num, ack_bytes, ack_checksum = struct.unpack(PACKET_FORMAT, ack_packet)

                    if len(sent_packets) == 1 and 11 in sent_packets:
                        break
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

            if len(sent_packets) == 1 and 11 in sent_packets:
                break

        self.socket.settimeout(None)

        # Receiving responses for queries
        while len(responses) < 10:

            # Receive a packet from the server
            pckt, address = self.socket.recvfrom(PACKET_SIZE)
            print(f"Received a response for query num: {10 - len(responses)}")

            # Unpack the packet
            seq_num, response_bytes, cs = struct.unpack(PACKET_FORMAT, pckt)

            # Calculate the checksum of the received packet
            data = struct.pack(PACKET_FORMAT_UDP, seq_num, response_bytes)
            if calculate_checksum(data) != cs:
                # Send a negative acknowledgement for the packet with a checksum error
                nack_packet = struct.pack(PACKET_FORMAT, seq_num, b'NACK', CHECKSUM_ERROR)
                self.socket.sendto(nack_packet, address)
                continue  # Receive the next packet

            print(f"Seq num: {seq_num}, Window: [{self.window_start}, {self.window_end}]")

            if response_bytes.decode('utf-8', 'ignore').rstrip('\x00') == 'END':
                break

            # Check if packet is within the sliding window
            if self.window_start <= seq_num <= self.window_end:

                # Add the packet to the received packets dictionary
                self.received_packets[seq_num] = response_bytes.decode('utf-8', 'ignore').rstrip('\x00')

                # Send a positive acknowledgement for the received packet
                ack_packet = struct.pack(PACKET_FORMAT, seq_num, b'ACK', cs)

                # Include the packet number in the ack field
                ack_packet = ack_packet[:4] + struct.pack("!I", seq_num) + ack_packet[8:]

                self.socket.sendto(ack_packet, address)

                print(f'Sent an ACK packet for packet: {seq_num}')

                print(f"Window start: {self.window_start}, received_packets: {self.received_packets}")

                # Slide the window if possible
                while self.window_start in self.received_packets:
                    # Add the query to the list of queries
                    responses.append(self.received_packets[self.window_start])
                    del self.received_packets[self.window_start]

                    # Update the window
                    self.window_start += 1
                    self.window_end += 1

            elif seq_num < self.window_start:

                # Send a positive acknowledgement for the received packet
                ack_packet = struct.pack(PACKET_FORMAT, seq_num, b'ACK', cs)

                # Include the packet number in the ack field
                ack_packet = ack_packet[:4] + struct.pack("!I", seq_num) + ack_packet[8:]

                self.socket.sendto(ack_packet, address)

                print(f'Sent an ACK packet for packet: {seq_num}')

        # Check that the number of responses received matches the expected number
        if len(responses) != expected_responses:
            print(responses)
            raise Exception('Unexpected number of responses received')

        self.window_start = 1
        self.window_end = self.window_size - 1
        return responses

    def send_queries_tcp(self, queries):
        """
        Send a list of queries to a server using TCP and return the responses.
        :param queries: queries (list of str): The list of queries to send to the server.
        :return: A list of str containing the responses from the server.
        """
        responses = []
        print('Opening TCP socket and connecting the server')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((SERVER_ADDRESS, SERVER_PORT))

        # Keep track of how many responses are expected
        expected_responses = len(queries)
        i = 1
        for query in queries:
            # Encode the query and add null terminator
            query_bytes = query.encode('utf-8', 'ignore') + b'\x00'

            pckt = struct.pack(PACKET_FORMAT_UDP, self.seq_num, query_bytes)

            # Send the query string to the server
            self.socket.sendall(pckt)
            print(f'Sent query {i} to the server')
            i += 1

        # Wait for a response to each query
        for i in range(expected_responses):
            response_bytes = self.socket.recv(PACKET_SIZE_UDP)

            # Decode the response, remove null characters and append it to the list of responses
            response = response_bytes.decode('utf-8', 'ignore').replace('\x00', '')
            responses.append(response)
            print(f'Received response for query {i + 1}')

        # Check that the number of responses received matches the expected number
        if len(responses) != expected_responses:
            raise Exception('Unexpected number of responses received')

        return responses

    def send_and_print_queries(self, queries, protocol):
        """
        Sends SQL queries to the server using the specified protocol (TCP or RUDP), receives the responses and prints them.
        :param queries: A list of SQL queries to be sent to the server
        :param protocol: The protocol to be used for communication with the server. Valid options are 'TCP' and 'RUDP'.
        """

        # Send SQL queries to the server using the specified protocol
        if protocol == 'TCP':
            responses = self.send_queries_tcp(queries)
        elif protocol == 'RUDP':
            responses = self.send_queries_rudp(queries)
        else:
            raise ValueError('Invalid protocol specified')

        # Print the responses
        for i, response in enumerate(responses):
            print(f'Response to query {i + 1}: {response}')

    def queries_input(self):
        """
        This method takes user input for two SQL queries and appends them to the queries list of the object instance.
        """

        table_name = 'mytable'  # Replace 'mytable' with your actual table name
        column_names = ['id', 'name', 'age']  # Replace with your actual column names

        for i in range(10):
            print(
                f"Enter a SQL query (query {i + 1} of 10) for the '{table_name}' table with columns: {', '.join(column_names)}")
            print("Example queries: SELECT name, age FROM mytable WHERE age BETWEEN 30 AND 40")
            query = __builtins__.input(">> ")
            while not is_valid_query(query):
                print("Invalid format, try again.")
                print("Example queries: SELECT * FROM mytable WHERE column = value")
                query = __builtins__.input(">> ")
            self.queries.append(query)

    def init_protocol(self):
        """
        Initializes the communication protocol with the server.
        Prompts the user to enter the desired protocol (TCP or RUDP). Sends the protocol information to the server using a
        UDP socket and waits for the server to acknowledge receipt. Closes the UDP socket once the acknowledgement is
        received.
        """

        # Protocol input
        self.protocol = __builtins__.input("Enter protocol 'TCP'/'RUDP': ")

        # Open TCP connection
        print('Opening TCP socket and connecting the server')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((SERVER_ADDRESS, CLIENT_PORT))
        self.socket.connect((SERVER_ADDRESS, SERVER_PORT))

        # Encoding the protocol string
        p = self.protocol.encode('utf-8', 'ignore') + b'\x00'

        # Create the packet
        packeta = struct.pack(PACKET_FORMAT_UDP, self.seq_num, p)

        # Send the packet to the server
        self.socket.sendto(packeta, (SERVER_ADDRESS, SERVER_PORT))

        print('Connected to the server')
        # Close the socket
        self.socket.close()

    def get_ip(self):
        """Sends a DHCP discover packet over the network, captures and processes the DHCP offer packet to obtain an IP address.
        Returns the IP address obtained, or None if no offer is received within 5 seconds.
        """

        conf.checkIPaddr = False
        conf.checkMACaddr = False
        dhcp_discover = Ether(src=get_if_hwaddr("Wi-Fi"), dst="ff:ff:ff:ff:ff:ff") / \
                        IP(src="0.0.0.0", dst="255.255.255.255") / \
                        UDP(sport=68, dport=67) / \
                        BOOTP(op=1, chaddr=get_if_hwaddr("Wi-Fi"), xid=random.randint(1, 1000000000)) / \
                        DHCP(options=[("message-type", "discover"),
                                      "end"])
        sendp(dhcp_discover)
        sniff(filter="udp and (port 67 or port 68)", prn=self.detect_dhcp, store=0, timeout=5)

    def detect_dhcp(self, pckt):
        """
        This method receives a packet as an argument and checks if it contains DHCP messages.
        If the DHCP message is an "offer", it sends a DHCP request message to the server that offered the IP address.
        If the DHCP message is an "ack", it prints the assigned IP address, gateway IP address, subnet mask, and lease time.

        :param pckt: The packet to analyze for DHCP messages.
        """

        if DHCP in pckt and pckt[DHCP].options[0][1] == 2:
            print("Received DHCP Offer from: " + pckt[Ether].src)
            dhcp_request = Ether(src=get_if_hwaddr("Wi-Fi"), dst=pckt[Ether].src) / \
                           IP(src="0.0.0.0", dst="255.255.255.255") / \
                           UDP(sport=68, dport=67) / \
                           BOOTP(op=1, chaddr=get_if_hwaddr("Wi-Fi"), xid=pckt[BOOTP].xid) / \
                           DHCP(options=[("message-type", "request"),
                                         ("requested_addr", pckt[BOOTP].yiaddr),
                                         ("server_id", pckt[IP].src),
                                         "end"])
            sendp(dhcp_request)

        if DHCP in pckt and pckt[DHCP].options[0][1] == 5:
            print("[*] src: " + pckt[Ether].src)
            print("[*] IP Address: " + pckt[BOOTP].yiaddr)
            print("[*] Gateway IP Address: " + str(pckt[DHCP].options[2][1]))
            print("[*] Subnet Mask: " + pckt[DHCP].options[1][1])
            print("[*] Lease time: " + str(pckt[DHCP].options[3][1]))
            self.my_ip = pckt[BOOTP].yiaddr
            self.gateway_ip = str(pckt[DHCP].options[2][1])
            self.subnet_mask = str(pckt[DHCP].options[1][1])
            self.ip_lease_time = str(pckt[DHCP].options[3][1])


if __name__ == '__main__':
    client = Client()
    client.client_start()
