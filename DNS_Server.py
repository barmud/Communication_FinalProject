from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime, timedelta

CACHE_DURATION = 60  # Cache duration in seconds


def dns_server(port=53):
    # Set up a TCP socket to listen on the specified port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("localhost", port))
    sock.listen(1)
    print('DNS server is listening..')

    # Initialize the DNS cache
    dns_cache = {}

    # Start the DNS server loop
    while True:

        # Wait for a client to connect to the server
        conn, addr = sock.accept()

        # Receive the DNS query packet from the client over the TCP connection
        dns_request_packet_bytes = conn.recv(1024)
        dns_request_packet = IP(dns_request_packet_bytes)
        print('Received a DNS query from the client')

        # Parse the DNS query packet
        dns_request = dns_request_packet[DNS]
        domain_name = dns_request.qd.qname.decode("utf-8")[:-1]

        # Check if the requested domain is in the cache
        if domain_name in dns_cache:
            cached_ip_addr, cached_time = dns_cache[domain_name]
            if datetime.now() - cached_time < timedelta(seconds=CACHE_DURATION):
                # If the cached entry is still valid, return the cached IP address
                print(f"Resolved {domain_name} from cache")
                dns_answer = DNSRR(rrname=domain_name + ".", ttl=CACHE_DURATION, type="A", rdata=cached_ip_addr)
                dns_response_packet = IP(dst=addr[0]) / TCP(dport=addr[1]) / DNS(id=dns_request.id, qr=1, an=dns_answer)
                conn.sendall(bytes(dns_response_packet))
                conn.close()
                continue
            else:
                # If the cached entry has expired, remove it from the cache
                del dns_cache[domain_name]

        # Build the DNS query packet to send to Google DNS server
        dns_query = DNS(rd=1, qd=DNSQR(qname=domain_name, qtype="A"))
        ip_packet = IP(dst="8.8.8.8")
        udp_packet = UDP(dport=53)
        dns_query_packet = ip_packet / udp_packet / dns_query
        print('Built the DNS query packet, forwarding to the DNS server of google')

        # Send the DNS query packet to the Google DNS server over TCP and receive the response
        dns_response_packet_bytes = sr1(dns_query_packet, verbose=0)
        dns_response_packet = IP(bytes(dns_response_packet_bytes))
        print('Sent the DNS query packet to a remote DNS server')

        # Check if the response packet contains answer records
        if not dns_response_packet.haslayer(DNSRR):
            print(f"Could not resolve {domain_name}")
            continue

        # Extract the IP address from the DNS response packet
        ip_addr = dns_response_packet[DNSRR].rdata

        # Store the resolved IP address in the cache
        dns_cache[domain_name] = (ip_addr, datetime.now())

        # Build the DNS response packet and send it to the client over the TCP connection
        dns_answer = DNSRR(rrname=domain_name + ".", ttl=CACHE_DURATION, type="A", rdata=ip_addr)
        dns_response_packet = IP(dst=addr[0]) / TCP(dport=addr[1]) / DNS(id=dns_request.id, qr=1, an=dns_answer)
        conn.sendall(bytes(dns_response_packet))
        print('Sent the response to the client')

        # Close the TCP connection to the client
        conn.close()
        break


if __name__ == "__main__":
    dns_server()