from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

# Define the DHCP server configuration
SERVER_IP = "192.168.1.1"
SUBNET_MASK = "255.255.255.0"
LEASE_TIME = 3600  # 1 hour
IP_POOL = {"192.168.1.%d" % i: datetime.min for i in range(1, 256)}


def get_available_random_ip():
    """
    Get a random IP address from the IP pool
    """
    ip_address = "192.168.1." + str(random.randint(1, 255))
    expire_time = IP_POOL.get(ip_address)
    if expire_time is not None and expire_time <= datetime.now():
        IP_POOL[ip_address] = datetime.now() + timedelta(seconds=LEASE_TIME)
        return ip_address
    return None


def detect_dhcp(pckt):
    # If packet is a Discovery packet
    if DHCP in pckt and pckt[DHCP].options[0][1] == 1:
        print("Received DHCP Discover from: " + pckt[Ether].src)
        ip_address = get_available_random_ip()
        if ip_address is None:
            return
        dhcp_offer = Ether(src=pckt[Ether].dst, dst=pckt[Ether].src) / \
                     IP(src=SERVER_IP, dst="255.255.255.255") / \
                     UDP(sport=67, dport=68) / \
                     BOOTP(op=2, yiaddr=ip_address, siaddr=SERVER_IP, giaddr="0.0.0.0",
                           xid=pckt[BOOTP].xid) / \
                     DHCP(options=[("message-type", "offer"),
                                   ("subnet_mask", SUBNET_MASK),
                                   ("router", SERVER_IP),
                                   ("lease_time", LEASE_TIME),
                                   ("server_id", SERVER_IP),
                                   "end"])
        sendp(dhcp_offer)
        print("Sent DHCP OFFER.")

    # If packet is a Request packet
    if DHCP in pckt and pckt[DHCP].options[0][1] == 3:
        print("Received DHCP Request from: " + pckt[Ether].src)
        requested_ip_option = next((option for option in pckt[DHCP].options if option[0] == "requested_addr"), None)
        if requested_ip_option is None:
            return
        requested_ip = requested_ip_option[1]
        if requested_ip not in IP_POOL:
            return
        dhcp_ack = Ether(src=pckt[Ether].dst, dst=pckt[Ether].src) / \
                   IP(src=SERVER_IP, dst="255.255.255.255") / \
                   UDP(sport=67, dport=68) / \
                   BOOTP(op=2, yiaddr=requested_ip, siaddr=SERVER_IP, giaddr="0.0.0.0", xid=pckt[BOOTP].xid) / \
                   DHCP(options=[("message-type", "ack"),
                                 ("subnet_mask", SUBNET_MASK),
                                 ("router", SERVER_IP),
                                 ("lease_time", LEASE_TIME),
                                 ("server_id", SERVER_IP),
                                 "end"])
        sendp(dhcp_ack)
        print("Sent DHCP ACK with configuration.")

# Main function
def main():
    print('DHCP server is sniffing for DHCP packets..')
    conf.checkIPaddr = False
    conf.checkMACaddr = False
    sniff(filter="udp and (port 67 or port 68)", prn=detect_dhcp, store=0)


if __name__ == "__main__":
    main()