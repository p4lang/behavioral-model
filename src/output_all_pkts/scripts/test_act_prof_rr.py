from scapy.all import Ether, IP, TCP, sendp, AsyncSniffer
import time
send_iface = "veth0"   # Send into BMv2
recv_ifaces = ["veth2"]   # Capture what comes out of BMv2

def captured(pkt):
    """
    Callback function to process captured packets.
    """
    print("Captured packet on interface:", pkt.sniffed_on)
    print("Packet captured:", pkt.show())
    print("Packet raw data:", bytes(pkt).hex())
    return True  # Return True to stop sniffing after the first packet

# Construct packet
pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ee:dd:cc:bb:aa") / \
      IP(dst="10.0.0.1", src="10.0.0.2") / \
      TCP(sport=1234, dport=5678)


# AsyncSniff packets on the specified interfaces
sniffers = []
for iface in recv_ifaces:
    # sniff 2 packets on each interface

    sniffer = AsyncSniffer(iface=iface, prn=captured, store=False, count=2)
    sniffer.start()
    sniffers.append(sniffer)



# Send and sniff
print("Sending packet of size", len(pkt), "bytes on", send_iface)
sendp(pkt, iface=send_iface, verbose=True)

time.sleep(1)  # Wait for the packet to be sent and captured

