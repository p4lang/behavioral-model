#!/usr/bin/env python3
from scapy.all import Ether, Packet, XByteField
from scapy.all import AsyncSniffer, sendp


class TestPacket(Packet):
    name = "TestPacket"
    fields_desc = [
        XByteField('a', 0),
        XByteField('b', 0),
        XByteField('c', 0),
        XByteField('d', 0),
    ]

def report(pkt_sent, pkt_received):
    print()
    print('Packet sent:')
    pkt_sent.show2()
    print('Packet received:')
    pkt_received.show2()

def main():
    # Build the test packet.
    pkt = Ether() / TestPacket()

    # Prepare to sniff 1 packet.
    sniffer = AsyncSniffer(
        iface='veth3',
        count=1,
        prn=lambda pkt_received: report(pkt, pkt_received)
    )
    sniffer.start()

    # Send the test packet.
    sendp(pkt, iface="veth1")

    # Wait until 1 packet is sniffed and report.
    sniffer.join()


if __name__ == main():
    main()
