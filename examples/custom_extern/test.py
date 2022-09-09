#!/usr/bin/env python3
# Copyright 2022 P4lang Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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
