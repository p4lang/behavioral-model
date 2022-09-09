# Custom Extern Example

This example demonstrates how to add custom extern functions and objects that could be compiled to and used in the bmv2 software switch (`simple_switch`).

## Requirements

Make sure the following tools are installed:
- [p4c](https://github.com/p4lang/p4c)
- [bmv2](https://github.com/p4lang/behavioral-model)
- [Scapy](https://scapy.readthedocs.io/en/latest/index.html): `pip install scapy`

## Testing Process

First, build the P4 program and the extern library:
```console
$ make build
```

Then, start `simple_switch` and keep the terminal alive:
```console
$ make start
...
Calling target program-options parser
Adding interface veth0 as port 0
Adding interface veth2 as port 1
```

In another terminal, we can verify behavior by sending a test packet and checking the packet after it has been processed by `simple_switch`.
```console
$ make test
```

If everything works as expected, you should see:
```console
WARNING: Mac address to reach destination not found. Using broadcast.
.
Sent 1 packets.

Packet sent:
WARNING: Mac address to reach destination not found. Using broadcast.
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 42:01:c0:a8:3f:48
  type      = 0x9000
###[ Raw ]### 
     load      = '\x00\x00\x00\x00'

Packet received:
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 42:01:c0:a8:3f:48
  type      = 0x9000
###[ Raw ]### 
     load      = '\\xbd\x11\x01\x00'
```

When you are done with testing, tun the following after killing the `simple_switch` process:
```console
$ make stop
$ make clean
```

## Reference

- [Previous discussion](https://github.com/p4lang/behavioral-model/issues/697)
- [Relevant section in the P4 Language Specification](https://p4.org/p4-spec/docs/P4-16-v1.2.3.html#sec-external-units)
- [Relevant testing code in bmv2](https://github.com/p4lang/behavioral-model/blob/main/tests/test_extern.cpp)
- [Another example](https://github.com/engjefersonsantiago/p4-programs/tree/master/examples/div_by_n)
