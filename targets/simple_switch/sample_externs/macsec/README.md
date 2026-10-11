# Add macsec extern to simple_switch
# macsec is layer-2 security.

For reference, the extern is implemented in crypto.cpp in this directory.
Steps to use the macsec extern are described below.

TODO

The code is crypto.cpp is also available in the repo URL included below
so that testing can be done using MACsec (MAC security) code.  A
README.md is available at the repo below with steps for how to test
the code.

https://github.com/uni-tue-kn/p4-macsec

The extern definition is included below.

extern ExternCrypt {
    ExternCrypt();
    void protect(in bit<128> SAK,
                in bit<64> SCI,
                in bit<32> PN,
                in bit<48> src_addr,
                in bit<48> dst_addr,
                in bit<128> sectag,
                in bit<16> ethertype,
                in bit<8> prepend_ipv4_hdr,
                in bit<160> ipv4_hdr);
    void validate(in bit<128> SAK,
                in bit<64> SCI,
                in bit<32> PN,
                in bit<48> src_addr,
                in bit<48> dst_addr,
                in bit<128> sectag,
                out bit<8> valid,
                out bit<16> ethertype);
}

Additionally the extern is used in P4 code as crypt.validate() which is
decryption and crypt.protect() which is encryption.

https://github.com/uni-tue-kn/p4-macsec/p4/p4/basic.p4

basic.p4 is used to test the cryto extern code with simple_switch as follows:

In p4-macsec/p4/p4 directory, run `make run`. This will compile the P4 program
and start the switches and mininet.

basic.p4 is compiled using p4c with args shown in

https://github.com/uni-tue-kn/p4-macsec/blob/master/p4/p4/Makefile
