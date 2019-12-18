# ADD CRYPTO to SIMPLE_SWITCH

For reference, the extern is implemented in crypto.cpp in this directory.
This cpp code is to be incorporated in
behavioral-model/targets/simple_switch/simple_switch.cpp

The code is crypto.cpp is also available in the repo URL included below
so that testing can be done using MACsec (MAC security) code.  A
README.md is available at the repo below with steps for how to test
the code.

https://github.com/uni-tue-kn/p4-macsec

The extern is defined in the following P4 file.  Search for ExternCrypt
for the extern definition. Additionally the extern is used in P4 code
as crypt.validate() which is decryption and crypt.protect() which is
encryption.

https://github.com/uni-tue-kn/p4-macsec/p4/p4/basic.p4

basic.p4 is used to test the cryto extern code with simple_switch.

