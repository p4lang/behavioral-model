# ADD CRYPTO to behavioral-model

Patch diffs-simple_switch.cpp to your behavioral-model repo

# LINKING

When crypto is incorporated in simple_switch.cpp, change the following Makefile.am to link crypto libs.

diff --git a/targets/simple_switch/Makefile.am b/targets/simple_switch/Makefile.am
index ee1bc7e..3e06ae1 100644
--- a/targets/simple_switch/Makefile.am
+++ b/targets/simple_switch/Makefile.am
@@ -33,7 +33,7 @@ $(top_builddir)/src/bm_sim/libbmsim.la \
 $(top_builddir)/src/bf_lpm_trie/libbflpmtrie.la \
 $(top_builddir)/src/BMI/libbmi.la \
 $(top_builddir)/third_party/jsoncpp/libjson.la \
--lboost_system $(THRIFT_LIB) -lboost_program_options -lboost_filesystem
+-lboost_system $(THRIFT_LIB) -lboost_program_options -lboost_filesystem -lcrypto -lz
 
 libsimpleswitch_runner_la_LIBADD = \
 $(PI_LIB) \

# BUILD

Since targets/simple_switch/Makefile.am is changed, run "./configure" from root diretory
of behavioral-model

# Compiling basic.p4

ARGS are: --emit-externs --p4runtime-file $(basename $@).p4info --p4runtime-format text

# RUN simple_switch or simple_switch_grpc, TODO

# P4 CODE

In basic.p4, see crypt.validate() for decryption.

Likewise, see crypt.protect() for encryption.

extern ExternCrypt is also defined in basic.p4.

Most args to encrypt and decrypt are self-explanatory.  Also see this paper:

https://arxiv.org/abs/1904.07088


