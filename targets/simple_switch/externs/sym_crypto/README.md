# ADD CRYPTO to SIMPLE_SWITCH

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
