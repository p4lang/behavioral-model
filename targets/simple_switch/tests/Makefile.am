if COND_THRIFT
MAYBE_CLI_TESTS = CLI_tests
endif

SUBDIRS = . $(MAYBE_CLI_TESTS)

AM_CPPFLAGS += \
-isystem $(top_srcdir)/third_party/gtest/include \
-I$(srcdir)/.. \
-I$(srcdir)/ \
-I$(top_srcdir)/targets/test_utils \
-DTESTDATADIR=\"$(srcdir)/testdata\"

LDADD = $(builddir)/../libsimpleswitch.la \
$(top_builddir)/third_party/gtest/libgtest.la \
$(top_builddir)/targets/test_utils/libtargetstestutils.la \
$(top_builddir)/src/bm_apps/libbmapps.la \
-lboost_filesystem

# Define unit tests
common_source = main.cpp ../../test_utils/utils.cpp ../../test_utils/utils.h
TESTS = test_packet_redirect \
test_packet_redirect_bmi \
test_truncate \
test_swap \
test_queueing \
test_recirc \
test_parser_error

check_PROGRAMS = $(TESTS) test_all
lib_LIBRARIES = pcap_mock/libpcap.a

# Sources for tests
test_packet_redirect_SOURCES = $(common_source) test_packet_redirect.cpp
test_packet_redirect_bmi_SOURCES = $(common_source) test_packet_redirect_bmi.cpp
test_packet_redirect_bmi_LDFLAGS = -L$(srcdir)/pcap_mock
test_packet_redirect_bmi_DEPENDENCIES = pcap_mock/libpcap.a
test_truncate_SOURCES = $(common_source) test_truncate.cpp
test_swap_SOURCES = $(common_source) test_swap.cpp
test_queueing_SOURCES = $(common_source) test_queueing.cpp
test_recirc_SOURCES = $(common_source) test_recirc.cpp
test_parser_error_SOURCES = $(common_source) test_parser_error.cpp

pcap_mock_libpcap_a_SOURCES = pcap_mock/mock_libpcap.cpp pcap_mock/pcap_mock.hpp
pcap_mock_libpcap_a_LIBADD = 

test_all_SOURCES = $(common_source) \
test_packet_redirect.cpp \
test_packet_redirect_bmi.cpp \
test_truncate.cpp \
test_swap.cpp \
test_queueing.cpp \
test_recirc.cpp \
test_parser_error.cpp

test_all_LDFLAGS = -L$(srcdir)/pcap_mock
test_all_DEPENDENCIES = pcap_mock/libpcap.a

EXTRA_DIST = \
testdata/packet_redirect.json \
testdata/truncate.json \
testdata/swap_1.json \
testdata/swap_2.json \
testdata/queueing.json \
testdata/recirc.json \
testdata/parser_error.p4 \
testdata/parser_error.json
