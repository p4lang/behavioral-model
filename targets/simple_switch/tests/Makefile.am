# SPDX-FileCopyrightText: 2015 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

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
$(top_builddir)/src/bm_apps/libbmapps.la

# Define unit tests
common_source = main.cpp ../../test_utils/utils.cpp ../../test_utils/utils.h
gtest_programs = test_packet_redirect \
test_truncate \
test_swap \
test_queueing \
test_recirc \
test_parser_error

TESTS = $(gtest_programs)

check_PROGRAMS = $(gtest_programs) test_all

# Sources for tests
test_packet_redirect_SOURCES = $(common_source) test_packet_redirect.cpp
test_truncate_SOURCES = $(common_source) test_truncate.cpp
test_swap_SOURCES = $(common_source) test_swap.cpp
test_queueing_SOURCES = $(common_source) test_queueing.cpp
test_recirc_SOURCES = $(common_source) test_recirc.cpp
test_parser_error_SOURCES = $(common_source) test_parser_error.cpp

test_all_SOURCES = $(common_source) \
test_packet_redirect.cpp \
test_truncate.cpp \
test_swap.cpp \
test_queueing.cpp \
test_recirc.cpp \
test_parser_error.cpp

# Golden tests for the structured packet tracer. The runner sends each
# pipeline's scenario packets through an in-process simple_switch and prints
# the resulting packet traces; run_packet_trace_test.sh diffs that output
# against the checked-in testdata/<pipeline>.trace files.
if COND_PACKET_TRACE
PACKET_TRACE_PIPELINES = \
packet_redirect \
parser_error \
queueing \
recirc \
truncate

check_PROGRAMS += test_packet_trace
test_packet_trace_SOURCES = test_packet_trace.cpp
test_packet_trace_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_builddir)/proto/cpp_out
test_packet_trace_LDADD = $(LDADD) $(PROTOBUF_LIBS)

dist_check_SCRIPTS = run_packet_trace_test.sh
TESTS += run_packet_trace_test.sh

AM_TESTS_ENVIRONMENT = \
PACKET_TRACE_BIN='$(abs_builddir)/test_packet_trace'; \
export PACKET_TRACE_BIN; \
PACKET_TRACE_TESTDATA='$(abs_srcdir)/testdata'; \
export PACKET_TRACE_TESTDATA; \
PACKET_TRACE_PIPELINES='$(PACKET_TRACE_PIPELINES)'; \
export PACKET_TRACE_PIPELINES;
endif

EXTRA_DIST = \
testdata/packet_redirect.json \
testdata/truncate.json \
testdata/swap_1.json \
testdata/swap_2.json \
testdata/queueing.json \
testdata/recirc.json \
testdata/parser_error.p4 \
testdata/parser_error.json \
testdata/packet_redirect.trace \
testdata/parser_error.trace \
testdata/queueing.trace \
testdata/recirc.trace \
testdata/truncate.trace
