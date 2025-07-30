#TODO(Hao) merge this with the outer Makefile.am

print-top-srcdir:
	@echo "top_srcdir = $(top_srcdir)" \
    @echo "top_builddir = $(top_builddir)" \
    @echo "abs_srcdir = $(abs_srcdir)"


ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

# Ensures that gtest has been built
SUBDIRS = ../../../../third_party

# for deprecated Protobuf fields
AM_CXXFLAGS += -Wno-error=deprecated-declarations

AM_CPPFLAGS += \
-isystem $(top_srcdir)/../../third_party/gtest/include \
-I$(top_srcdir) \
-I$(top_srcdir)/tests \
-I$(top_srcdir)/../../include \
-isystem $(top_srcdir)/../../third_party/spdlog \
-I$(top_builddir)/../../services/cpp_out -I$(top_builddir)/../../services/grpc_out \
-DTESTDATADIR=\"$(abs_srcdir)/testdata\"

TESTS = test_selector_fanout

check_PROGRAMS = test_selector_fanout

common_source = ../utils.h ../utils.cpp ../base_test.h ../base_test.cpp


# TODO(Hao): a new suite for selector fanout tests, be carefull with the conflicts
test_selector_fanout_SOURCES = \
$(common_source) ../main.cpp \
test_ingress_fanout.cpp

test_selector_fanout_LDADD = \
$(top_builddir)/libsimple_switch_grpc.la \
$(top_builddir)/../simple_switch/libsimpleswitch.la \
-lpiprotogrpc -lpiprotobuf \
$(PROTOBUF_LIBS) $(GRPC_LIBS) \
$(top_builddir)/../../third_party/gtest/libgtest.la

