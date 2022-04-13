ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = . tests

AM_CPPFLAGS += \
-I$(srcdir)/../../include \
-I$(srcdir)/../simple_switch \
-I$(srcdir)/../../PI \
-isystem$(srcdir)/../../third_party/spdlog

if WITH_SYSREPO
AM_CPPFLAGS += -DWITH_SYSREPO
endif

if WITH_THRIFT
AM_CPPFLAGS += -DWITH_THRIFT \
-I$(builddir)/../simple_switch/gen-cpp
endif

bin_PROGRAMS = simple_switch_grpc

simple_switch_grpc_SOURCES = main.cpp

simple_switch_grpc_LDADD = \
libsimple_switch_grpc.la

# We follow this tutorial to link with grpc++_reflection:
# https://github.com/grpc/grpc/blob/master/doc/server_reflection_tutorial.md
simple_switch_grpc_LDFLAGS = \
-Wl,--no-as-needed,-lgrpc++_reflection,--as-needed \
-rdynamic

noinst_LTLIBRARIES = libsimple_switch_grpc.la

libsimple_switch_grpc_la_SOURCES = \
switch_runner.cpp switch_runner.h
if WITH_SYSREPO
libsimple_switch_grpc_la_SOURCES += \
switch_sysrepo.h switch_sysrepo.cpp
endif

libsimple_switch_grpc_la_LIBADD = \
$(builddir)/../simple_switch/libsimpleswitch.la \
$(builddir)/../../PI/libbmpi.la \
$(builddir)/../../services/libbm_grpc_dataplane.la

if WITH_THRIFT
libsimple_switch_grpc_la_LIBADD += \
$(builddir)/../../src/bm_runtime/libbmruntime.la \
$(builddir)/../../thrift_src/libruntimestubs.la \
$(builddir)/../simple_switch/libsimpleswitch_thrift.la
endif

libsimple_switch_grpc_la_LIBADD += \
-lpifeproto -lpigrpcserver -lpi -lpip4info \
$(GRPC_LIBS) $(PROTOBUF_LIBS)

AM_CPPFLAGS += \
 -I$(builddir)/../../services/cpp_out \
 -I$(builddir)/../../services/grpc_out
