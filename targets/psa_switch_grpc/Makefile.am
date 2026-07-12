# SPDX-FileCopyrightText: 2017 Antonin Bas
#
# SPDX-License-Identifier: Apache-2.0

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = . tests

AM_CPPFLAGS += \
-I$(srcdir)/../../include \
-I$(srcdir)/../psa_switch \
-I$(srcdir)/../../PI \
-isystem$(srcdir)/../../third_party/spdlog

if WITH_SYSREPO
AM_CPPFLAGS += -DWITH_SYSREPO
endif

if WITH_THRIFT
AM_CPPFLAGS += -DWITH_THRIFT \
-I$(builddir)/../psa_switch/gen-cpp
endif

bin_PROGRAMS = psa_switch_grpc

psa_switch_grpc_SOURCES = main.cpp

psa_switch_grpc_LDADD = \
libpsa_switch_grpc.la

# We follow this tutorial to link with grpc++_reflection:
# https://github.com/grpc/grpc/blob/master/doc/server_reflection_tutorial.md
psa_switch_grpc_LDFLAGS = \
-Wl,--no-as-needed,-lgrpc++_reflection,--as-needed \
-rdynamic

noinst_LTLIBRARIES = libpsa_switch_grpc.la

libpsa_switch_grpc_la_SOURCES = \
switch_runner.cpp switch_runner.h
if WITH_SYSREPO
libpsa_switch_grpc_la_SOURCES += \
switch_sysrepo.h switch_sysrepo.cpp
endif

libpsa_switch_grpc_la_LIBADD = \
$(builddir)/../psa_switch/libpsaswitch.la \
$(builddir)/../../PI/libbmpi.la \
$(builddir)/../../services/libbm_grpc_dataplane.la

if WITH_THRIFT
libpsa_switch_grpc_la_LIBADD += \
$(builddir)/../../src/bm_runtime/libbmruntime.la \
$(builddir)/../../thrift_src/libruntimestubs.la \
$(builddir)/../psa_switch/libpsaswitch_thrift.la
endif

libpsa_switch_grpc_la_LIBADD += \
-lpifeproto -lpigrpcserver -lpi -lpip4info \
$(GRPC_LIBS) $(PROTOBUF_LIBS)

AM_CPPFLAGS += \
 -I$(builddir)/../../services/cpp_out \
 -I$(builddir)/../../services/grpc_out
