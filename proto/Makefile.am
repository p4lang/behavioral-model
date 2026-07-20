# SPDX-FileCopyrightText: 2026 Yuao Ma
#
# SPDX-License-Identifier: Apache-2.0

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

noinst_LTLIBRARIES = libbm_packet_trace.la

proto = $(srcdir)/packet_trace.proto
PROTOFLAGS = -I$(srcdir)

proto_cpp_files = \
	cpp_out/packet_trace.pb.cc \
	cpp_out/packet_trace.pb.h

BUILT_SOURCES = $(proto_cpp_files)

proto_files.ts: $(proto)
	@rm -f proto_files.tmp
	@touch proto_files.tmp
	@mkdir -p $(builddir)/cpp_out
	$(PROTOC) $^ --cpp_out $(builddir)/cpp_out $(PROTOFLAGS)
	@mv -f proto_files.tmp $@

$(BUILT_SOURCES): proto_files.ts
	@if test -f $@; then :; else \
		trap 'rm -rf proto_files.lock proto_files.ts' 1 2 13 15; \
		if mkdir proto_files.lock 2>/dev/null; then \
			rm -f proto_files.ts; \
			$(MAKE) $(AM_MAKEFLAGS) proto_files.ts; \
			result=$$?; rm -rf proto_files.lock; exit $$result; \
		else \
			while test -d proto_files.lock; do sleep 1; done; \
			test -f proto_files.ts; \
		fi; \
	fi

AM_CPPFLAGS += -I$(builddir)/cpp_out

nodist_libbm_packet_trace_la_SOURCES = $(proto_cpp_files)
libbm_packet_trace_la_CXXFLAGS =

CLEANFILES = $(BUILT_SOURCES) proto_files.ts
