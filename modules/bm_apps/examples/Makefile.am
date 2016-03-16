AM_CPPFLAGS = -I$(top_srcdir)/modules/bm_apps/include

if P4THRIFT
  AM_CPPFLAGS+=$(THRIFT_INC) $(THRIFT_LIB)
  ifndef AM_LDFLAGS
    AM_LDFLAGS=$(THRIFT_LIB)
  else
    AM_LDFLAGS+=$(THRIFT_LIB)
  endif
endif

noinst_PROGRAMS = test_packet_pipe
test_packet_pipe_SOURCES = test_packet_pipe.cpp
test_packet_pipe_LDADD = $(top_builddir)/modules/bm_apps/libbmapps.la
