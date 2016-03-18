ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

if COND_TARGETS
    MAYBE_TARGETS = targets
endif

pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA=$(builddir)/bmv2-libthrift.pc

SUBDIRS = thrift_src third_party modules tests $(MAYBE_TARGETS)
