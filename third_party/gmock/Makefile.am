AM_CPPFLAGS = -I$(srcdir)/include \
              -isystem $(top_srcdir)/third_party/gtest/include
AM_CXXFLAGS =

LDADD = \
$(top_builddir)/third_party/gtest/libgtest.la

check_LTLIBRARIES = libgmock.la

EXTRA_DIST = \
include/gmock/gmock-actions.h \
include/gmock/gmock-cardinalities.h \
include/gmock/gmock-function-mocker.h \
include/gmock/gmock-matchers.h \
include/gmock/gmock-more-actions.h \
include/gmock/gmock-more-matchers.h \
include/gmock/gmock-nice-strict.h \
include/gmock/gmock-spec-builders.h \
include/gmock/gmock.h \
include/gmock/internal/custom/gmock-generated-actions.h \
include/gmock/internal/custom/gmock-matchers.h \
include/gmock/internal/custom/gmock-port.h \
include/gmock/internal/gmock-internal-utils.h \
include/gmock/internal/gmock-port.h \
include/gmock/internal/gmock-pp.h

EXTRA_DIST += \
src/gmock-all.cc \
src/gmock-cardinalities.cc \
src/gmock-internal-utils.cc \
src/gmock-matchers.cc \
src/gmock-spec-builders.cc \
src/gmock.cc \
src/gmock_main.cc

libgmock_la_SOURCES = \
src/gmock-all.cc \
include/gmock/gmock.h
