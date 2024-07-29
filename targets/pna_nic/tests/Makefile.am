SUBDIRS = .

AM_CPPFLAGS += \
-isystem $(top_srcdir)/third_party/gtest/include \
-I$(srcdir)/.. \
-I$(srcdir)/ \
-DTESTDATADIR=\"$(srcdir)/testdata\"
LDADD = $(builddir)/../libpnanic.la \
$(top_builddir)/third_party/gtest/libgtest.la \
$(top_builddir)/src/bm_apps/libbmapps.la \
-lboost_filesystem

# Define unit tests
common_source = main.cpp utils.cpp utils.h
TESTS = test_internet_checksum \
test_hash \
test_parse_pna

check_PROGRAMS = $(TESTS) test_all

# Sources for tests
test_internet_checksum_SOURCES = $(common_source) test_internet_checksum.cpp
test_hash_SOURCES = $(common_source) test_hash.cpp
test_parse_pna_SOURCES = $(common_source) test_parse_pna.cpp

test_all_SOURCES = $(common_source) \
test_internet_checksum.cpp \
test_hash.cpp \
test_parse_pna.cpp

EXTRA_DIST = \
testdata/pna-demo-L2-one-table.json \
testdata/pna-demo-L2-one-table.p4