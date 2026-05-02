# SPDX-FileCopyrightText: 2015 Anirudh Sivaraman
#
# SPDX-License-Identifier: Apache-2.0

AM_CPPFLAGS += \
-I$(top_builddir)/thrift_src/gen-cpp

noinst_PROGRAMS = learn_client
learn_client_SOURCES = learn_client.cpp
learn_client_LDADD = $(top_builddir)/src/bm_apps/libbmapps.la
