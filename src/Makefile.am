ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

if COND_THRIFT
MAYBE_BM_RUNTIME = bm_runtime
endif

if COND_NANOMSG
MAYBE_BM_APPS = bm_apps
endif

SUBDIRS = BMI bm_sim $(MAYBE_BM_RUNTIME) $(MAYBE_BM_APPS)

lib_LTLIBRARIES = libbmall.la

if COND_NANOMSG
lib_LTLIBRARIES += libbmp4apps.la
libbmp4apps_la_SOURCES =
# Dummy C++ source to cause C++ linking.
nodist_EXTRA_libbmp4apps_la_SOURCES = dummy.cpp
libbmp4apps_la_LIBADD = bm_apps/libbmapps.la
endif

libbmall_la_SOURCES =
# Dummy C++ source to cause C++ linking.
nodist_EXTRA_libbmall_la_SOURCES = dummy.cpp
libbmall_la_LIBADD = \
$(top_builddir)/src/bm_sim/libbmsim.la \
$(top_builddir)/src/BMI/libbmi.la \
$(top_builddir)/third_party/jsoncpp/libjson.la

if COND_THRIFT
libbmall_la_LIBADD += \
$(top_builddir)/src/bm_runtime/libbmruntime.la \
$(top_builddir)/thrift_src/libruntimestubs.la
endif

libbmall_la_LIBADD += \
-lboost_system $(THRIFT_LIB) -lboost_program_options -lboost_filesystem
