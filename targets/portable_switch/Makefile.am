if COND_NANOMSG
MAYBE_TESTS = tests
endif

SUBDIRS = . $(MAYBE_TESTS)

THRIFT_IDL = $(srcdir)/thrift/portable_switch.thrift

noinst_LTLIBRARIES = libsimpleswitch.la

libsimpleswitch_la_SOURCES = portable_switch.cpp portable_switch.h primitives.cpp

libsimpleswitch_la_LIBADD = \
$(top_builddir)/src/bm_sim/libbmsim.la \
$(top_builddir)/src/bf_lpm_trie/libbflpmtrie.la \
$(top_builddir)/src/BMI/libbmi.la \
$(top_builddir)/third_party/jsoncpp/libjson.la \
-lboost_system $(THRIFT_LIB) -lboost_program_options -lboost_filesystem

if COND_THRIFT

portable_switch_thrift_py_files = \
gen-py/pswitch_runtime/constants.py \
gen-py/pswitch_runtime/__init__.py \
gen-py/pswitch_runtime/PortableSwitch.py \
gen-py/pswitch_runtime/ttypes.py
portable_switch_thrift_files = \
gen-cpp/bm/portable_switch_constants.cpp \
gen-cpp/bm/portable_switch_constants.h \
gen-cpp/bm/PortableSwitch.cpp \
gen-cpp/bm/PortableSwitch.h \
gen-cpp/bm/portable_switch_types.cpp \
gen-cpp/bm/portable_switch_types.h

BUILT_SOURCES = $(portable_switch_thrift_files) $(portable_switch_thrift_py_files)

pswitchpydir = $(pythondir)/pswitch_runtime
nodist_pswitchpy_PYTHON = $(portable_switch_thrift_py_files)

python_PYTHON = pswitch_CLI.py

# See
# http://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Installation-Directory-Variables.html
edit = sed \
	-e 's|@pythondir[@]|$(pythondir)|g'

portable_switch_CLI: Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/$@.in >$@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

portable_switch_CLI: portable_switch_CLI.in

EXTRA_DIST = \
portable_switch_CLI.in \
pswitch_CLI

bin_SCRIPTS = \
portable_switch_CLI

AM_CPPFLAGS += \
-I$(srcdir)/thrift/src/ \
-I$(builddir)/gen-cpp

libsimpleswitch_la_SOURCES += thrift/src/PortableSwitch_server.cpp

bin_PROGRAMS = portable_switch

portable_switch_LDADD = \
$(top_builddir)/src/bm_runtime/libbmruntime.la \
$(top_builddir)/thrift_src/libruntimestubs.la \
libsimpleswitch.la \
libsimpleswitch_thrift.la

portable_switch_SOURCES = main.cpp

lib_LTLIBRARIES = libsimpleswitch_thrift.la

nodist_libsimpleswitch_thrift_la_SOURCES = \
$(portable_switch_thrift_files)

# See http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html

EXTRA_DIST += $(THRIFT_IDL)

# We copy the generated Python code to srcdir/ if we have permissions (i.e. not
# for 'make distcheck'). This is to ensure we can run the CLI easily. Maybe I
# will think of a better solution later.
thrift_files.ts: $(THRIFT_IDL)
	@rm -f thrift_files.tmp
	@touch thrift_files.tmp
	@mkdir -p $(builddir)/gen-cpp/bm
	$(THRIFT) -out $(builddir)/gen-cpp/bm --gen cpp -r $(THRIFT_IDL)
	$(THRIFT) -o $(builddir) --gen py -r $(THRIFT_IDL)
	if mkdir $(srcdir)/pswitch_runtime.test 2>/dev/null; then \
	  rm -rf $(srcdir)/pswitch_runtime/; \
	  cp -r $(builddir)/gen-py/pswitch_runtime/ $(srcdir)/; \
	  rm -rf $(srcdir)/pswitch_runtime.test; else :; \
        fi
	@mv -f thrift_files.tmp $@

$(BUILT_SOURCES): thrift_files.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf thrift_files.lock thrift_files.ts' 1 2 13 15; \
## mkdir is a portable test-and-set
	if mkdir thrift_files.lock 2>/dev/null; then \
## This code is being executed by the first process.
	  rm -f thrift_files.ts; \
	  $(MAKE) $(AM_MAKEFLAGS) thrift_files.ts; \
	  result=$$?; rm -rf thrift_files.lock; exit $$result; \
	else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
	  while test -d thrift_files.lock; do sleep 1; done; \
## Succeed if and only if the first process succeeded.
	    test -f thrift_files.ts; \
	  fi; \
	fi

nodist_pkginclude_HEADERS = \
gen-cpp/bm/portable_switch_constants.h \
gen-cpp/bm/PortableSwitch.h \
gen-cpp/bm/portable_switch_types.h

CLEANFILES = $(BUILT_SOURCES) \
thrift_files.ts \
gen-cpp/bm/PortableSwitch_server.skeleton.cpp \
$(bin_SCRIPTS)

# I used to do a rm on gen-cpp, but it was removing a .deps directory, instead I
# am adding the skeleton file to CLEANFILES
clean-local:
	rm -rf gen-py

endif  # COND_THRIFT
