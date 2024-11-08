if COND_NANOMSG
MAYBE_TESTS = tests
endif

SUBDIRS = . $(MAYBE_TESTS)

THRIFT_IDL = $(srcdir)/thrift/pna_nic.thrift

noinst_LTLIBRARIES = libpnanic.la

libpnanic_la_SOURCES = \
pna_nic.cpp pna_nic.h \
primitives.cpp \
externs/pna_counter.h externs/pna_counter.cpp \
externs/pna_meter.h externs/pna_meter.cpp \
externs/pna_random.h externs/pna_random.cpp \
externs/pna_internet_checksum.h externs/pna_internet_checksum.cpp \
externs/pna_hash.h externs/pna_hash.cpp

libpnanic_la_LIBADD = \
$(top_builddir)/src/bm_sim/libbmsim.la \
$(top_builddir)/src/bf_lpm_trie/libbflpmtrie.la \
$(top_builddir)/src/BMI/libbmi.la \
$(top_builddir)/third_party/jsoncpp/libjson.la \
-lboost_system $(THRIFT_LIB) -lboost_program_options -lboost_filesystem

if COND_THRIFT

pna_nic_thrift_py_files = \
gen-py/pnic_runtime/constants.py \
gen-py/pnic_runtime/__init__.py \
gen-py/pnic_runtime/PnaNic.py \
gen-py/pnic_runtime/ttypes.py
pna_nic_thrift_files = \
gen-cpp/bm/pna_nic_constants.cpp \
gen-cpp/bm/pna_nic_constants.h \
gen-cpp/bm/PnaNic.cpp \
gen-cpp/bm/PnaNic.h \
gen-cpp/bm/pna_nic_types.cpp \
gen-cpp/bm/pna_nic_types.h

BUILT_SOURCES = $(pna_nic_thrift_files) $(pna_nic_thrift_py_files)

pnicpydir = $(pythondir)/pnic_runtime
nodist_pnicpy_PYTHON = $(pna_nic_thrift_py_files)

python_PYTHON = pnic_CLI.py

# See
# http://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Installation-Directory-Variables.html
edit = sed \
	-e 's|@pythondir[@]|$(pythondir)|g'

pna_nic_CLI: Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/$@.in >$@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

pna_nic_CLI: pna_nic_CLI.in

EXTRA_DIST = \
pna_nic_CLI.in \
pnic_CLI

bin_SCRIPTS = \
pna_nic_CLI

AM_CPPFLAGS += \
-I$(srcdir)/thrift/src/ \
-I$(builddir)/gen-cpp

libpnanic_la_SOURCES += thrift/src/PnaNic_server.cpp

bin_PROGRAMS = pna_nic

pna_nic_LDADD = \
$(top_builddir)/src/bm_runtime/libbmruntime.la \
$(top_builddir)/thrift_src/libruntimestubs.la \
libpnanic.la \
libpnanic_thrift.la

pna_nic_SOURCES = main.cpp

lib_LTLIBRARIES = libpnanic_thrift.la

nodist_libpnanic_thrift_la_SOURCES = \
$(pna_nic_thrift_files)

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
	touch $(pna_nic_thrift_files)
	if mkdir $(srcdir)/pnic_runtime.test 2>/dev/null; then \
	  rm -rf $(srcdir)/pnic_runtime/; \
	  cp -r $(builddir)/gen-py/pnic_runtime/ $(srcdir)/; \
	  rm -rf $(srcdir)/pnic_runtime.test; else :; \
        fi
	@mv -f thrift_files.tmp $@

$(BUILT_SOURCES): thrift_files.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf thrift_files.lock thrift_files.ts' 1 2 13 15; \
## mkdir is a simple test-and-set
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
gen-cpp/bm/pna_nic_constants.h \
gen-cpp/bm/PnaNic.h \
gen-cpp/bm/pna_nic_types.h

CLEANFILES = $(BUILT_SOURCES) \
thrift_files.ts \
gen-cpp/bm/PnaNic_server.skeleton.cpp \
$(bin_SCRIPTS)

# I used to do a rm on gen-cpp, but it was removing a .deps directory, instead I
# am adding the skeleton file to CLEANFILES
clean-local:
	rm -rf gen-py

endif  # COND_THRIFT
