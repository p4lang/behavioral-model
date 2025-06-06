if COND_STRESS_TESTS
    MAYBE_STRESS_TESTS = stress_tests
endif

SUBDIRS = . $(MAYBE_STRESS_TESTS)

noinst_LTLIBRARIES = libtestutils.la

libtestutils_la_SOURCES = utils.h utils.cpp
libtestutils_la_LIBADD = $(top_builddir)/src/bm_sim/libbmsim.la

AM_CPPFLAGS += \
-I$(top_srcdir)/src/bm_sim \
-I$(top_srcdir)/src/BMI \
-isystem $(top_srcdir)/third_party/gtest/include \
-isystem $(top_srcdir)/third_party/jsoncpp/include \
-DTESTDATADIR=\"$(abs_srcdir)/testdata\"

if SKIP_UNDETERMINISTIC_TESTS
    AM_CPPFLAGS += -DSKIP_UNDETERMINISTIC_TESTS
endif

LDADD = \
$(top_builddir)/third_party/gtest/libgtest.la \
$(top_builddir)/src/bm_runtime/libbmruntime.la \
$(top_builddir)/src/bm_apps/libbmapps.la \
$(top_builddir)/src/bm_sim/libbmsim.la \
$(top_builddir)/thrift_src/libruntimestubs.la \
$(THRIFT_LIB) \
$(top_builddir)/third_party/jsoncpp/libjson.la \
$(builddir)/libtestutils.la \
-lboost_system -lboost_filesystem -lboost_program_options

# Define unit tests
common_source = main.cpp bmi_stubs.c primitives.cpp
TESTS = test_actions \
test_checksums \
test_expressions \
test_conditionals \
test_data \
test_handle_mgr \
test_p4objects \
test_parser \
test_phv \
test_queue \
test_queueing \
test_tables \
test_learning \
test_pre \
test_calculations \
test_headers \
test_header_stacks \
test_header_unions \
test_meters \
test_ageing \
test_counters \
test_pcap \
test_fields \
test_devmgr \
test_packet \
test_extern \
test_periodic_tasks \
test_switch \
test_target_parser \
test_runtime_iface \
test_bm_apps \
test_stateful \
test_enums \
test_core_primitives \
test_control_flow \
test_assert_assume \
test_log_msg \
test_ras

check_PROGRAMS = $(TESTS) test_all

# Sources for tests
test_actions_SOURCES         = $(common_source) test_actions.cpp
test_checksums_SOURCES       = $(common_source) test_checksums.cpp
test_expressions_SOURCES     = $(common_source) test_expressions.cpp
test_conditionals_SOURCES    = $(common_source) test_conditionals.cpp
test_data_SOURCES            = $(common_source) test_data.cpp
test_handle_mgr_SOURCES      = $(common_source) test_handle_mgr.cpp
test_p4objects_SOURCES       = $(common_source) test_p4objects.cpp
test_parser_SOURCES          = $(common_source) test_parser.cpp
test_phv_SOURCES             = $(common_source) test_phv.cpp
test_queue_SOURCES           = $(common_source) test_queue.cpp
test_queueing_SOURCES        = $(common_source) test_queueing.cpp
test_tables_SOURCES          = $(common_source) test_tables.cpp
test_learning_SOURCES        = $(common_source) test_learning.cpp
test_pre_SOURCES             = $(common_source) test_pre.cpp
test_calculations_SOURCES    = $(common_source) test_calculations.cpp
test_headers_SOURCES         = $(common_source) test_headers.cpp
test_header_stacks_SOURCES   = $(common_source) test_header_stacks.cpp
test_header_unions_SOURCES   = $(common_source) test_header_unions.cpp
test_meters_SOURCES          = $(common_source) test_meters.cpp
test_ageing_SOURCES          = $(common_source) test_ageing.cpp
test_counters_SOURCES        = $(common_source) test_counters.cpp
test_fields_SOURCES          = $(common_source) test_fields.cpp
test_pcap_SOURCES            = $(common_source) test_pcap.cpp
test_devmgr_SOURCES          = $(common_source) test_devmgr.cpp
test_packet_SOURCES          = $(common_source) test_packet.cpp
test_extern_SOURCES          = $(common_source) test_extern.cpp
test_periodic_tasks_SOURCES  = $(common_source) test_periodic_tasks.cpp
test_switch_SOURCES          = $(common_source) test_switch.cpp
test_target_parser_SOURCES   = $(common_source) test_target_parser.cpp
test_runtime_iface_SOURCES   = $(common_source) test_runtime_iface.cpp
test_bm_apps_SOURCES         = $(common_source) test_bm_apps.cpp
test_stateful_SOURCES        = $(common_source) test_stateful.cpp
test_enums_SOURCES           = $(common_source) test_enums.cpp
test_core_primitives_SOURCES = $(common_source) test_core_primitives.cpp
test_control_flow_SOURCES    = $(common_source) test_control_flow.cpp
test_assert_assume_SOURCES   = $(common_source) test_assert_assume.cpp
test_log_msg_SOURCES         = $(common_source) test_log_msg.cpp
test_ras_SOURCES             = $(common_source) test_ras.cpp

test_all_SOURCES = $(common_source) \
test_actions.cpp \
test_checksums.cpp \
test_expressions.cpp \
test_conditionals.cpp \
test_data.cpp \
test_handle_mgr.cpp \
test_p4objects.cpp \
test_parser.cpp \
test_phv.cpp \
test_queue.cpp \
test_queueing.cpp \
test_tables.cpp \
test_learning.cpp \
test_pre.cpp \
test_calculations.cpp \
test_headers.cpp \
test_header_stacks.cpp \
test_header_unions.cpp \
test_meters.cpp \
test_ageing.cpp \
test_counters.cpp \
test_pcap.cpp \
test_fields.cpp \
test_devmgr.cpp \
test_packet.cpp \
test_extern.cpp \
test_periodic_tasks.cpp \
test_switch.cpp \
test_target_parser.cpp \
test_runtime_iface.cpp \
test_bm_apps.cpp \
test_stateful.cpp \
test_enums.cpp \
test_core_primitives.cpp \
test_control_flow.cpp \
test_assert_assume.cpp \
test_log_msg.cpp \
test_ras.cpp

EXTRA_DIST = \
testdata/en0.pcap \
testdata/lo0.pcap \
testdata/empty_config.json \
testdata/empty_config.md5 \
testdata/serialize.p4 \
testdata/serialize.json \
testdata/runtime_iface.p4 \
testdata/runtime_iface.json \
testdata/one_header.json \
testdata/parse_vset.p4 \
testdata/parse_vset.json \
testdata/header_stack.p4 \
testdata/header_stack.json \
testdata/config_options.json \
testdata/one_extern.json \
testdata/unions_e2e_options_bos.json \
testdata/unions_e2e_options_count.json \
testdata/logging.json \
testdata/pvs_struct_2.p4 \
testdata/pvs_struct_2.json
