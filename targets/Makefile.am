MAYBE_SECONDARY_TARGETS =

if COND_THRIFT
MAYBE_SECONDARY_TARGETS += simple_router l2_switch
endif

if COND_PI
MAYBE_SECONDARY_TARGETS += simple_switch_grpc
endif

SUBDIRS = test_utils simple_switch psa_switch pna_nic $(MAYBE_SECONDARY_TARGETS)
