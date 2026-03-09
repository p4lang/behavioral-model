def get_grpc_linkopts():
    return [
        "-lgrpc++", "-lgrpc", "-lprotobuf", "-lgpr", "-lupb", "-lcares", "-lz", "-lre2", "-laddress_sorting", "-lssl", "-lcrypto",
        "-labsl_synchronization", "-labsl_base", "-labsl_time", "-labsl_strings", "-labsl_throw_delegate",
        "-labsl_raw_logging_internal", "-labsl_random_distributions", "-labsl_statusor", "-labsl_status", "-labsl_cord",
        "-labsl_cordz_info", "-labsl_cord_internal", "-labsl_cordz_functions", "-labsl_exponential_biased", "-labsl_cordz_handle",
        "-labsl_bad_optional_access", "-labsl_strerror", "-labsl_str_format_internal", "-labsl_graphcycles_internal",
        "-labsl_stacktrace", "-labsl_symbolize", "-labsl_debugging_internal", "-labsl_demangle_internal", "-labsl_malloc_internal",
        "-labsl_civil_time", "-labsl_strings_internal", "-labsl_spinlock_wait", "-labsl_int128", "-labsl_time_zone",
        "-labsl_bad_variant_access", "-labsl_log_severity", "-labsl_raw_hash_set", "-labsl_hashtablez_sampler", "-labsl_hash",
        "-labsl_city", "-labsl_low_level_hash", "-latomic", "-lrt"
    ]
