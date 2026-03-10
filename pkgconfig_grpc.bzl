def get_grpc_linkopts():
    return [
        "-lgrpc++", "-lgrpc", "-lprotobuf", "-lgpr",
        "-labsl_cord", "-labsl_strings", "-labsl_base",
        "-labsl_synchronization", "-labsl_status",
        "-labsl_statusor", "-labsl_time",
        "-lre2", "-lcares", "-lupb"
    ]