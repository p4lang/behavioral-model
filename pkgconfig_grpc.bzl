def get_grpc_linkopts():
    return [
        "-lgrpc++", "-lgrpc", "-lprotobuf", "-lgpr",
    ]
