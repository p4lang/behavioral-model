load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "PI",
    srcs = glob(
        [
            "src/**/*.c",
            "lib/**/*.c",
            "cJSON/*.c",
            "proto_frontend/*.cpp",
            "proto_frontend/server_config/*.cpp",
            "proto/p4info/*.cpp",
            "frontends_cpp/*.cpp",
        ],
        exclude = [
            "src/pi_rpc_server.c",
            "src/pi_notifications_pub.c",
        ],
    ),
    hdrs = glob([
        "PI/**/*.h",
        "src/**/*.h",
        "lib/**/*.h",
        "cJSON/**/*.h",
        "proto_frontend/**/*.h",
        "proto/p4info/**/*.h",
    ]),
    includes = [
        ".",
        "src",
        "src/utils",
        "src/p4info",
        "lib",
        "cJSON",
        "proto_frontend",
        "proto/p4info",
    ],
    copts = [
        "-Wno-implicit-function-declaration",
        "-Wno-error=implicit-function-declaration",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@protobuf//:protobuf",
        "@grpc//:grpc++",
        "@fmt//:fmt",
        "@boost.thread//:boost.thread",
        "//third_party/p4runtime:p4runtime",
    ],
)
