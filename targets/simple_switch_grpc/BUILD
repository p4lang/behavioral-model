load("@rules_cc//cc:defs.bzl", "cc_library", "cc_binary", "cc_test")

cc_library(
    name = "simpleswitchgrpc_lib",
    srcs = ["switch_runner.cpp"],
    hdrs = ["switch_runner.h"],
    deps = [
        "//:bmv2_core",
        "//third_party/PI:PI",
        "//services:dataplane_interface_grpc",
        "@protobuf//:protobuf",
        "@grpc//:grpc++",
    ],
    visibility = ["//visibility:public"],
)

cc_binary(
    name = "simple_switch_grpc",
    srcs = ["main.cpp"],
    deps = [
        ":simpleswitchgrpc_lib",
        "@protobuf//:protobuf",
        "@grpc//:grpc++",
    ],
)

cc_test(
    name = "simple_switch_grpc_test",
    srcs = [
        "tests/main.cpp",
        "tests/base_test.cpp",
        "tests/base_test.h",
        "tests/utils.cpp",
        "tests/utils.h",
        "tests/test_basic.cpp",
        "tests/test_counter.cpp",
        "tests/test_meter.cpp",
        "tests/test_digest.cpp",
        "tests/test_packet_io.cpp",
        "tests/test_pre.cpp",
        "tests/test_action_profile.cpp",
        "tests/test_idle_timeout.cpp",
        "tests/test_optional.cpp",
        "tests/test_ternary.cpp",
        "tests/test_grpc_dp.cpp",
        "tests/test_gnmi.cpp",
    ],
    copts = [
        "-Itargets/simple_switch_grpc/tests",
        "-Itargets/simple_switch_grpc",
        "-DTESTDATADIR=\\\"targets/simple_switch_grpc/tests/testdata\\\"",
    ],
    data = glob(["tests/testdata/**"]),
    deps = [
        ":simpleswitchgrpc_lib",
        "@googletest//:gtest",
    ],
)
